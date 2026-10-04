"""ARIES 风格崩溃恢复审计引擎(星载姿控参数页)。

输入:稳定审计标识、至多 48 个初始页像(含 pageLSN)、至多 128 条按 LSN
排列的受限 WAL 记录(begin / update / commit / abort / end / checkpoint)。

处理流水线:
  1. 校验(断链、重复 LSN、越界区间、前像长度、已结束事务引用等)-> 稳定拒绝码
  2. 分析:自最后一个检查点开始,重建事务表(TT)与脏页表(DPT)
  3. 重做:自最小 recLSN 起,重放确有缺失的更新(pageLSN < LSN 且通过前像校验)
  4. 撤销:沿失败事务前驱链逆序,仅在页 LSN 条件满足时改写页像,并分配 CLR LSN

输出:冻结的恢复裁决(逐条分析归属 / 重做判据 / 撤销判据、恢复前后 pageLSN、
最终页像 SHA-256)。裁决不含任何时钟字段,同一输入永远得到同一裁决。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

MAX_PAGES = 48
MAX_RECORDS = 128
MAX_PAGE_BYTES = 4096
MAX_AUDIT_ID_LEN = 128
MAX_TXN_LEN = 64

RECORD_TYPES = ("begin", "update", "commit", "abort", "end", "checkpoint")
CHECKPOINT_TXN_STATUS = ("running", "committed", "aborting")


class Reject(Exception):
    """稳定拒绝:code 是审计契约的一部分,调用方可据此断言。"""

    def __init__(self, code: str, message: str, lsn: int | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.lsn = lsn

    def to_dict(self) -> dict:
        body = {"verdict": "REJECTED", "error": self.code, "message": self.message}
        if self.lsn is not None:
            body["lsn"] = self.lsn
        return body


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------


@dataclass
class Record:
    lsn: int
    type: str
    txn: str | None = None
    prev_lsn: int | None = None
    page_id: int | None = None
    offset: int | None = None
    length: int | None = None
    before: bytes | None = None
    after: bytes | None = None
    ckpt_txns: list = field(default_factory=list)
    ckpt_dpt: list = field(default_factory=list)
    # 逐条审计轨迹
    analysis_note: str = ""
    redo_note: str = "n/a (not an update)"
    undo_note: str = "n/a (not undone)"


@dataclass
class PageImage:
    page_id: int
    lsn_before: int
    data_before: bytes
    lsn: int
    data: bytearray


# ---------------------------------------------------------------------------
# 基础解析
# ---------------------------------------------------------------------------


def _require(cond: bool, code: str, message: str, lsn: int | None = None):
    if not cond:
        raise Reject(code, message, lsn)


def _hex_to_bytes(value, code: str, what: str, lsn: int | None = None) -> bytes:
    _require(isinstance(value, str), code, f"{what} must be a hex string", lsn)
    _require(len(value) % 2 == 0, code, f"{what} must have even hex length", lsn)
    try:
        return bytes.fromhex(value)
    except ValueError:
        raise Reject(code, f"{what} is not valid hexadecimal", lsn)


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_audit_id(payload) -> str:
    audit_id = payload.get("audit_id")
    _require(
        isinstance(audit_id, str) and 0 < len(audit_id) <= MAX_AUDIT_ID_LEN,
        "BAD_AUDIT_ID",
        f"audit_id must be a string of 1..{MAX_AUDIT_ID_LEN} characters",
    )
    _require(
        all(ch.isprintable() for ch in audit_id),
        "BAD_AUDIT_ID",
        "audit_id must contain only printable characters",
    )
    return audit_id


def _parse_pages(payload) -> list[PageImage]:
    pages = payload.get("pages")
    _require(isinstance(pages, list), "BAD_RECORD", "pages must be a list")
    _require(
        len(pages) <= MAX_PAGES,
        "LIMIT_EXCEEDED",
        f"at most {MAX_PAGES} initial page images allowed, got {len(pages)}",
    )
    result: list[PageImage] = []
    seen: set[int] = set()
    for i, item in enumerate(pages):
        _require(isinstance(item, dict), "BAD_RECORD", f"pages[{i}] must be an object")
        page_id = item.get("page_id")
        page_lsn = item.get("page_lsn")
        _require(_is_int(page_id) and page_id >= 0, "BAD_RECORD", f"pages[{i}].page_id must be a non-negative integer")
        _require(_is_int(page_lsn) and page_lsn >= 0, "BAD_RECORD", f"pages[{i}].page_lsn must be a non-negative integer")
        _require(page_id not in seen, "DUPLICATE_PAGE", f"duplicate page_id {page_id}")
        seen.add(page_id)
        data = _hex_to_bytes(item.get("data"), "BAD_HEX", f"pages[{i}].data")
        _require(
            0 < len(data) <= MAX_PAGE_BYTES,
            "BAD_RECORD",
            f"pages[{i}].data must decode to 1..{MAX_PAGE_BYTES} bytes",
        )
        result.append(PageImage(page_id, page_lsn, data, page_lsn, bytearray(data)))
    return result


def _parse_txn_name(value, lsn) -> str:
    _require(
        isinstance(value, str) and 0 < len(value) <= MAX_TXN_LEN,
        "BAD_RECORD",
        "txn must be a non-empty string",
        lsn,
    )
    return value


def _parse_wal(payload, pages_by_id: dict[int, PageImage]) -> list[Record]:
    wal = payload.get("wal")
    _require(isinstance(wal, list), "BAD_RECORD", "wal must be a list")
    _require(
        len(wal) <= MAX_RECORDS,
        "LIMIT_EXCEEDED",
        f"at most {MAX_RECORDS} WAL records allowed, got {len(wal)}",
    )
    records: list[Record] = []
    prev_lsn = 0
    for i, item in enumerate(wal):
        _require(isinstance(item, dict), "BAD_RECORD", f"wal[{i}] must be an object")
        lsn = item.get("lsn")
        _require(_is_int(lsn) and lsn >= 1, "BAD_RECORD", f"wal[{i}].lsn must be an integer >= 1")
        _require(lsn > prev_lsn, "DUPLICATE_LSN" if lsn == prev_lsn else "LSN_OUT_OF_ORDER",
                 f"wal[{i}].lsn={lsn} is not strictly greater than previous LSN {prev_lsn}", lsn)
        prev_lsn = lsn
        rtype = item.get("type")
        _require(rtype in RECORD_TYPES, "BAD_RECORD", f"wal[{i}].type must be one of {RECORD_TYPES}", lsn)

        rec = Record(lsn=lsn, type=rtype)
        if rtype == "checkpoint":
            rec.ckpt_txns = _parse_ckpt_txns(item.get("txns", []), lsn)
            rec.ckpt_dpt = _parse_ckpt_dpt(item.get("dpt", []), lsn)
        else:
            rec.txn = _parse_txn_name(item.get("txn"), lsn)
            if rtype == "begin":
                pl = item.get("prev_lsn", 0)
                _require(pl in (None, 0), "BROKEN_CHAIN", "begin record must not carry a predecessor", lsn)
                rec.prev_lsn = 0
            else:
                pl = item.get("prev_lsn")
                _require(_is_int(pl) and pl >= 0, "BROKEN_CHAIN", f"{rtype} record requires integer prev_lsn >= 0", lsn)
                rec.prev_lsn = pl
            if rtype == "update":
                rec.page_id = item.get("page_id")
                _require(_is_int(rec.page_id) and rec.page_id >= 0, "BAD_RECORD", "update.page_id must be a non-negative integer", lsn)
                page = pages_by_id.get(rec.page_id)
                _require(page is not None, "UNKNOWN_PAGE", f"update references page {rec.page_id} with no submitted image", lsn)
                off, length = item.get("offset"), item.get("length")
                _require(_is_int(off) and off >= 0, "BAD_RECORD", "update.offset must be a non-negative integer", lsn)
                _require(_is_int(length) and length >= 1, "BAD_RECORD", "update.length must be an integer >= 1", lsn)
                _require(
                    off + length <= len(page.data),
                    "INTERVAL_OUT_OF_BOUNDS",
                    f"half-open interval [{off}, {off + length}) exceeds page {rec.page_id} size {len(page.data)}",
                    lsn,
                )
                rec.offset, rec.length = off, length
                rec.before = _hex_to_bytes(item.get("before"), "BAD_HEX", "update.before", lsn)
                rec.after = _hex_to_bytes(item.get("after"), "BAD_HEX", "update.after", lsn)
                _require(
                    len(rec.before) == length and len(rec.after) == length,
                    "BAD_IMAGE_LENGTH",
                    f"before/after images must both decode to exactly length={length} bytes",
                    lsn,
                )
        records.append(rec)
    return records


def _parse_ckpt_txns(value, lsn) -> list:
    _require(isinstance(value, list), "BAD_CHECKPOINT", "checkpoint.txns must be a list", lsn)
    out = []
    seen = set()
    for entry in value:
        _require(isinstance(entry, dict), "BAD_CHECKPOINT", "checkpoint txns entries must be objects", lsn)
        txn = _parse_txn_name(entry.get("txn"), lsn)
        last = entry.get("last_lsn")
        _require(_is_int(last) and last >= 1, "BAD_CHECKPOINT", "checkpoint txn last_lsn must be an integer >= 1", lsn)
        status = entry.get("status", "running")
        _require(status in CHECKPOINT_TXN_STATUS, "BAD_CHECKPOINT", f"checkpoint txn status must be one of {CHECKPOINT_TXN_STATUS}", lsn)
        _require(txn not in seen, "BAD_CHECKPOINT", f"checkpoint lists txn {txn} twice", lsn)
        seen.add(txn)
        out.append({"txn": txn, "last_lsn": last, "status": status})
    return out


def _parse_ckpt_dpt(value, lsn) -> list:
    _require(isinstance(value, list), "BAD_CHECKPOINT", "checkpoint.dpt must be a list", lsn)
    out = []
    seen = set()
    for entry in value:
        _require(isinstance(entry, dict), "BAD_CHECKPOINT", "checkpoint dpt entries must be objects", lsn)
        page_id = entry.get("page_id")
        rec_lsn = entry.get("rec_lsn")
        _require(_is_int(page_id) and page_id >= 0, "BAD_CHECKPOINT", "checkpoint dpt page_id must be a non-negative integer", lsn)
        _require(_is_int(rec_lsn) and rec_lsn >= 1, "BAD_CHECKPOINT", "checkpoint dpt rec_lsn must be an integer >= 1", lsn)
        _require(page_id not in seen, "BAD_CHECKPOINT", f"checkpoint dpt lists page {page_id} twice", lsn)
        seen.add(page_id)
        out.append({"page_id": page_id, "rec_lsn": rec_lsn})
    return out


# ---------------------------------------------------------------------------
# 前驱链 / 结束事务校验(覆盖整条受限 WAL)
# ---------------------------------------------------------------------------


def _validate_chains(records: list[Record]) -> None:
    first_lsn = records[0].lsn if records else 0
    lsn_to_txn: dict[int, str] = {}
    last_lsn_by_txn: dict[str, int] = {}
    ended: set[str] = set()
    begun: set[str] = set()

    for rec in records:
        if rec.type == "checkpoint":
            # 检查点内部引用若落在窗口内,必须与窗口记录一致
            for entry in rec.ckpt_txns:
                ref = entry["last_lsn"]
                if ref in lsn_to_txn and lsn_to_txn[ref] != entry["txn"]:
                    raise Reject(
                        "BAD_CHECKPOINT",
                        f"checkpoint last_lsn {ref} belongs to txn {lsn_to_txn[ref]}, not {entry['txn']}",
                        rec.lsn,
                    )
            continue

        txn = rec.txn
        _require(txn not in ended, "TXN_ENDED", f"record references txn {txn} after its end record", rec.lsn)

        if rec.type == "begin":
            _require(txn not in begun, "BAD_RECORD", f"txn {txn} begun twice", rec.lsn)
            begun.add(txn)
        else:
            pl = rec.prev_lsn
            _require(pl < rec.lsn, "BROKEN_CHAIN", f"prev_lsn {pl} must be smaller than lsn {rec.lsn}", rec.lsn)
            if txn in last_lsn_by_txn:
                _require(
                    pl == last_lsn_by_txn[txn],
                    "BROKEN_CHAIN",
                    f"txn {txn} predecessor should be {last_lsn_by_txn[txn]}, got {pl}",
                    rec.lsn,
                )
            else:
                # 窗口内首条记录:前驱必须落在窗口之外(受限 WAL 截断)或为 0
                if pl in lsn_to_txn:
                    raise Reject(
                        "BROKEN_CHAIN",
                        f"txn {txn} first in-window record points at LSN {pl} owned by txn {lsn_to_txn[pl]}",
                        rec.lsn,
                    )
                _require(
                    pl == 0 or pl < first_lsn,
                    "BROKEN_CHAIN",
                    f"txn {txn} predecessor {pl} missing from submitted WAL window",
                    rec.lsn,
                )
        if rec.type == "end":
            ended.add(txn)
        last_lsn_by_txn[txn] = rec.lsn
        lsn_to_txn[rec.lsn] = txn


# ---------------------------------------------------------------------------
# 阶段一:分析(自最后一个检查点开始)
# ---------------------------------------------------------------------------


def _analyze(records: list[Record]) -> tuple[dict, dict, int | None]:
    tt: dict[str, dict] = {}   # txn -> {"status": str, "last_lsn": int}
    dpt: dict[int, int] = {}   # page_id -> recLSN
    ckpt_index = -1
    for i, rec in enumerate(records):
        if rec.type == "checkpoint":
            ckpt_index = i
    ckpt_lsn = records[ckpt_index].lsn if ckpt_index >= 0 else None

    for i, rec in enumerate(records):
        if ckpt_index >= 0 and i < ckpt_index:
            rec.analysis_note = f"not scanned (before checkpoint LSN {ckpt_lsn})"
            continue
        if rec.type == "checkpoint":
            for entry in rec.ckpt_txns:
                tt[entry["txn"]] = {"status": entry["status"], "last_lsn": entry["last_lsn"]}
            for entry in rec.ckpt_dpt:
                dpt[entry["page_id"]] = entry["rec_lsn"]
            rec.analysis_note = (
                f"analysis starts here: TT seeded with {len(rec.ckpt_txns)} txn(s), "
                f"DPT seeded with {len(rec.ckpt_dpt)} page(s)"
            )
        elif rec.type == "begin":
            tt[rec.txn] = {"status": "running", "last_lsn": rec.lsn}
            rec.analysis_note = f"TT[{rec.txn}] = (running, {rec.lsn})"
        elif rec.type == "update":
            notes = []
            if rec.txn not in tt:
                tt[rec.txn] = {"status": "running", "last_lsn": rec.lsn}
                notes.append(f"TT[{rec.txn}] inserted as running")
            tt[rec.txn]["last_lsn"] = rec.lsn
            notes.append(f"TT[{rec.txn}].lastLSN = {rec.lsn}")
            if rec.page_id not in dpt:
                dpt[rec.page_id] = rec.lsn
                notes.append(f"DPT[{rec.page_id}] = {rec.lsn} (recLSN)")
            rec.analysis_note = "; ".join(notes)
        elif rec.type == "commit":
            tt.setdefault(rec.txn, {"status": "running", "last_lsn": rec.lsn})
            tt[rec.txn]["status"] = "committed"
            tt[rec.txn]["last_lsn"] = rec.lsn
            rec.analysis_note = f"TT[{rec.txn}].status = committed"
        elif rec.type == "abort":
            tt.setdefault(rec.txn, {"status": "running", "last_lsn": rec.lsn})
            tt[rec.txn]["status"] = "aborting"
            tt[rec.txn]["last_lsn"] = rec.lsn
            rec.analysis_note = f"TT[{rec.txn}].status = aborting"
        elif rec.type == "end":
            tt.pop(rec.txn, None)
            rec.analysis_note = f"TT[{rec.txn}] removed (end)"
    return tt, dpt, ckpt_lsn


# ---------------------------------------------------------------------------
# 阶段二:重做(自最小 recLSN 起,重放确有缺失的更新)
# ---------------------------------------------------------------------------


def _redo(records: list[Record], pages: dict[int, PageImage], dpt: dict[int, int]) -> int | None:
    redo_start = min(dpt.values()) if dpt else None
    for rec in records:
        if rec.type != "update":
            continue
        if redo_start is None:
            rec.redo_note = "not scanned (DPT empty, nothing to redo)"
            continue
        if rec.lsn < redo_start:
            rec.redo_note = f"not scanned (LSN < redo start {redo_start})"
            continue
        page = pages[rec.page_id]
        if rec.page_id not in dpt:
            rec.redo_note = "skipped: page not in DPT"
            continue
        if rec.lsn < dpt[rec.page_id]:
            rec.redo_note = f"skipped: LSN < recLSN {dpt[rec.page_id]}"
            continue
        if page.lsn >= rec.lsn:
            rec.redo_note = f"skipped: pageLSN {page.lsn} >= LSN {rec.lsn} (already persisted)"
            continue
        lo, hi = rec.offset, rec.offset + rec.length
        current = bytes(page.data[lo:hi])
        if current != rec.before:
            raise Reject(
                "BEFORE_IMAGE_MISMATCH",
                f"redo of LSN {rec.lsn}: page {rec.page_id} bytes [{lo}, {hi}) are "
                f"{current.hex()}, expected before-image {rec.before.hex()}",
                rec.lsn,
            )
        page.data[lo:hi] = rec.after
        page.lsn = rec.lsn
        rec.redo_note = f"redone: before-image matched; pageLSN -> {rec.lsn}"
    return redo_start


# ---------------------------------------------------------------------------
# 阶段三:撤销(沿失败事务前驱链逆序,页 LSN 条件满足时才改写页像)
# ---------------------------------------------------------------------------


def _undo(records: list[Record], pages: dict[int, PageImage], tt: dict[str, dict]) -> list[dict]:
    by_lsn = {rec.lsn: rec for rec in records}
    max_lsn = records[-1].lsn if records else 0
    next_clr = max_lsn + 1
    clr_records: list[dict] = []

    losers = {txn: info["last_lsn"] for txn, info in tt.items() if info["status"] in ("running", "aborting")}
    pending = dict(losers)  # txn -> 下一个待撤销 LSN

    while pending:
        # ARIES:每次挑选最大 LSN 的失败事务;并列时按事务名确定顺序
        txn = max(pending, key=lambda t: (pending[t], t))
        lsn = pending[txn]
        rec = by_lsn.get(lsn)
        if rec is None or lsn <= 0:
            # 前驱链越出受限 WAL 窗口:窗口内无可撤销记录,关闭该事务
            for r in records:
                if r.txn == txn and r.type == "update" and r.undo_note == "n/a (not undone)":
                    r.undo_note = "not reached (predecessor chain leaves submitted WAL window)"
            del pending[txn]
            continue

        if rec.type == "update":
            page = pages[rec.page_id]
            if page.lsn < rec.lsn:
                rec.undo_note = f"skipped: pageLSN {page.lsn} < update LSN {rec.lsn} (update never persisted)"
            else:
                lo, hi = rec.offset, rec.offset + rec.length
                current = bytes(page.data[lo:hi])
                if current != rec.after:
                    raise Reject(
                        "UNDO_IMAGE_MISMATCH",
                        f"undo of LSN {rec.lsn}: page {rec.page_id} bytes [{lo}, {hi}) are "
                        f"{current.hex()}, expected after-image {rec.after.hex()}",
                        rec.lsn,
                    )
                page.data[lo:hi] = rec.before
                page.lsn = next_clr
                rec.undo_note = f"undone by CLR {next_clr}: before-image restored; pageLSN -> {next_clr}"
                clr_records.append(
                    {"lsn": next_clr, "txn": txn, "page_id": rec.page_id, "undoes_lsn": rec.lsn}
                )
                next_clr += 1
            pending[txn] = rec.prev_lsn or 0
        elif rec.type == "begin":
            rec.undo_note = "begin reached: loser txn closed (end)"
            del pending[txn]
        elif rec.type in ("commit", "abort"):
            rec.undo_note = "traversed during loser undo"
            pending[txn] = rec.prev_lsn or 0
        else:  # end 不应出现在失败事务链中;防御性关闭
            del pending[txn]
    return clr_records


# ---------------------------------------------------------------------------
# 裁决组装
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def recover(payload: dict) -> dict:
    """执行完整恢复审计,返回冻结裁决;违规输入抛出 Reject。"""
    _require(isinstance(payload, dict), "BAD_RECORD", "request body must be a JSON object")
    audit_id = _parse_audit_id(payload)
    page_list = _parse_pages(payload)
    pages = {p.page_id: p for p in page_list}
    records = _parse_wal(payload, pages)
    _validate_chains(records)

    tt, dpt, ckpt_lsn = _analyze(records)
    redo_start = _redo(records, pages, dpt)
    clr_records = _undo(records, pages, tt)

    winners = sorted(t for t, i in tt.items() if i["status"] == "committed")
    losers = sorted(t for t, i in tt.items() if i["status"] in ("running", "aborting"))

    verdict = {
        "audit_id": audit_id,
        "verdict": "OK",
        "checkpoint_lsn": ckpt_lsn,
        "redo_from_lsn": redo_start,
        "analysis": {
            "winners": winners,
            "losers": losers,
            "transaction_table": {t: dict(i) for t, i in sorted(tt.items())},
            "dirty_page_table": {str(p): dpt[p] for p in sorted(dpt)},
        },
        "records": [
            {
                "lsn": r.lsn,
                "type": r.type,
                "txn": r.txn,
                "analysis": r.analysis_note,
                "redo": r.redo_note,
                "undo": r.undo_note,
            }
            for r in records
        ],
        "clr_records": clr_records,
        "pages": [
            {
                "page_id": p.page_id,
                "page_lsn_before": p.lsn_before,
                "page_lsn_after": p.lsn,
                "sha256_before": _sha256(p.data_before),
                "sha256_after": _sha256(bytes(p.data)),
                "changed": bytes(p.data) != p.data_before or p.lsn != p.lsn_before,
            }
            for p in page_list
        ],
    }
    canonical = json.dumps(verdict, sort_keys=True, separators=(",", ":")).encode()
    verdict["verdict_sha256"] = _sha256(canonical)
    return verdict
