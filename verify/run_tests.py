#!/usr/bin/env python3
"""verify 容器入口:规则测试 + 构建检查 + API/HTTP 冒烟,完成后以退出码结束。

  退出码 0:全部通过;退出码 1:任一失败。

环境变量:
  BASE_URL   被测服务地址(默认 http://127.0.0.1:8000;Compose 中为 http://app:8000)
"""

from __future__ import annotations

import hashlib
import json
import os
import py_compile
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "app"))

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8000").rstrip("/")

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str):
    """测试用例装饰器:异常即失败。"""
    def deco(fn):
        try:
            fn()
            RESULTS.append((name, True, ""))
        except Exception as exc:  # noqa: BLE001 - 测试框架需捕获一切
            RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))
        return fn
    return deco


def expect(cond: bool, msg: str):
    if not cond:
        raise AssertionError(msg)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# 共享场景:已提交事务 T1 / 失败事务 T2 / 检查点 / 崩溃页像
# ---------------------------------------------------------------------------


def sample_payload() -> dict:
    return {
        "audit_id": "SAT-ATT-2026-001",
        "pages": [
            {"page_id": 7, "page_lsn": 110, "data": "1111" + "00" * 14},
            {"page_id": 9, "page_lsn": 90, "data": "00" * 16},
        ],
        "wal": [
            {"lsn": 100, "type": "begin", "txn": "T1"},
            {"lsn": 110, "type": "update", "txn": "T1", "prev_lsn": 100, "page_id": 7,
             "offset": 0, "length": 2, "before": "0000", "after": "1111"},
            {"lsn": 120, "type": "begin", "txn": "T2"},
            {"lsn": 130, "type": "update", "txn": "T2", "prev_lsn": 120, "page_id": 7,
             "offset": 4, "length": 2, "before": "0000", "after": "2222"},
            {"lsn": 140, "type": "checkpoint",
             "txns": [{"txn": "T1", "last_lsn": 110, "status": "running"},
                      {"txn": "T2", "last_lsn": 130, "status": "running"}],
             "dpt": [{"page_id": 7, "rec_lsn": 110}]},
            {"lsn": 150, "type": "update", "txn": "T1", "prev_lsn": 110, "page_id": 9,
             "offset": 0, "length": 2, "before": "0000", "after": "3333"},
            {"lsn": 160, "type": "commit", "txn": "T1", "prev_lsn": 150},
            {"lsn": 170, "type": "update", "txn": "T2", "prev_lsn": 130, "page_id": 9,
             "offset": 4, "length": 2, "before": "0000", "after": "4444"},
        ],
    }


def expect_reject(payload: dict, code: str):
    from recovery import Reject, recover
    try:
        recover(payload)
    except Reject as rej:
        expect(rej.code == code, f"expected reject {code}, got {rej.code}: {rej.message}")
        return
    raise AssertionError(f"expected reject {code}, but recovery succeeded")


# ---------------------------------------------------------------------------
# 第一部分:规则测试(直接驱动恢复引擎)
# ---------------------------------------------------------------------------


@check("rule: 已提交事务的缺失更新被重做(补写)")
def _():
    from recovery import recover
    v = recover(sample_payload())
    expect(v["verdict"] == "OK", "verdict must be OK")
    expect(v["analysis"]["winners"] == ["T1"], f"winners: {v['analysis']['winners']}")
    expect(v["redo_from_lsn"] == 110, f"redo_from_lsn: {v['redo_from_lsn']}")
    p9 = next(p for p in v["pages"] if p["page_id"] == 9)
    # T1 已提交,LSN 150 的更新未落盘(pageLSN 90 < 150),必须重做补写
    expect(p9["sha256_after"] == sha256_hex(bytes.fromhex("3333" + "00" * 14)),
           "page 9 must contain redone committed update 3333")
    rec150 = next(r for r in v["records"] if r["lsn"] == 150)
    expect(rec150["redo"].startswith("redone"), f"LSN 150 redo note: {rec150['redo']}")


@check("rule: 失败事务的已落盘更新被逆序回滚(CLR)")
def _():
    from recovery import recover
    v = recover(sample_payload())
    expect(v["analysis"]["losers"] == ["T2"], f"losers: {v['analysis']['losers']}")
    p7 = next(p for p in v["pages"] if p["page_id"] == 7)
    p9 = next(p for p in v["pages"] if p["page_id"] == 9)
    # T2 的 2222(LSN 130)与 4444(LSN 170)必须全部被回滚
    expect(p7["sha256_after"] == sha256_hex(bytes.fromhex("1111" + "00" * 14)),
           "page 7 loser bytes must be rolled back")
    expect(p9["sha256_after"] == sha256_hex(bytes.fromhex("3333" + "00" * 14)),
           "page 9 loser bytes must be rolled back")
    # 逆序:先撤销 LSN 170(CLR 171),再撤销 LSN 130(CLR 172)
    expect([c["undoes_lsn"] for c in v["clr_records"]] == [170, 130],
           f"CLR order: {v['clr_records']}")
    expect(p9["page_lsn_after"] == 171 and p7["page_lsn_after"] == 172,
           f"CLR pageLSN: p9={p9['page_lsn_after']} p7={p7['page_lsn_after']}")


@check("rule: 损坏的前驱链被稳定拒绝(BROKEN_CHAIN)")
def _():
    payload = sample_payload()
    payload["wal"][5]["prev_lsn"] = 999  # LSN 150 的前驱应为 110
    expect_reject(payload, "BROKEN_CHAIN")
    payload2 = sample_payload()
    payload2["wal"][2]["prev_lsn"] = 100  # begin 不得携带前驱 -> 结构非法
    payload2["wal"][2] = {"lsn": 120, "type": "update", "txn": "T2", "prev_lsn": 100,
                          "page_id": 7, "offset": 8, "length": 1, "before": "00", "after": "99"}
    expect_reject(payload2, "BROKEN_CHAIN")  # 前驱 100 属于 T1


@check("rule: 重复 LSN 被稳定拒绝(DUPLICATE_LSN)")
def _():
    payload = sample_payload()
    payload["wal"][3]["lsn"] = 120  # 与 begin T2 重复
    expect_reject(payload, "DUPLICATE_LSN")


@check("rule: 越界半开区间被稳定拒绝(INTERVAL_OUT_OF_BOUNDS)")
def _():
    payload = sample_payload()
    payload["wal"][1]["offset"] = 15
    payload["wal"][1]["length"] = 2  # [15,17) 超出 16 字节页
    payload["wal"][1]["before"] = "0000"
    payload["wal"][1]["after"] = "9999"
    expect_reject(payload, "INTERVAL_OUT_OF_BOUNDS")


@check("rule: 已结束事务仍被引用被稳定拒绝(TXN_ENDED)")
def _():
    payload = sample_payload()
    payload["wal"].append({"lsn": 180, "type": "end", "txn": "T1", "prev_lsn": 160})
    payload["wal"].append({"lsn": 190, "type": "update", "txn": "T1", "prev_lsn": 180,
                           "page_id": 9, "offset": 8, "length": 1, "before": "00", "after": "55"})
    expect_reject(payload, "TXN_ENDED")


@check("rule: 错误前像被稳定拒绝(BEFORE_IMAGE_MISMATCH)")
def _():
    payload = sample_payload()
    payload["wal"][5]["before"] = "ffff"  # LSN 150 前像应为 0000
    expect_reject(payload, "BEFORE_IMAGE_MISMATCH")


@check("rule: 前后像不等长被稳定拒绝(BAD_IMAGE_LENGTH)")
def _():
    payload = sample_payload()
    payload["wal"][1]["after"] = "111122"  # length=2 但 after 为 3 字节
    expect_reject(payload, "BAD_IMAGE_LENGTH")


@check("rule: 检查点播种分析,recLSN 之前的更新不被重做")
def _():
    from recovery import recover
    v = recover(sample_payload())
    a = v["analysis"]
    expect(a["dirty_page_table"] == {"7": 110, "9": 150}, f"DPT: {a['dirty_page_table']}")
    expect(a["transaction_table"]["T1"]["status"] == "committed", "T1 committed")
    expect(a["transaction_table"]["T2"]["status"] == "running", "T2 running")
    rec110 = next(r for r in v["records"] if r["lsn"] == 110)
    expect("pageLSN 110 >= LSN 110" in rec110["redo"], f"LSN 110 redo: {rec110['redo']}")
    rec100 = next(r for r in v["records"] if r["lsn"] == 100)
    expect("not scanned" in rec100["analysis"], f"LSN 100 analysis: {rec100['analysis']}")


@check("rule: 未持久化的失败事务更新在撤销时被跳过(页 LSN 条件)")
def _():
    from recovery import recover
    payload = {
        "audit_id": "SAT-ATT-SKIP",
        "pages": [
            {"page_id": 3, "page_lsn": 50, "data": "00" * 8},
            {"page_id": 4, "page_lsn": 0, "data": "00" * 8},
        ],
        "wal": [
            {"lsn": 100, "type": "begin", "txn": "T1"},
            # 检查点 DPT:页 3 的 recLSN=200(晚于后续更新),页 4 的 recLSN=120
            {"lsn": 110, "type": "checkpoint",
             "txns": [{"txn": "T1", "last_lsn": 100, "status": "running"}],
             "dpt": [{"page_id": 3, "rec_lsn": 200}, {"page_id": 4, "rec_lsn": 120}]},
            {"lsn": 120, "type": "update", "txn": "T1", "prev_lsn": 100, "page_id": 3,
             "offset": 0, "length": 2, "before": "0000", "after": "9999"},
        ],
    }
    v = recover(payload)
    rec120 = next(r for r in v["records"] if r["lsn"] == 120)
    # 重做起点 = min(200,120) = 120;LSN 120 < 页 3 的 recLSN 200 -> 不重做
    expect("recLSN" in rec120["redo"], f"redo: {rec120['redo']}")
    # 页 3 pageLSN=50 < 120:更新从未持久化 -> 撤销跳过,页像保持原样
    expect("never persisted" in rec120["undo"], f"undo: {rec120['undo']}")
    p3 = next(p for p in v["pages"] if p["page_id"] == 3)
    expect(p3["sha256_after"] == p3["sha256_before"], "page must stay untouched")
    expect(p3["page_lsn_after"] == 50, f"pageLSN: {p3['page_lsn_after']}")


@check("rule: 超限输入被稳定拒绝(LIMIT_EXCEEDED)")
def _():
    payload = sample_payload()
    payload["pages"] = [{"page_id": i, "page_lsn": 0, "data": "00"} for i in range(49)]
    expect_reject(payload, "LIMIT_EXCEEDED")
    payload = sample_payload()
    payload["wal"] = payload["wal"] + [
        {"lsn": 1000 + i, "type": "checkpoint", "txns": [], "dpt": []} for i in range(122)
    ]
    expect_reject(payload, "LIMIT_EXCEEDED")


@check("rule: 裁决是冻结的(同一输入得到同一 verdict_sha256)")
def _():
    from recovery import recover
    v1 = recover(sample_payload())
    v2 = recover(sample_payload())
    expect(v1["verdict_sha256"] == v2["verdict_sha256"], "verdict digest must be deterministic")


# ---------------------------------------------------------------------------
# 第二部分:构建检查
# ---------------------------------------------------------------------------


@check("build: 全部 Python 源文件可编译")
def _():
    for path in sorted(ROOT.glob("app/**/*.py")) + sorted(ROOT.glob("verify/**/*.py")):
        py_compile.compile(str(path), doraise=True)


@check("build: Docker 交付物齐备且内容合法")
def _():
    for name in ("Dockerfile", "docker-compose.yml", ".dockerignore"):
        p = ROOT / name
        expect(p.is_file(), f"missing {name}")
        expect(p.stat().st_size > 0, f"empty {name}")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    expect("HOST_PORT" in compose, "compose must expose configurable host port via HOST_PORT")
    expect("service_healthy" in compose, "verify must wait for app health")
    expect("/health" in compose, "compose must probe /health")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    expect("USER" in dockerfile, "image must drop root")
    index = ROOT / "app" / "static" / "index.html"
    expect(index.is_file() and "审计" in index.read_text(encoding="utf-8"), "index.html missing")


# ---------------------------------------------------------------------------
# 第三部分:API / HTTP 冒烟
# ---------------------------------------------------------------------------


def http(method: str, path: str, body: dict | None = None, timeout: float = 5.0):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE_URL + path, data=data, method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


@check("http: 服务可达且 /health 返回 ok")
def _():
    deadline = time.time() + 30
    last = None
    while time.time() < deadline:
        try:
            status, body = http("GET", "/health")
            expect(status == 200 and body.get("status") == "ok", f"health: {status} {body}")
            return
        except Exception as exc:  # 服务尚未就绪,重试
            last = exc
            time.sleep(1)
    raise AssertionError(f"service not reachable at {BASE_URL}: {last}")


@check("http: GET / 返回审计页面")
def _():
    req = urllib.request.Request(BASE_URL + "/")
    with urllib.request.urlopen(req, timeout=5) as resp:
        html = resp.read().decode()
        ctype = resp.headers.get("Content-Type", "")
    expect(resp.status == 200 and "text/html" in ctype, f"GET /: {resp.status} {ctype}")
    expect("崩溃恢复审计" in html and "/api/recover" in html, "page must reference audit API")


@check("http: POST /api/recover 冻结裁决,GET /api/verdict 可读回")
def _():
    payload = sample_payload()
    payload["audit_id"] = "SMOKE-OK-001"
    status, body = http("POST", "/api/recover", payload)
    expect(status == 200 and body["verdict"] == "OK", f"recover: {status} {body.get('error')}")
    expect(body["analysis"]["winners"] == ["T1"] and body["analysis"]["losers"] == ["T2"],
           "smoke analysis mismatch")
    status2, body2 = http("GET", "/api/verdict/SMOKE-OK-001")
    expect(status2 == 200, f"verdict read: {status2}")
    expect(body2["verdict_sha256"] == body["verdict_sha256"], "frozen verdict digest mismatch")


@check("http: 损坏前驱链被拒绝且旧成功证据被清除")
def _():
    ok_payload = sample_payload()
    ok_payload["audit_id"] = "SMOKE-CLEAR-001"
    status, _ = http("POST", "/api/recover", ok_payload)
    expect(status == 200, "seed success verdict first")
    bad = sample_payload()
    bad["audit_id"] = "SMOKE-CLEAR-001"
    bad["wal"][5]["prev_lsn"] = 999
    status, body = http("POST", "/api/recover", bad)
    expect(status == 422 and body.get("error") == "BROKEN_CHAIN", f"reject: {status} {body}")
    status2, body2 = http("GET", "/api/verdict/SMOKE-CLEAR-001")
    expect(status2 == 404 and body2.get("error") == "NOT_FOUND",
           f"old success evidence must be cleared, got {status2}")


@check("http: 各类稳定拒绝码经 API 可达")
def _():
    cases = []
    p = sample_payload(); p["audit_id"] = "SMOKE-DUP"; p["wal"][3]["lsn"] = 120
    cases.append((p, "DUPLICATE_LSN"))
    p = sample_payload(); p["audit_id"] = "SMOKE-OOB"
    p["wal"][1]["offset"] = 15; p["wal"][1]["length"] = 2
    p["wal"][1]["before"] = "0000"; p["wal"][1]["after"] = "9999"
    cases.append((p, "INTERVAL_OUT_OF_BOUNDS"))
    p = sample_payload(); p["audit_id"] = "SMOKE-ENDED"
    p["wal"].append({"lsn": 180, "type": "end", "txn": "T1", "prev_lsn": 160})
    p["wal"].append({"lsn": 190, "type": "update", "txn": "T1", "prev_lsn": 180,
                     "page_id": 9, "offset": 8, "length": 1, "before": "00", "after": "55"})
    cases.append((p, "TXN_ENDED"))
    p = sample_payload(); p["audit_id"] = "SMOKE-BEFORE"
    p["wal"][5]["before"] = "ffff"
    cases.append((p, "BEFORE_IMAGE_MISMATCH"))
    for payload, code in cases:
        status, body = http("POST", "/api/recover", payload)
        expect(status == 422 and body.get("error") == code,
               f"expected {code}, got {status} {body.get('error')}")


@check("http: 未知审计标识查询返回 404")
def _():
    status, body = http("GET", "/api/verdict/NEVER-EXISTED")
    expect(status == 404 and body.get("error") == "NOT_FOUND", f"got {status} {body}")


# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------


def main() -> int:
    width = max((len(n) for n, _, _ in RESULTS), default=0)
    failed = 0
    for name, ok, detail in RESULTS:
        mark = "PASS" if ok else "FAIL"
        print(f"[{mark}] {name.ljust(width)}" + (f"  -- {detail}" if detail else ""), flush=True)
        if not ok:
            failed += 1
    total = len(RESULTS)
    print(f"\nverify: {total - failed}/{total} passed against {BASE_URL}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
