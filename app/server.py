"""星载姿控参数恢复审计服务(仅 Python 标准库)。

端点:
  GET  /                     审计页面(填写审计标识、初始页像、受限 WAL)
  GET  /health               健康响应 {"status": "ok"}
  POST /api/recover          提交审计负载,返回冻结的恢复裁决;
                             违规负载以稳定错误码拒绝,并清除该标识旧的成功证据
  GET  /api/verdict/<id>     读取该审计标识已冻结的裁决(无则 404)

端口由环境变量 PORT 控制(默认 8000),宿主机端口映射由 Docker Compose 配置。
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from recovery import Reject, recover

PORT = int(os.environ.get("PORT", "8000"))
MAX_BODY = 1 << 20  # 1 MiB
STATIC_DIR = Path(__file__).resolve().parent / "static"

# audit_id -> 冻结裁决;仅在成功时写入,拒绝时清除(状态进程内保持)
_VERDICTS: dict[str, dict] = {}
_LOCK = threading.Lock()


def _json_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "SatRecoveryAudit/1.0"
    protocol_version = "HTTP/1.1"

    # -- 工具 ---------------------------------------------------------------

    def _send(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, obj):
        self._send(status, _json_bytes(obj), "application/json; charset=utf-8")

    def log_message(self, fmt, *args):  # 静默访问日志,保持审计输出干净
        pass

    # -- GET ----------------------------------------------------------------

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            self._send_json(200, {"status": "ok"})
            return
        if path == "/":
            index = STATIC_DIR / "index.html"
            self._send(200, index.read_bytes(), "text/html; charset=utf-8")
            return
        if path.startswith("/api/verdict/"):
            audit_id = unquote(path[len("/api/verdict/"):])
            with _LOCK:
                verdict = _VERDICTS.get(audit_id)
            if verdict is None:
                self._send_json(404, {"error": "NOT_FOUND", "message": f"no frozen verdict for audit_id {audit_id!r}"})
            else:
                self._send_json(200, verdict)
            return
        self._send_json(404, {"error": "NOT_FOUND", "message": f"unknown path {path}"})

    # -- POST ---------------------------------------------------------------

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/api/recover":
            self._send_json(404, {"error": "NOT_FOUND", "message": f"unknown path {path}"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self._send_json(413, {"error": "PAYLOAD_TOO_LARGE", "message": f"body must be 1..{MAX_BODY} bytes"})
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._send_json(400, {"error": "BAD_JSON", "message": f"request body is not valid JSON: {exc}"})
            return

        # 无论后续校验是否通过,先尽力提取审计标识,以便拒绝时清除旧成功证据
        audit_id = payload.get("audit_id") if isinstance(payload, dict) else None

        try:
            verdict = recover(payload)
        except Reject as rej:
            if isinstance(audit_id, str):
                with _LOCK:
                    _VERDICTS.pop(audit_id, None)
            self._send_json(422, rej.to_dict())
            return

        with _LOCK:
            _VERDICTS[verdict["audit_id"]] = verdict
        self._send_json(200, verdict)


def main():
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"sat-recovery-audit listening on 0.0.0.0:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
