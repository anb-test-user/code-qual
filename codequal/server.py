"""A tiny stdlib HTTP server exposing the engine for the IDE plugin.

No third-party dependencies. Endpoints:
  GET  /health  -> {"status","mode","model"}
  POST /scan    -> body {"path","content","language"?,"focus_lines"?}
                   returns {"mode","model","errors","findings":[...]}
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from .engine import Engine
from .scanners.file import scan_content


def make_handler(engine: Engine):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, code: int, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            if self.path.split("?")[0] in ("/health", "/"):
                self._send(200, {"status": "ok", "mode": engine.mode, "model": engine.config.model})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path.split("?")[0] != "/scan":
                self._send(404, {"error": "not found"})
                return
            length = int(self.headers.get("Content-Length", 0) or 0)
            try:
                raw = self.rfile.read(length) if length else b"{}"
                data = json.loads(raw or b"{}")
            except (ValueError, OSError):
                self._send(400, {"error": "invalid JSON body"})
                return
            content = data.get("content")
            if content is None:
                self._send(400, {"error": "'content' is required"})
                return
            focus = data.get("focus_lines")
            focus_set = {int(x) for x in focus} if isinstance(focus, list) else None
            result = scan_content(
                data.get("path", "buffer"),
                content,
                engine=engine,
                language=data.get("language"),
                focus_lines=focus_set,
                kind="diff" if focus_set else "file",
            )
            self._send(
                200,
                {
                    "mode": result.mode,
                    "model": result.model,
                    "errors": result.errors,
                    "findings": [f.to_dict() for f in result.sorted_findings()],
                },
            )

        def log_message(self, *args) -> None:  # silence default request logging
            return

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8787, engine: Optional[Engine] = None) -> None:
    engine = engine or Engine()
    httpd = ThreadingHTTPServer((host, port), make_handler(engine))
    print(f"CodeQual server on http://{host}:{port}  (mode={engine.mode}, model={engine.config.model})")
    print("  POST /scan  {path, content, language?}   ·   GET /health")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        httpd.server_close()
