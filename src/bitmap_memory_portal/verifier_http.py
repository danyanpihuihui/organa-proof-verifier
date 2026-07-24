from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Mapping
from urllib.parse import unquote, urlparse

from .proof_verifier import health_response, resolve_cell, verify_controller_claim, verify_package

_DEFAULT_MAX_REQUEST_BYTES = 1_048_576
_DEFAULT_RESOLVERS = {
    "7187.bitmap": "https://danyanpihuihui.github.io/organa-cell-7187/.well-known/organa.json",
}
_ROOT = Path(__file__).resolve().parents[2]
_LANDING_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Organa Proof Verifier</title><style>body{margin:0;background:#090b10;color:#edf4ff;font:16px/1.6 system-ui;max-width:900px;padding:64px 24px;margin:auto}a{color:#ff9b4a}.card{background:#111722;border:1px solid #273247;border-radius:16px;padding:24px;margin:20px 0}.status{display:inline-block;color:#71e6ae;border:1px solid #285b48;border-radius:999px;padding:7px 12px}</style></head><body><h1>Organa Proof Verifier</h1><p>Public, read-only cryptographic and structural verification for Organa Cells.</p><div class="card"><h2>7187.bitmap</h2><p class="status">Live · Active · BIP-322 verified · v0.2.0</p><p>The first live Organa Cell. Verify its canonical manifest, linked resources, version continuity and signed controller claim without exposing private execution data.</p><p><a href="/v1/cell/7187.bitmap">Run public verification</a> · <a href="https://danyanpihuihui.github.io/organa-cell-7187/.well-known/organa.json">Canonical resolver</a> · <a href="https://danyanpihuihui.github.io/organa-cell-7187/versions/0.2.0/controller-claim.json">Signed claim</a> · <a href="https://danyanpihuihui.github.io/organa-cell-7187/organa-state-semantics-v0.1.json">State semantics</a></p></div><p><a href="/docs">API documentation</a> · <a href="/openapi.json">OpenAPI JSON</a> · <a href="/health">Health</a></p><p>Verification proves structural integrity and controller authentication. It does not prove business truth, economic performance, or private execution correctness.</p></body></html>"""
_DOCS_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Organa Verifier API</title><style>body{background:#090b10;color:#edf4ff;font:16px/1.6 system-ui;max-width:900px;margin:50px auto;padding:24px}a{color:#ff9b4a}code{background:#111722;color:#71e6ae;padding:3px 7px;border-radius:6px}li{margin:12px 0}</style></head><body><h1>Organa Proof Verifier API</h1><p>Machine contract: <a href="/openapi.json">openapi.json</a></p><p>State model: <a href="https://danyanpihuihui.github.io/organa-cell-7187/organa-state-semantics-v0.1.json">organa-state-semantics-v0.1.json</a></p><ul><li><code>GET /health</code></li><li><code>GET /v1/cell/{coordinate}</code></li><li><code>POST /v1/verify/package</code></li><li><code>POST /v1/verify/controller-claim</code></li></ul><p><a href="/">Back to verifier</a></p></body></html>"""


def _failure(status: str, code: str, message: str) -> Dict[str, Any]:
    return {"ok": False, "status": status, "errors": [{"code": code, "message": message}], "warnings": [], "hashes": {}}


def _http_status(result: Mapping[str, Any]) -> int:
    if result.get("ok") is True:
        return 200
    status = result.get("status")
    if status in {"invalid-input", "unsupported-coordinate"}:
        return 400
    return 422


def create_server(
    host: str,
    port: int,
    *,
    resolve_func: Callable[..., Dict[str, Any]] = resolve_cell,
    verify_package_func: Callable[[Any], Dict[str, Any]] = verify_package,
    verify_claim_func: Callable[..., Dict[str, Any]] = verify_controller_claim,
    resolver_urls: Mapping[str, str] | None = None,
    max_request_bytes: int = _DEFAULT_MAX_REQUEST_BYTES,
    cors_origins: list[str] | tuple[str, ...] | None = None,
) -> ThreadingHTTPServer:
    if max_request_bytes <= 0:
        raise ValueError("max_request_bytes must be positive")
    resolvers = dict(_DEFAULT_RESOLVERS if resolver_urls is None else resolver_urls)
    allowed_origins = frozenset(cors_origins or ())

    class Handler(BaseHTTPRequestHandler):
        server_version = "OrganaProofVerifier/0.1"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _cors(self) -> None:
            origin = self.headers.get("Origin")
            if origin in allowed_origins:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")

        def _send(self, status: int, body: Mapping[str, Any]) -> None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self._cors()
            self.end_headers()
            self.wfile.write(data)

        def _send_html(self, status: int, body: str) -> None:
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "public, max-age=300")
            self.send_header("X-Content-Type-Options", "nosniff")
            self._cors()
            self.end_headers()
            self.wfile.write(data)

        def _read_json(self) -> tuple[Dict[str, Any] | None, tuple[int, Dict[str, Any]] | None]:
            content_type = self.headers.get_content_type()
            if content_type != "application/json":
                return None, (415, _failure("invalid-input", "unsupported-media-type", "Content-Type must be application/json"))
            content_length = self.headers.get("Content-Length")
            if content_length is None:
                return None, (411, _failure("invalid-input", "content-length-required", "Content-Length is required"))
            try:
                length = int(content_length)
            except ValueError:
                return None, (400, _failure("invalid-input", "invalid-content-length", "Content-Length must be an integer"))
            if length < 0:
                return None, (400, _failure("invalid-input", "invalid-content-length", "Content-Length must not be negative"))
            if length > max_request_bytes:
                return None, (413, _failure("invalid-input", "request-too-large", "request body exceeds configured limit"))
            raw = self.rfile.read(length)
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                return None, (400, _failure("invalid-input", "malformed-json", str(exc)))
            if not isinstance(value, dict):
                return None, (400, _failure("invalid-input", "malformed-json", "JSON body must be an object"))
            return value, None

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self._send_html(200, _LANDING_HTML)
                return
            if parsed.path == "/docs":
                self._send_html(200, _DOCS_HTML)
                return
            if parsed.path == "/health":
                self._send(200, health_response())
                return
            if parsed.path == "/openapi.json":
                try:
                    spec = json.loads((_ROOT / "openapi.json").read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    self._send(500, _failure("verifier-unavailable", "openapi-unavailable", str(exc)))
                    return
                self._send(200, spec)
                return
            prefix = "/v1/cell/"
            if parsed.path.startswith(prefix):
                coordinate = unquote(parsed.path[len(prefix):])
                resolver_url = resolvers.get(coordinate)
                if resolver_url is None:
                    self._send(400, _failure("unsupported-coordinate", "unsupported-coordinate", "no resolver is configured for this coordinate"))
                    return
                result = resolve_func(coordinate, resolver_url)
                self._send(_http_status(result), result)
                return
            self._send(404, _failure("not-found", "not-found", "route not found"))

        def do_OPTIONS(self) -> None:
            origin = self.headers.get("Origin")
            if origin not in allowed_origins:
                self._send(403, _failure("invalid-input", "cors-origin-denied", "origin is not allowed"))
                return
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "content-type")
            self.send_header("Access-Control-Max-Age", "600")
            self.send_header("Vary", "Origin")
            self.end_headers()

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            value, error = self._read_json()
            if error is not None:
                self._send(*error)
                return
            assert value is not None
            if parsed.path == "/v1/verify/controller-claim":
                required = ("signing_address", "message", "signature")
                missing = [field for field in required if not isinstance(value.get(field), str) or not value[field]]
                if missing:
                    self._send(400, _failure("invalid-input", "missing-field", "missing non-empty string field(s): " + ", ".join(missing)))
                    return
                result = verify_claim_func(value["signing_address"], value["message"], value["signature"])
                self._send(_http_status(result), result)
                return
            if parsed.path == "/v1/verify/package":
                if "package_path" in value:
                    self._send(400, _failure("invalid-input", "remote-path-disallowed", "HTTP clients cannot submit local filesystem paths"))
                    return
                result = verify_package_func(value)
                self._send(_http_status(result), result)
                return
            self._send(404, _failure("not-found", "not-found", "route not found"))

    return ThreadingHTTPServer((host, port), Handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Organa Proof Verifier HTTP service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--max-request-bytes", type=int, default=_DEFAULT_MAX_REQUEST_BYTES)
    parser.add_argument(
        "--cors-origin",
        action="append",
        default=["https://danyanpihuihui.github.io"],
        help="Allowed browser origin; repeatable",
    )
    args = parser.parse_args(argv)
    server = create_server(
        args.host,
        args.port,
        max_request_bytes=args.max_request_bytes,
        cors_origins=args.cors_origin,
    )
    print(json.dumps({"ok": True, "status": "listening", "host": args.host, "port": server.server_address[1]}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
