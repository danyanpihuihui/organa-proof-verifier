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
) -> ThreadingHTTPServer:
    if max_request_bytes <= 0:
        raise ValueError("max_request_bytes must be positive")
    resolvers = dict(_DEFAULT_RESOLVERS if resolver_urls is None else resolver_urls)

    class Handler(BaseHTTPRequestHandler):
        server_version = "OrganaProofVerifier/0.1"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send(self, status: int, body: Mapping[str, Any]) -> None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
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
    args = parser.parse_args(argv)
    server = create_server(args.host, args.port, max_request_bytes=args.max_request_bytes)
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
