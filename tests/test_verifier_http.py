import json
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from bitmap_memory_portal.verifier_http import create_server


def _request(base_url, path, *, method="GET", payload=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        base_url + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        response = urlopen(request, timeout=2)
    except HTTPError as exc:
        response = exc
    with response:
        return response.status, json.loads(response.read().decode("utf-8"))


def _running_server(**dependencies):
    server = create_server("127.0.0.1", 0, **dependencies)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_address[1]}"


def test_http_health_and_openapi_are_served():
    server, thread, base = _running_server()
    try:
        status, body = _request(base, "/health")
        spec_status, spec = _request(base, "/openapi.json")
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert status == 200
    assert body["ok"] is True
    assert body["status"] == "healthy"
    assert spec_status == 200
    assert spec["info"]["title"] == "Organa Proof Verifier API"


def test_http_resolves_supported_cell_with_configured_resolver():
    seen = {}

    def resolve(coordinate, resolver_url):
        seen.update(coordinate=coordinate, resolver_url=resolver_url)
        return {"ok": True, "status": "resolved-integrity-valid", "errors": [], "warnings": [], "hashes": {}}

    server, thread, base = _running_server(
        resolve_func=resolve,
        resolver_urls={"7187.bitmap": "https://resolver.example/.well-known/organa.json"},
    )
    try:
        status, body = _request(base, "/v1/cell/7187.bitmap")
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert status == 200
    assert body["ok"] is True
    assert seen == {
        "coordinate": "7187.bitmap",
        "resolver_url": "https://resolver.example/.well-known/organa.json",
    }


def test_http_controller_claim_and_package_routes_delegate_exact_json():
    seen = {}

    def verify_claim(signing_address, message, signature):
        seen["claim"] = (signing_address, message, signature)
        return {"ok": True, "status": "cryptographically-valid", "errors": [], "warnings": [], "hashes": {}}

    def verify_package(package):
        seen["package"] = package
        return {"ok": False, "status": "integrity-invalid", "errors": [{"code": "changed-resource", "message": "bad"}], "warnings": [], "hashes": {}}

    server, thread, base = _running_server(verify_claim_func=verify_claim, verify_package_func=verify_package)
    try:
        claim_status, claim = _request(base, "/v1/verify/controller-claim", method="POST", payload={
            "signing_address": "address", "message": "message", "signature": "signature"
        })
        package_status, package = _request(base, "/v1/verify/package", method="POST", payload={"files": {"organa-cell.json": {}}})
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert claim_status == 200
    assert claim["ok"] is True
    assert seen["claim"] == ("address", "message", "signature")
    assert package_status == 422
    assert package["ok"] is False
    assert seen["package"] == {"files": {"organa-cell.json": {}}}


def test_http_rejects_bad_json_large_body_unknown_route_and_missing_fields():
    server, thread, base = _running_server(max_request_bytes=32)
    try:
        bad = Request(base + "/v1/verify/package", data=b"{", method="POST", headers={"Content-Type": "application/json"})
        try:
            urlopen(bad, timeout=2)
        except HTTPError as exc:
            with exc:
                bad_status = exc.status
                bad_body = json.loads(exc.read())

        large_status, large = _request(base, "/v1/verify/package", method="POST", payload={"files": {"x": "y" * 100}})
        missing_status, missing = _request(base, "/v1/verify/controller-claim", method="POST", payload={"message": "m"})
        unknown_status, unknown = _request(base, "/unknown")
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert bad_status == 400
    assert bad_body["errors"][0]["code"] == "malformed-json"
    assert large_status == 413
    assert large["errors"][0]["code"] == "request-too-large"
    assert missing_status == 400
    assert missing["errors"][0]["code"] == "missing-field"
    assert unknown_status == 404
    assert unknown["ok"] is False


def test_http_requires_json_content_type():
    server, thread, base = _running_server()
    try:
        request = Request(
            base + "/v1/verify/package",
            data=b'{}',
            method="POST",
            headers={"Content-Type": "text/plain"},
        )
        try:
            urlopen(request, timeout=2)
        except HTTPError as exc:
            with exc:
                status = exc.status
                body = json.loads(exc.read())
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert status == 415
    assert body["errors"][0]["code"] == "unsupported-media-type"


def test_http_disallows_package_path_from_remote_request():
    server, thread, base = _running_server()
    try:
        status, body = _request(base, "/v1/verify/package", method="POST", payload={"package_path": "/etc"})
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert status == 400
    assert body["errors"][0]["code"] == "remote-path-disallowed"
