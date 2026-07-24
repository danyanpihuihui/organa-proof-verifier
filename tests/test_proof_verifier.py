import json
import socket
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest

from bitmap_memory_portal.cell_resolution import build_cell_resolution_package
from bitmap_memory_portal.proof_verifier import (
    FetchError,
    default_https_fetch,
    health_response,
    resolve_cell,
    verify_controller_claim,
    verify_package,
)


COORDINATE = "7187.bitmap"
BASE_URL = "https://resolver.example/cell"
ADDRESS = "bc1ptestcontroller"


def _package(tmp_path: Path) -> Path:
    out = tmp_path / "package"
    build_cell_resolution_package(out, COORDINATE, BASE_URL, ADDRESS)
    return out


def _files(out: Path) -> dict[str, object]:
    return {
        path.relative_to(out).as_posix(): json.loads(path.read_text(encoding="utf-8"))
        for path in out.rglob("*.json")
        if path.name != "verification-report.json"
    }


def _response_ok(result: dict) -> None:
    assert set(("ok", "status", "errors", "warnings", "hashes")).issubset(result)


def test_health_response_is_framework_neutral_and_structured():
    result = health_response()

    assert result == {
        "ok": True,
        "status": "healthy",
        "service": "organa-proof-verifier",
        "errors": [],
        "warnings": [],
        "hashes": {},
    }


def test_verify_package_accepts_safe_local_directory(tmp_path):
    result = verify_package(_package(tmp_path))

    _response_ok(result)
    assert result["ok"] is True
    assert result["status"] == "integrity-valid"
    assert result["integrity_valid"] is True
    assert result["business_content_verified"] is False
    assert result["hashes"]["cell_manifest"].startswith("sha256:")
    assert result["warnings"] == ["Integrity and cryptographic checks do not establish the truth of business content."]


def test_verify_package_accepts_structured_json_mapping(tmp_path):
    result = verify_package({"files": _files(_package(tmp_path))})

    assert result["ok"] is True
    assert result["source_type"] == "structured-json"


def test_verify_package_rejects_unsafe_directory_and_malformed_json(tmp_path):
    not_directory = tmp_path / "package.json"
    not_directory.write_text("{}", encoding="utf-8")

    unsafe = verify_package(not_directory)
    malformed = verify_package({"files": {"organa-cell.json": "{"}})

    assert unsafe["ok"] is False
    assert unsafe["status"] == "invalid-input"
    assert unsafe["errors"][0]["code"] == "unsafe-local-package"
    assert malformed["ok"] is False
    assert malformed["errors"][0]["code"] == "malformed-json"


def test_verify_package_rejects_structured_path_escape(tmp_path):
    result = verify_package({"files": {"../../outside.json": {"secret": True}}})

    assert result["ok"] is False
    assert result["errors"][0]["code"] == "unsafe-package-path"
    assert not (tmp_path / "outside.json").exists()


def test_resolve_cell_downloads_discovery_and_package_with_injected_fetcher(tmp_path):
    out = _package(tmp_path)
    payloads = {
        f"{BASE_URL}/.well-known/organa.json": (out / ".well-known/organa.json").read_bytes(),
        **{
            f"{BASE_URL}/{path.relative_to(out).as_posix()}": path.read_bytes()
            for path in out.rglob("*.json")
            if path.name != "verification-report.json" and path.relative_to(out).as_posix() != ".well-known/organa.json"
        },
    }
    calls = []

    def fetch(url, *, timeout, max_bytes):
        calls.append((url, timeout, max_bytes))
        return payloads[url]

    result = resolve_cell(COORDINATE, f"{BASE_URL}/.well-known/organa.json", fetcher=fetch)

    assert result["ok"] is True
    assert result["status"] == "resolved-integrity-valid"
    assert result["coordinate"] == COORDINATE
    assert calls[0][0].endswith("/.well-known/organa.json")
    assert f"{BASE_URL}/organa-cell.json" in [item[0] for item in calls]


def test_resolve_cell_rejects_unsupported_coordinate_without_fetching():
    called = False

    def fetch(*args, **kwargs):
        nonlocal called
        called = True

    result = resolve_cell("999.bitmap", "https://resolver.example/organa.json", fetcher=fetch)

    assert result["ok"] is False
    assert result["errors"][0]["code"] == "unsupported-coordinate"
    assert called is False


@pytest.mark.parametrize("url", ["http://resolver.example/organa.json", "file:///etc/passwd"])
def test_resolve_cell_rejects_non_https_url(url):
    result = resolve_cell(COORDINATE, url, fetcher=lambda *args, **kwargs: b"{}")

    assert result["ok"] is False
    assert result["errors"][0]["code"] == "non-https-url"


def test_resolve_cell_rejects_non_https_manifest_url_before_fetching_it():
    discovery = {
        "coordinate": COORDINATE,
        "current_manifest": {"url": "http://internal.test/organa-cell.json", "sha256": "sha256:" + "0" * 64},
    }
    calls = []

    def fetch(url, *, timeout, max_bytes):
        calls.append(url)
        return json.dumps(discovery).encode("utf-8")

    result = resolve_cell(COORDINATE, "https://resolver.example/organa.json", fetcher=fetch)

    assert result["ok"] is False
    assert result["errors"][0]["code"] == "non-https-url"
    assert calls == ["https://resolver.example/organa.json"]


def test_resolve_cell_enforces_size_for_injected_fetcher():
    result = resolve_cell(
        COORDINATE,
        "https://resolver.example/organa.json",
        fetcher=lambda **kwargs: b"x" * 11,
        max_bytes=10,
    )

    assert result["ok"] is False
    assert result["errors"][0]["code"] == "oversized-response"


def test_resolve_cell_fails_closed_for_malformed_json_and_fetch_errors():
    malformed = resolve_cell(COORDINATE, "https://resolver.example/organa.json", fetcher=lambda **kwargs: b"{")

    def unavailable(url, *, timeout, max_bytes):
        raise FetchError("verifier-unavailable", "network unavailable")

    unavailable_result = resolve_cell(COORDINATE, "https://resolver.example/organa.json", fetcher=unavailable)

    assert malformed["ok"] is False
    assert malformed["errors"][0]["code"] == "malformed-json"
    assert unavailable_result["ok"] is False
    assert unavailable_result["errors"][0]["code"] == "verifier-unavailable"


def test_verify_controller_claim_passes_exact_values_to_verifier():
    seen = {}

    def verifier(claim):
        seen.update(claim)
        return {**claim, "signature_valid": True, "signature_verification": "test-verifier"}

    result = verify_controller_claim(
        signing_address="bc1pexact",
        message="exact UTF-8 message\n",
        signature="exact-signature",
        verifier=verifier,
    )

    assert seen == {
        "signing_address": "bc1pexact",
        "message": "exact UTF-8 message\n",
        "signature": "exact-signature",
    }
    assert result["ok"] is True
    assert result["status"] == "cryptographically-valid"
    assert result["cryptographic_valid"] is True
    assert result["business_content_verified"] is False
    assert result["hashes"]["message_sha256"].startswith("sha256:")


def test_verify_controller_claim_fails_closed_when_invalid_or_unavailable():
    invalid = verify_controller_claim("a", "m", "s", verifier=lambda claim: {**claim, "signature_valid": False, "verification_error": "bad signature"})

    def broken(claim):
        raise RuntimeError("node missing")

    unavailable = verify_controller_claim("a", "m", "s", verifier=broken)

    assert invalid["ok"] is False
    assert invalid["status"] == "cryptographically-invalid"
    assert invalid["errors"][0]["code"] == "invalid-signature"
    assert unavailable["ok"] is False
    assert unavailable["errors"][0]["code"] == "verifier-unavailable"


def test_default_fetcher_blocks_private_and_local_addresses(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))])

    with pytest.raises(FetchError) as exc:
        default_https_fetch("https://example.test/data", timeout=1, max_bytes=100)

    assert exc.value.code == "unsafe-address"


def test_default_fetcher_rejects_non_https_redirect(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])

    class Opener:
        def open(self, request, timeout):
            raise HTTPError(request.full_url, 302, "Found", {"Location": "http://evil.example/data"}, None)

    with pytest.raises(FetchError) as exc:
        default_https_fetch("https://example.test/data", timeout=1, max_bytes=100, opener=Opener())

    assert exc.value.code == "unsafe-redirect"


def test_default_fetcher_rejects_redirect_to_private_address(monkeypatch):
    def addresses(host, *args, **kwargs):
        ip = "93.184.216.34" if host == "example.test" else "10.0.0.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]

    monkeypatch.setattr(socket, "getaddrinfo", addresses)

    class Opener:
        def open(self, request, timeout):
            raise HTTPError(request.full_url, 302, "Found", {"Location": "https://internal.test/data"}, None)

    with pytest.raises(FetchError) as exc:
        default_https_fetch("https://example.test/data", timeout=1, max_bytes=100, opener=Opener())

    assert exc.value.code == "unsafe-address"


def test_default_fetcher_retries_one_transient_network_failure(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])
    attempts = []

    class Response:
        headers = {"Content-Length": "2"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, size):
            return b"{}"

    class Opener:
        def open(self, request, timeout):
            attempts.append(request.full_url)
            if len(attempts) == 1:
                raise URLError("transient TLS EOF")
            return Response()

    data = default_https_fetch("https://example.test/data", timeout=1, max_bytes=100, opener=Opener())

    assert data == b"{}"
    assert len(attempts) == 2


def test_default_fetcher_enforces_download_size(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])

    class Response:
        headers = {"Content-Length": "101"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, size):
            return b"x" * 101

    class Opener:
        def open(self, request, timeout):
            return Response()

    with pytest.raises(FetchError) as exc:
        default_https_fetch("https://example.test/data", timeout=1, max_bytes=100, opener=Opener())

    assert exc.value.code == "oversized-response"
