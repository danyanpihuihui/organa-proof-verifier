from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, Mapping, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .cell_resolution import verify_cell_resolution_package
from .claims import verify_claim_signature

SUPPORTED_COORDINATE = "7187.bitmap"
DEFAULT_TIMEOUT = 15.0
DEFAULT_MAX_BYTES = 1_048_576
MAX_REDIRECTS = 3
_TRUTH_WARNING = "Integrity and cryptographic checks do not establish the truth of business content."


class FetchError(Exception):
    """A fail-closed error raised by the bounded HTTPS fetcher."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _error(code: str, message: str) -> Dict[str, str]:
    return {"code": code, "message": message}


def _response(ok: bool, status: str, *, errors=None, warnings=None, hashes=None, **extra) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ok": ok,
        "status": status,
        "errors": list(errors or []),
        "warnings": list(warnings if warnings is not None else ([] if ok and status == "healthy" else [_TRUTH_WARNING])),
        "hashes": dict(hashes or {}),
    }
    result.update(extra)
    return result


def health_response() -> Dict[str, Any]:
    return _response(True, "healthy", service="organa-proof-verifier")


def _safe_relative_path(value: Any) -> Optional[PurePosixPath]:
    if not isinstance(value, str) or not value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or "." in path.parts or ".." in path.parts:
        return None
    return path


def _json_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        json.loads(value.decode("utf-8"))
        return value
    if isinstance(value, str):
        json.loads(value)
        return value.encode("utf-8")
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _verification_response(verification: Mapping[str, Any], source_type: str) -> Dict[str, Any]:
    ok = verification.get("ok") is True
    error_items = []
    for field in ("schema_errors", "missing_resources", "changed_resources", "unsafe_resources", "cross_reference_errors"):
        for value in verification.get(field, []) or []:
            error_items.append(_error(field.replace("_", "-"), str(value)))
    hashes = {}
    if verification.get("cell_sha256"):
        hashes["cell_manifest"] = verification["cell_sha256"]
    return _response(
        ok,
        "integrity-valid" if ok else "integrity-invalid",
        errors=error_items,
        warnings=[_TRUTH_WARNING],
        hashes=hashes,
        integrity_valid=ok,
        cryptographic_valid=None,
        business_content_verified=False,
        source_type=source_type,
        verification=dict(verification),
    )


def verify_package(package: Any) -> Dict[str, Any]:
    """Verify a local package directory or an in-memory ``{"files": ...}`` package."""
    if isinstance(package, (str, Path)):
        path = Path(package).expanduser()
        if not path.is_dir() or path.is_symlink():
            return _response(False, "invalid-input", errors=[_error("unsafe-local-package", "package must be a non-symlink directory")])
        root = path.resolve()
        for required in ("organa-cell.json", ".well-known/organa.json", "signature-request.json"):
            candidate = path / required
            if candidate.is_symlink():
                return _response(False, "invalid-input", errors=[_error("unsafe-local-package", f"required file must not be a symlink: {required}")])
            if candidate.exists():
                try:
                    candidate.resolve().relative_to(root)
                except ValueError:
                    return _response(False, "invalid-input", errors=[_error("unsafe-local-package", f"required file escapes package: {required}")])
        return _verification_response(verify_cell_resolution_package(path), "local-directory")

    if not isinstance(package, Mapping) or not isinstance(package.get("files"), Mapping):
        return _response(False, "invalid-input", errors=[_error("malformed-package", "structured package must contain a files object")])

    try:
        with tempfile.TemporaryDirectory(prefix="organa-proof-") as temp:
            root = Path(temp)
            for name, value in package["files"].items():
                relative = _safe_relative_path(name)
                if relative is None:
                    return _response(False, "invalid-input", errors=[_error("unsafe-package-path", "structured package contains an unsafe path")])
                data = _json_bytes(value)
                target = root.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            return _verification_response(verify_cell_resolution_package(root), "structured-json")
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return _response(False, "invalid-input", errors=[_error("malformed-json", str(exc))])


def _validate_remote_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise FetchError("invalid-url", str(exc))
    if parsed.scheme != "https":
        raise FetchError("non-https-url", "only HTTPS URLs are allowed")
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise FetchError("invalid-url", "URL must have a host and no credentials or fragment")
    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost"):
        raise FetchError("unsafe-address", "localhost is not allowed")
    try:
        addresses = socket.getaddrinfo(host, port or 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise FetchError("verifier-unavailable", "DNS resolution failed: %s" % exc)
    if not addresses:
        raise FetchError("verifier-unavailable", "DNS resolution returned no addresses")
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0].split("%", 1)[0])
        if not ip.is_global:
            raise FetchError("unsafe-address", "private, local, reserved, and link-local addresses are blocked")
    return url


def default_https_fetch(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    opener=None,
) -> bytes:
    """Fetch HTTPS bytes with DNS/IP validation, manual safe redirects, timeout, and size bounds."""
    if timeout <= 0 or max_bytes <= 0:
        raise FetchError("invalid-fetch-limits", "timeout and max_bytes must be positive")
    active_opener = opener or build_opener(_NoRedirect())
    current = url
    transient_failures = 0
    for redirect_count in range(MAX_REDIRECTS + 1):
        _validate_remote_url(current)
        request = Request(current, headers={"Accept": "application/json", "User-Agent": "Organa-Proof-Verifier/0.1"})
        try:
            response = active_opener.open(request, timeout=timeout)
        except HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308):
                location = exc.headers.get("Location") if exc.headers else None
                if not location:
                    raise FetchError("unsafe-redirect", "redirect omitted Location")
                destination = urljoin(current, location)
                try:
                    _validate_remote_url(destination)
                except FetchError as redirect_error:
                    if redirect_error.code == "non-https-url":
                        raise FetchError("unsafe-redirect", "redirect target must use HTTPS")
                    raise
                if redirect_count >= MAX_REDIRECTS:
                    raise FetchError("too-many-redirects", "redirect limit exceeded")
                current = destination
                continue
            raise FetchError("http-error", "HTTP request failed with status %s" % exc.code)
        except (URLError, OSError, TimeoutError) as exc:
            if transient_failures < 1:
                transient_failures += 1
                continue
            raise FetchError("verifier-unavailable", "HTTPS request failed after retry: %s" % exc)

        with response:
            content_length = response.headers.get("Content-Length") if response.headers else None
            if content_length:
                try:
                    if int(content_length) > max_bytes:
                        raise FetchError("oversized-response", "response exceeds maximum size")
                except ValueError:
                    raise FetchError("invalid-response", "invalid Content-Length")
            data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise FetchError("oversized-response", "response exceeds maximum size")
            return data
    raise FetchError("too-many-redirects", "redirect limit exceeded")


def _fetch_json(fetcher: Callable[..., bytes], url: str, timeout: float, max_bytes: int) -> tuple[Dict[str, Any], bytes]:
    _validate_remote_url(url)
    data = fetcher(url=url, timeout=timeout, max_bytes=max_bytes)
    if not isinstance(data, bytes):
        raise FetchError("invalid-response", "fetcher must return bytes")
    if len(data) > max_bytes:
        raise FetchError("oversized-response", "response exceeds maximum size")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FetchError("malformed-json", str(exc))
    if not isinstance(value, dict):
        raise FetchError("malformed-json", "JSON document must be an object")
    return value, data


def resolve_cell(
    coordinate: str,
    resolver_url: str,
    *,
    fetcher: Callable[..., bytes] = default_https_fetch,
    claim_verifier: Callable[[Dict[str, Any]], Dict[str, Any]] = verify_claim_signature,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> Dict[str, Any]:
    """Resolve and integrity-check the supported Organa Cell through injected byte fetching."""
    if coordinate != SUPPORTED_COORDINATE:
        return _response(False, "unsupported-coordinate", errors=[_error("unsupported-coordinate", "only 7187.bitmap is supported")])
    if urlparse(resolver_url).scheme != "https":
        return _response(False, "invalid-input", errors=[_error("non-https-url", "resolver URL must use HTTPS")])

    try:
        discovery, discovery_bytes = _fetch_json(fetcher, resolver_url, timeout, max_bytes)
        if discovery.get("coordinate") != coordinate:
            raise FetchError("coordinate-mismatch", "discovery coordinate does not match the request")
        current = discovery.get("current_manifest")
        if not isinstance(current, dict) or not isinstance(current.get("url"), str):
            raise FetchError("malformed-json", "discovery is missing current_manifest.url")
        manifest_url = current["url"]
        manifest, manifest_bytes = _fetch_json(fetcher, manifest_url, timeout, max_bytes)
        if current.get("sha256") != _sha256(manifest_bytes):
            raise FetchError("integrity-mismatch", "manifest hash does not match discovery")
        if manifest.get("coordinate") != coordinate:
            raise FetchError("coordinate-mismatch", "manifest coordinate does not match the request")

        files: Dict[str, Any] = {
            ".well-known/organa.json": discovery_bytes,
            "organa-cell.json": manifest_bytes,
        }
        for resource in manifest.get("resources", []):
            if not isinstance(resource, dict) or not isinstance(resource.get("path"), str) or not isinstance(resource.get("url"), str):
                raise FetchError("malformed-json", "manifest contains a malformed resource")
            files[resource["path"]] = _fetch_json(fetcher, resource["url"], timeout, max_bytes)[1]
        claim = discovery.get("controller_claim") or {}
        request_url = claim.get("signature_request_url")
        if not isinstance(request_url, str):
            raise FetchError("malformed-json", "discovery is missing signature_request_url")
        request_bytes = _fetch_json(fetcher, request_url, timeout, max_bytes)[1]
        if claim.get("signature_request_sha256") != _sha256(request_bytes):
            raise FetchError("integrity-mismatch", "signature request hash does not match discovery")
        files["signature-request.json"] = request_bytes

        cryptographic_valid = None
        activation_status = discovery.get("activation_status")
        if claim.get("status") == "signed" or activation_status == "active":
            claim_url = claim.get("signed_claim_url")
            if not isinstance(claim_url, str):
                raise FetchError("malformed-json", "signed discovery is missing signed_claim_url")
            signed_claim, signed_claim_bytes = _fetch_json(fetcher, claim_url, timeout, max_bytes)
            if claim.get("signed_claim_sha256") != _sha256(signed_claim_bytes):
                raise FetchError("integrity-mismatch", "signed controller claim hash does not match discovery")
            request_document = json.loads(request_bytes.decode("utf-8"))
            message = request_document.get("message")
            if not isinstance(message, str):
                raise FetchError("malformed-json", "signature request message must be a string")
            manifest_hash = _sha256(manifest_bytes)
            controller = manifest.get("controller") if isinstance(manifest.get("controller"), dict) else {}
            if (
                signed_claim.get("coordinate") != coordinate
                or signed_claim.get("controller_address") != controller.get("address")
                or signed_claim.get("manifest_url") != manifest_url
                or signed_claim.get("manifest_sha256") != manifest_hash
                or signed_claim.get("message") != message
                or signed_claim.get("message_sha256") != _sha256(str(message).encode("utf-8"))
                or signed_claim.get("signature_method") != "BIP-322-simple-message-signature"
            ):
                raise FetchError("integrity-mismatch", "signed controller claim linkage is invalid")
            signature_result = claim_verifier({
                "signing_address": signed_claim.get("controller_address"),
                "message": signed_claim.get("message"),
                "signature": signed_claim.get("signature"),
            })
            cryptographic_valid = signature_result.get("signature_valid") is True
            if not cryptographic_valid:
                raise FetchError("invalid-signature", "signed controller claim failed BIP-322 verification")

        verified = verify_package({"files": files})
        verified["coordinate"] = coordinate
        verified["activation_status"] = activation_status
        verified["cryptographic_valid"] = cryptographic_valid
        verified["snapshot_controller_signature_status"] = (
            manifest.get("controller", {}).get("signature_status")
            if isinstance(manifest.get("controller"), dict)
            else None
        )
        verified.pop("controller_signature_status", None)
        verified["controller_authentication_status"] = claim.get("status")
        verified["state_semantics"] = discovery.get("state_semantics") or {
            "canonical_state_source": ".well-known/organa.json",
            "immutable_candidate_manifest": True,
        }
        verified["hashes"].update({"discovery": _sha256(discovery_bytes), "cell_manifest": _sha256(manifest_bytes)})
        if verified["ok"]:
            verified["status"] = (
                "resolved-live-cryptographically-valid"
                if activation_status == "active" and cryptographic_valid is True
                else "resolved-integrity-valid"
            )
        return verified
    except FetchError as exc:
        return _response(False, "resolution-failed", errors=[_error(exc.code, exc.message)], coordinate=coordinate, integrity_valid=False, business_content_verified=False)
    except Exception as exc:
        return _response(False, "resolution-failed", errors=[_error("verifier-unavailable", str(exc))], coordinate=coordinate, integrity_valid=False, business_content_verified=False)


def verify_controller_claim(
    signing_address: str,
    message: str,
    signature: str,
    *,
    verifier: Callable[[Dict[str, Any]], Dict[str, Any]] = verify_claim_signature,
) -> Dict[str, Any]:
    """Verify exactly the supplied address, UTF-8 message, and signature."""
    claim = {"signing_address": signing_address, "message": message, "signature": signature}
    try:
        verified = verifier(claim)
    except Exception as exc:
        return _response(False, "verifier-unavailable", errors=[_error("verifier-unavailable", str(exc))], cryptographic_valid=False, business_content_verified=False)
    valid = isinstance(verified, Mapping) and verified.get("signature_valid") is True
    unavailable = isinstance(verified, Mapping) and verified.get("signature_verification") == "verifier-unavailable"
    if unavailable:
        return _response(
            False,
            "verifier-unavailable",
            errors=[_error("verifier-unavailable", str(verified.get("verification_error", "signature verifier unavailable")))],
            cryptographic_valid=False,
            integrity_valid=None,
            business_content_verified=False,
            verification=dict(verified),
        )
    errors = [] if valid else [_error("invalid-signature", str(verified.get("verification_error", "signature verification failed")))]
    return _response(
        valid,
        "cryptographically-valid" if valid else "cryptographically-invalid",
        errors=errors,
        warnings=[_TRUTH_WARNING],
        hashes={"message_sha256": _sha256(message.encode("utf-8"))},
        cryptographic_valid=valid,
        integrity_valid=None,
        business_content_verified=False,
        verification=dict(verified),
    )
