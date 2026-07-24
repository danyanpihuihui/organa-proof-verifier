from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, Optional, Union
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from .cell_resolution import verify_cell_resolution_package
from .claims import verify_claim_signature

_REQUIRED_FILES = (
    "organa-cell.json",
    "signature-request.json",
    "controller-claim.json",
    ".well-known/organa.json",
)
_HASH_PREFIX = "sha256:"


def _sha256_bytes(value: bytes) -> str:
    return _HASH_PREFIX + hashlib.sha256(value).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _safe_relative_path(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        return None
    return path.as_posix()


def _download_url_bytes(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": "bitmap-memory-portal-snapshot-verifier/0.1"})
    try:
        with urlopen(request, timeout=20) as response:
            return response.read()
    except Exception as urlopen_error:
        try:
            completed = subprocess.run(
                ["curl", "-fsSL", "--retry", "2", "--connect-timeout", "15", "--max-time", "60", url],
                capture_output=True,
                check=False,
                timeout=75,
            )
        except Exception:
            raise urlopen_error
        if completed.returncode == 0:
            return completed.stdout
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise OSError(detail or str(urlopen_error)) from urlopen_error


def _normalize_https_base_url(value: str) -> str:
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.params
    ):
        raise ValueError("snapshot URL must be an HTTPS base URL without credentials, query, or fragment")
    return value.rstrip("/")


def _read_local_files(root: Path, resource_paths: Iterable[str], errors: list[str]) -> Dict[str, bytes]:
    files: Dict[str, bytes] = {}
    resolved_root = root.resolve()
    for relative in dict.fromkeys((*_REQUIRED_FILES, *resource_paths)):
        candidate = root.joinpath(*PurePosixPath(relative).parts)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(resolved_root)
        except (OSError, ValueError):
            errors.append(f"missing or unsafe file: {relative}")
            continue
        if candidate.is_symlink() or not resolved.is_file():
            errors.append(f"missing or unsafe file: {relative}")
            continue
        files[relative] = resolved.read_bytes()
    return files


def _download_files(base_url: str, resource_paths: Iterable[str], errors: list[str]) -> Dict[str, bytes]:
    files: Dict[str, bytes] = {}
    for relative in dict.fromkeys((*_REQUIRED_FILES, *resource_paths)):
        safe = _safe_relative_path(relative)
        if safe is None:
            errors.append(f"unsafe download path: {relative}")
            continue
        url = base_url + "/" + "/".join(quote(part, safe="") for part in PurePosixPath(safe).parts)
        try:
            files[safe] = _download_url_bytes(url)
        except Exception as exc:
            errors.append(f"unable to download {safe}: {exc}")
    return files


def _load_json(files: Dict[str, bytes], relative: str, errors: list[str]) -> Any:
    raw = files.get(relative)
    if raw is None:
        return None
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        errors.append(f"malformed JSON: {relative}: {exc}")
        return None
    if raw != _canonical_json_bytes(value):
        errors.append(f"non-canonical or byte-tampered JSON: {relative}")
    return value


def _append_once(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def verify_signed_organa_snapshot(
    source: Union[str, Path],
    *,
    trusted_manifest_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify a local or HTTPS Organa v0.1 signed snapshot, failing closed.

    ``trusted_manifest_hash`` is the external trust anchor when one is known. All
    other files are linked from the manifest, discovery document, and signed
    controller claim, and JSON bytes must use the snapshot's canonical encoding.
    """
    errors: list[str] = []
    unsafe_paths: list[str] = []
    source_text = str(source)
    is_remote = isinstance(source, str) and urlparse(source).scheme != ""

    if is_remote:
        try:
            base_url = _normalize_https_base_url(source_text)
        except ValueError as exc:
            return {"ok": False, "source": source_text, "errors": [str(exc)], "unsafe_paths": []}
        try:
            manifest_bytes = _download_url_bytes(base_url + "/organa-cell.json")
        except Exception as exc:
            return {"ok": False, "source": source_text, "errors": [f"unable to download organa-cell.json: {exc}"], "unsafe_paths": []}
        initial_files = {"organa-cell.json": manifest_bytes}
    else:
        root = Path(source).expanduser()
        base_url = None
        initial_files = _read_local_files(root, (), errors)

    manifest = _load_json(initial_files, "organa-cell.json", errors)
    resources = manifest.get("resources") if isinstance(manifest, dict) else None
    if not isinstance(resources, list) or not resources:
        errors.append("manifest resources must be a non-empty array")
        resources = []

    resource_paths: list[str] = []
    for resource in resources:
        relative = resource.get("path") if isinstance(resource, dict) else None
        safe = _safe_relative_path(relative)
        if safe is None:
            unsafe_paths.append(str(relative))
            continue
        if safe in resource_paths:
            errors.append(f"duplicate manifest resource path: {safe}")
            continue
        resource_paths.append(safe)

    if is_remote:
        files = dict(initial_files)
        if not unsafe_paths:
            files.update(_download_files(base_url, resource_paths, errors))
    else:
        files = _read_local_files(root, resource_paths, errors)
        if "organa-cell.json" not in files:
            files.update(initial_files)

    documents = {name: _load_json(files, name, errors) for name in (*_REQUIRED_FILES, *resource_paths)}
    manifest = documents["organa-cell.json"]
    request = documents["signature-request.json"]
    claim = documents["controller-claim.json"]
    discovery = documents[".well-known/organa.json"]
    manifest_hash = _sha256_bytes(files.get("organa-cell.json", b""))

    if trusted_manifest_hash is not None and manifest_hash != trusted_manifest_hash:
        errors.append("manifest bytes do not match trusted manifest hash")

    if isinstance(manifest, dict):
        public_base_url = manifest.get("public_base_url")
        expected_manifest_url = f"{public_base_url}/organa-cell.json" if isinstance(public_base_url, str) else None
        controller = manifest.get("controller") if isinstance(manifest.get("controller"), dict) else {}
        for resource in resources:
            if not isinstance(resource, dict):
                errors.append("malformed manifest resource entry")
                continue
            relative = _safe_relative_path(resource.get("path"))
            if relative is None:
                continue
            raw = files.get(relative)
            if raw is None or _sha256_bytes(raw) != resource.get("sha256"):
                errors.append(f"resource hash mismatch: {relative}")
            if resource.get("url") != f"{public_base_url}/{relative}":
                errors.append(f"resource URL mismatch: {relative}")
    else:
        errors.append("manifest must be a JSON object")
        public_base_url = None
        expected_manifest_url = None
        controller = {}

    if isinstance(discovery, dict):
        current = discovery.get("current_manifest") if isinstance(discovery.get("current_manifest"), dict) else {}
        discovery_claim = discovery.get("controller_claim") if isinstance(discovery.get("controller_claim"), dict) else {}
        if current.get("sha256") != manifest_hash or current.get("url") != expected_manifest_url:
            errors.append("discovery manifest linkage mismatch")
        if isinstance(manifest, dict) and (
            discovery.get("coordinate") != manifest.get("coordinate")
            or current.get("version") != manifest.get("version")
        ):
            errors.append("discovery identity linkage mismatch")
        request_bytes = files.get("signature-request.json")
        claim_bytes = files.get("controller-claim.json")
        if request_bytes is None or discovery_claim.get("signature_request_sha256") != _sha256_bytes(request_bytes):
            errors.append("discovery signature request hash mismatch")
        if claim_bytes is None or discovery_claim.get("signed_claim_sha256") != _sha256_bytes(claim_bytes):
            errors.append("discovery signed claim hash mismatch")
        if discovery_claim.get("signed_claim_url") != f"{public_base_url}/controller-claim.json":
            errors.append("discovery signed claim URL mismatch")
    else:
        errors.append("discovery document must be a JSON object")

    message = request.get("message") if isinstance(request, dict) else None
    if isinstance(request, dict):
        if not isinstance(message, str) or request.get("message_sha256") != _sha256_bytes(message.encode("utf-8")):
            errors.append("signature request message hash mismatch")
        if (
            request.get("coordinate") != (manifest or {}).get("coordinate")
            or request.get("controller_address") != controller.get("address")
            or request.get("signature_method") != "BIP-322-simple-message-signature"
        ):
            errors.append("signature request linkage mismatch")
        expected_lines = (
            f"Coordinate: {(manifest or {}).get('coordinate')}",
            f"Controller address: {controller.get('address')}",
            f"Cell manifest: {expected_manifest_url}",
            f"Cell manifest SHA-256: {manifest_hash}",
            f"Version: {(manifest or {}).get('version')}",
        )
        if not isinstance(message, str) or any(line not in message.splitlines() for line in expected_lines):
            errors.append("signature request message does not bind the manifest")
    else:
        errors.append("signature request must be a JSON object")

    signature_valid = False
    if isinstance(claim, dict):
        if (
            claim.get("message") != message
            or claim.get("message_sha256") != (request or {}).get("message_sha256")
            or claim.get("coordinate") != (manifest or {}).get("coordinate")
            or claim.get("controller_address") != controller.get("address")
            or claim.get("manifest_url") != expected_manifest_url
            or claim.get("manifest_sha256") != manifest_hash
            or claim.get("signature_method") != "BIP-322-simple-message-signature"
        ):
            errors.append("signed controller claim linkage mismatch")
        verification = verify_claim_signature({
            "signing_address": claim.get("controller_address"),
            "message": claim.get("message"),
            "signature": claim.get("signature"),
        })
        signature_valid = verification.get("signature_valid") is True
        if not signature_valid:
            errors.append("BIP-322 controller signature is invalid")
    else:
        errors.append("controller claim must be a JSON object")

    if not unsafe_paths and all(name in files for name in _REQUIRED_FILES):
        with tempfile.TemporaryDirectory(prefix="organa-snapshot-") as temp_dir:
            temp_root = Path(temp_dir)
            for relative, raw in files.items():
                safe = _safe_relative_path(relative)
                if safe is None:
                    continue
                destination = temp_root.joinpath(*PurePosixPath(safe).parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(raw)
            resolver_result = verify_cell_resolution_package(temp_root)
        if not resolver_result.get("ok"):
            errors.append("cell resolution verification failed")
            for category in ("schema_errors", "missing_resources", "changed_resources", "unsafe_resources", "cross_reference_errors"):
                for detail in resolver_result.get(category, []):
                    _append_once(errors, f"resolver {category}: {detail}")

    errors = list(dict.fromkeys(errors))
    unsafe_paths = list(dict.fromkeys(unsafe_paths))
    return {
        "ok": not errors and not unsafe_paths and signature_valid,
        "source": source_text.rstrip("/") if is_remote else source_text,
        "manifest_sha256": manifest_hash,
        "coordinate": manifest.get("coordinate") if isinstance(manifest, dict) else None,
        "version": manifest.get("version") if isinstance(manifest, dict) else None,
        "signature_valid": signature_valid,
        "unsafe_paths": unsafe_paths,
        "errors": errors,
    }
