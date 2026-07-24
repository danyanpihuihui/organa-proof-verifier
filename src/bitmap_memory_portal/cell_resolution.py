from __future__ import annotations

import hashlib
import json
import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List
from urllib.parse import urlparse

from jsonschema import Draft202012Validator

_COORDINATE_RE = re.compile(r"^[0-9]+\.bitmap$")
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_LIFECYCLE = ["live", "simulation", "pending", "deprecated"]
_EXPECTED_HASHED_RESOURCES = {
    "agent-registry.json",
    "service-registry.json",
    "proof-index.json",
    "disclosure-policy.json",
    "schemas/organa-cell-resolution-v0.1.schema.json",
    "schemas/organa-registry-v0.1.schema.json",
}


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _write_json(path: Path, value: Dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return _sha256_bytes(path.read_bytes())


def _reject_control(value: str, field: str) -> None:
    if not isinstance(value, str) or not value or _CONTROL_RE.search(value):
        raise ValueError(f"unsafe or empty {field}")


def _normalize_base_url(base_url: str) -> str:
    _reject_control(base_url, "base_url")
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("base_url must be an HTTPS origin or path without credentials")
    if parsed.query or parsed.fragment or parsed.params:
        raise ValueError("base_url must not contain params, query, or fragment")
    return base_url.rstrip("/")


def _validate_inputs(coordinate: str, base_url: str, controller_address: str, version: str) -> str:
    for value, field in (
        (coordinate, "coordinate"),
        (controller_address, "controller_address"),
        (version, "version"),
    ):
        _reject_control(value, field)
    if not _COORDINATE_RE.fullmatch(coordinate):
        raise ValueError("coordinate must match <number>.bitmap")
    if not _VERSION_RE.fullmatch(version):
        raise ValueError("version must be semantic version syntax")
    if not (14 <= len(controller_address) <= 90) or not controller_address.isascii() or any(ch.isspace() for ch in controller_address):
        raise ValueError("controller_address has invalid syntax")
    return _normalize_base_url(base_url)


def _resource_schema() -> Dict[str, Any]:
    return {
        "type": "object",
        "required": ["path", "url", "sha256"],
        "properties": {
            "path": {"type": "string", "minLength": 1},
            "url": {"type": "string", "format": "uri", "pattern": "^https://"},
            "sha256": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
        },
        "additionalProperties": False,
    }


def _registry_schema(base_url: str) -> Dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{base_url}/schemas/organa-registry-v0.1.schema.json",
        "title": "Organa Registry v0.1",
        "type": "object",
        "required": ["schema_version", "coordinate", "registry_type", "entries"],
        "properties": {
            "schema_version": {"const": "organa-registry-v0.1"},
            "coordinate": {"type": "string", "pattern": "^[0-9]+\\.bitmap$"},
            "registry_type": {"enum": ["agents", "services", "proofs"]},
            "entries": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "required": ["id", "lifecycle_status"],
                    "properties": {
                        "id": {"type": "string", "minLength": 1},
                        "lifecycle_status": {"enum": _LIFECYCLE},
                    },
                    "additionalProperties": True,
                },
            },
        },
        "additionalProperties": False,
    }


def _cell_schema(base_url: str) -> Dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{base_url}/schemas/organa-cell-resolution-v0.1.schema.json",
        "title": "Organa Cell Resolution Manifest v0.1",
        "type": "object",
        "required": [
            "schema_version", "coordinate", "cell_type", "version", "created_at_utc",
            "lifecycle_status", "controller", "public_base_url", "resources", "agents", "services",
        ],
        "properties": {
            "schema_version": {"const": "organa-cell-resolution-v0.1"},
            "coordinate": {"type": "string", "pattern": "^[0-9]+\\.bitmap$"},
            "cell_type": {"const": "organa-cell"},
            "title": {"type": "string", "minLength": 1},
            "version": {"type": "string", "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+"},
            "created_at_utc": {"type": "string", "format": "date-time"},
            "lifecycle_status": {"enum": _LIFECYCLE},
            "activation_status": {"enum": ["awaiting-controller-signature", "active", "deprecated"]},
            "state_semantics": {
                "type": "object",
                "required": ["lifecycle_status", "activation_status", "controller_signature_status", "canonical_state_source"],
                "properties": {
                    "lifecycle_status": {"const": "declared object lifecycle"},
                    "activation_status": {"const": "canonical publication activation"},
                    "controller_signature_status": {"const": "controller authentication state"},
                    "canonical_state_source": {"const": ".well-known/organa.json"},
                },
                "additionalProperties": False,
            },
            "status_note": {"type": "string"},
            "previous_manifest": {
                "type": "object",
                "required": ["url", "sha256", "version"],
                "properties": {
                    "url": {"type": "string", "pattern": "^https://"},
                    "sha256": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                    "version": {"type": "string", "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+"},
                },
                "additionalProperties": False,
            },
            "controller": {
                "type": "object",
                "required": ["address", "claim_type", "signature_status", "signature_request_url"],
                "properties": {
                    "address": {"type": "string", "minLength": 14, "maxLength": 90},
                    "claim_type": {"const": "bitmap-controller-wallet-claim"},
                    "signature_status": {"enum": ["pending-user-signature", "signed", "invalid", "deprecated"]},
                    "signature_request_url": {"type": "string", "pattern": "^https://"},
                },
                "additionalProperties": False,
            },
            "public_base_url": {"type": "string", "pattern": "^https://"},
            "resources": {
                "type": "array", "minItems": len(_EXPECTED_HASHED_RESOURCES),
                "items": _resource_schema(),
            },
            "agents": {"type": "array", "minItems": 1},
            "services": {"type": "array", "minItems": 1},
            "disclosure_policy_url": {"type": "string", "pattern": "^https://"},
            "proof_index_url": {"type": "string", "pattern": "^https://"},
            "machine_instructions": {"type": "array", "items": {"type": "string"}},
        },
        "additionalProperties": False,
    }


def _safe_package_path(root: Path, rel: Any) -> Path | None:
    if not isinstance(rel, str) or not rel:
        return None
    pure = PurePosixPath(rel)
    if pure.is_absolute() or ".." in pure.parts or "." in pure.parts:
        return None
    candidate = (root / Path(*pure.parts)).resolve()
    resolved_root = root.resolve()
    try:
        candidate.relative_to(resolved_root)
    except ValueError:
        return None
    if candidate.exists() and candidate.is_symlink():
        return None
    return candidate


def _schema_errors(instance: Any, schema: Dict[str, Any]) -> List[str]:
    return [error.message for error in Draft202012Validator(schema).iter_errors(instance)]


def build_cell_resolution_package(
    out_dir: Path,
    coordinate: str,
    base_url: str,
    controller_address: str,
    version: str = "0.1.0",
) -> Dict[str, Any]:
    base_url = _validate_inputs(coordinate, base_url, controller_address, version)
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    created_at = now.isoformat()

    agent_entries = [
        {
            "id": "organa-cell-orchestrator",
            "name": "Organa Cell Orchestrator",
            "role": "orchestrator",
            "lifecycle_status": "pending",
            "authority": {"canonical_state": "organa-cell-manifest", "external_adapter_mutation": False},
            "capabilities": ["task-routing", "proof-indexing", "disclosure-enforcement"],
        },
        {
            "id": "organa-proof-verifier-agent",
            "name": "Organa Proof Verifier",
            "role": "verifier",
            "lifecycle_status": "pending",
            "capabilities": ["schema-validation", "sha256-verification", "registry-cross-checking"],
        },
    ]
    service_entries = [{
        "id": "organa-proof-verifier",
        "name": "Organa Proof Verifier",
        "service_type": "artifact-verification",
        "lifecycle_status": "pending",
        "endpoint_status": "not-deployed",
        "openapi_url": f"{base_url}/openapi.json",
        "mcp_url": f"{base_url}/mcp",
        "human_url": f"{base_url}/verifier",
        "disclosure_level": "L2_METADATA_PROOF",
    }]
    proof_entries = [
        {
            "id": "controller-claim", "proof_type": "wallet-signature",
            "lifecycle_status": "pending", "signature_status": "pending-user-signature",
            "request_url": f"{base_url}/signature-request.json",
        },
        {
            "id": "cell-resolution-integrity", "proof_type": "sha256-resource-manifest",
            "lifecycle_status": "pending", "verification_status": "passed-local",
            "verification_url": f"{base_url}/verification-report.json",
        },
    ]
    disclosure = {
        "schema_version": "organa-disclosure-policy-v0.1",
        "coordinate": coordinate,
        "default_public_level": "L2_METADATA_PROOF",
        "levels": {
            "L0_PRIVATE": ["credentials", "raw_strategy", "private_memory", "source_accounts", "candidate_pools"],
            "L1_HASH_PROOF": ["private_payload_hash", "timestamp_commitment"],
            "L2_METADATA_PROOF": ["task_type", "version", "input_hash", "output_hash", "verification_status"],
            "L3_SELECTIVE_REVEAL": ["named_verifier", "scoped_redacted_evidence", "audit_log"],
            "L4_PUBLIC_PACKAGE": ["public_manifest", "public_artifacts", "public_verifier_result"],
        },
        "public_package_excludes": ["credentials", "private memory", "raw strategy", "candidate pools", "account data"],
    }
    registries = {
        "agent-registry.json": {"schema_version": "organa-registry-v0.1", "coordinate": coordinate, "registry_type": "agents", "entries": agent_entries},
        "service-registry.json": {"schema_version": "organa-registry-v0.1", "coordinate": coordinate, "registry_type": "services", "entries": service_entries},
        "proof-index.json": {"schema_version": "organa-registry-v0.1", "coordinate": coordinate, "registry_type": "proofs", "entries": proof_entries},
        "disclosure-policy.json": disclosure,
    }
    resource_hashes: Dict[str, str] = {}
    for name, value in registries.items():
        resource_hashes[name] = _write_json(out_dir / name, value)
    resource_hashes.update({
        "schemas/organa-cell-resolution-v0.1.schema.json": _write_json(out_dir / "schemas/organa-cell-resolution-v0.1.schema.json", _cell_schema(base_url)),
        "schemas/organa-registry-v0.1.schema.json": _write_json(out_dir / "schemas/organa-registry-v0.1.schema.json", _registry_schema(base_url)),
    })
    resources = [{"path": path, "url": f"{base_url}/{path}", "sha256": digest} for path, digest in sorted(resource_hashes.items())]
    cell = {
        "schema_version": "organa-cell-resolution-v0.1",
        "coordinate": coordinate,
        "cell_type": "organa-cell",
        "title": f"{coordinate} — Organa Cell",
        "version": version,
        "created_at_utc": created_at,
        "lifecycle_status": "pending",
        "status_note": "Locally verified candidate awaiting public deployment and controller wallet signature.",
        "controller": {
            "address": controller_address,
            "claim_type": "bitmap-controller-wallet-claim",
            "signature_status": "pending-user-signature",
            "signature_request_url": f"{base_url}/signature-request.json",
        },
        "public_base_url": base_url,
        "agents": agent_entries,
        "services": service_entries,
        "resources": resources,
        "disclosure_policy_url": f"{base_url}/disclosure-policy.json",
        "proof_index_url": f"{base_url}/proof-index.json",
        "machine_instructions": [
            "Verify every resource SHA-256 before trusting registry contents.",
            "Treat pending or simulation entries as non-live capabilities.",
            "Do not infer access to L0 private assets from public metadata.",
        ],
    }
    cell_sha = _write_json(out_dir / "organa-cell.json", cell)
    issued_at = now.isoformat()
    expires_at = (now + timedelta(days=7)).isoformat()
    signing_message = (
        "Organa Cell Controller Claim v0.1\n"
        "Domain: organa-cell-controller-claim\n"
        "Bitcoin network: mainnet\n"
        f"Coordinate: {coordinate}\n"
        f"Controller address: {controller_address}\n"
        f"Cell manifest: {base_url}/organa-cell.json\n"
        f"Cell manifest SHA-256: {cell_sha}\n"
        f"Schema version: organa-cell-resolution-v0.1\n"
        f"Version: {version}\n"
        f"Issued at UTC: {issued_at}\n"
        f"Expires at UTC: {expires_at}\n\n"
        "I attest that this wallet controls the publication authority for this Organa Cell manifest. "
        "This signature does not transfer assets, authorize spending, or reveal private Organa data."
    )
    signature_request = {
        "schema_version": "organa-controller-signature-request-v0.1",
        "coordinate": coordinate,
        "controller_address": controller_address,
        "bitcoin_network": "mainnet",
        "status": "awaiting-user-signature",
        "signature_method": "BIP-322-simple-message-signature",
        "message_encoding": "UTF-8",
        "issued_at_utc": issued_at,
        "expires_at_utc": expires_at,
        "message": signing_message,
        "message_sha256": _sha256_bytes(signing_message.encode("utf-8")),
        "signed_claim_output": "controller-claim.json",
    }
    signature_sha = _write_json(out_dir / "signature-request.json", signature_request)
    discovery = {
        "schema_version": "organa-well-known-v0.1",
        "coordinate": coordinate,
        "cell_type": "organa-cell",
        "current_manifest": {"url": f"{base_url}/organa-cell.json", "sha256": cell_sha, "version": version, "lifecycle_status": "pending"},
        "controller_claim": {
            "status": "pending-user-signature",
            "signature_request_url": f"{base_url}/signature-request.json",
            "signature_request_sha256": signature_sha,
        },
        "registries": {
            "agents": f"{base_url}/agent-registry.json",
            "services": f"{base_url}/service-registry.json",
            "proofs": f"{base_url}/proof-index.json",
        },
    }
    discovery_sha = _write_json(out_dir / ".well-known/organa.json", discovery)
    verification = verify_cell_resolution_package(out_dir)
    _write_json(out_dir / "verification-report.json", verification)
    return {
        "out_dir": str(out_dir), "cell_manifest": str(out_dir / "organa-cell.json"),
        "cell_sha256": cell_sha, "well_known_sha256": discovery_sha,
        "signature_request": str(out_dir / "signature-request.json"), "verification": verification,
    }


def verify_cell_resolution_package(out_dir: Path) -> Dict[str, Any]:
    out_dir = Path(out_dir).resolve()
    cell_path = out_dir / "organa-cell.json"
    base_result: Dict[str, Any] = {
        "schema_version": "organa-cell-resolution-verification-v0.1",
        "ok": False,
        "schema_errors": [], "missing_resources": [], "changed_resources": [],
        "unsafe_resources": [], "cross_reference_errors": [],
    }
    if not cell_path.is_file():
        base_result["schema_errors"] = ["missing organa-cell.json"]
        return base_result
    try:
        cell = json.loads(cell_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        base_result["schema_errors"] = [f"invalid organa-cell.json: {exc}"]
        return base_result
    if not isinstance(cell, dict):
        base_result["schema_errors"] = ["organa-cell.json must be an object"]
        return base_result
    base_url = cell.get("public_base_url")
    if isinstance(base_url, str):
        try:
            _normalize_base_url(base_url)
            schema = _cell_schema(base_url.rstrip("/"))
        except ValueError as exc:
            base_result["schema_errors"] = [str(exc)]
            return base_result
    else:
        schema = _cell_schema("https://invalid.example")
    base_result["schema_errors"] = _schema_errors(cell, schema)
    resources = cell.get("resources")
    if not isinstance(resources, list):
        base_result["schema_errors"].append("resources must be an array")
        resources = []
    seen: set[str] = set()
    for item in resources:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            base_result["schema_errors"].append("malformed resource entry")
            continue
        rel = item["path"]
        if rel in seen:
            base_result["schema_errors"].append(f"duplicate resource path: {rel}")
            continue
        seen.add(rel)
        path = _safe_package_path(out_dir, rel)
        if path is None:
            base_result["unsafe_resources"].append(rel)
            continue
        if not path.is_file():
            base_result["missing_resources"].append(rel)
            continue
        actual = _sha256_bytes(path.read_bytes())
        if actual != item.get("sha256"):
            base_result["changed_resources"].append(rel)
        expected_url = f"{base_url.rstrip('/')}/{rel}" if isinstance(base_url, str) else None
        if item.get("url") != expected_url or not _HASH_RE.fullmatch(str(item.get("sha256", ""))):
            base_result["cross_reference_errors"].append(f"invalid resource metadata: {rel}")
    missing_expected = sorted(_EXPECTED_HASHED_RESOURCES - seen)
    base_result["missing_resources"].extend(missing_expected)

    required = [".well-known/organa.json", "signature-request.json"]
    for rel in required:
        if not (out_dir / rel).is_file():
            base_result["missing_resources"].append(rel)
    discovery_path = out_dir / ".well-known/organa.json"
    request_path = out_dir / "signature-request.json"
    if discovery_path.is_file():
        try:
            discovery = json.loads(discovery_path.read_text(encoding="utf-8"))
            if discovery.get("coordinate") != cell.get("coordinate"):
                base_result["changed_resources"].append(".well-known/organa.json")
            current = discovery.get("current_manifest") or {}
            if current.get("sha256") != _sha256_bytes(cell_path.read_bytes()) or current.get("url") != f"{base_url}/organa-cell.json":
                base_result["changed_resources"].append(".well-known/organa.json")
        except (OSError, json.JSONDecodeError, AttributeError):
            base_result["changed_resources"].append(".well-known/organa.json")
    if request_path.is_file() and discovery_path.is_file():
        try:
            request = json.loads(request_path.read_text(encoding="utf-8"))
            discovery = json.loads(discovery_path.read_text(encoding="utf-8"))
            request_hash = _sha256_bytes(request_path.read_bytes())
            claimed_hash = (discovery.get("controller_claim") or {}).get("signature_request_sha256")
            if request_hash != claimed_hash:
                base_result["changed_resources"].append("signature-request.json")
            message = request.get("message")
            if not isinstance(message, str) or _sha256_bytes(message.encode("utf-8")) != request.get("message_sha256"):
                base_result["changed_resources"].append("signature-request.json")
            if request.get("coordinate") != cell.get("coordinate") or request.get("controller_address") != (cell.get("controller") or {}).get("address"):
                base_result["changed_resources"].append("signature-request.json")
        except (OSError, json.JSONDecodeError, AttributeError):
            base_result["changed_resources"].append("signature-request.json")

    for rel, expected_type in (
        ("agent-registry.json", "agents"),
        ("service-registry.json", "services"),
        ("proof-index.json", "proofs"),
    ):
        path = out_dir / rel
        if path.is_file():
            try:
                registry = json.loads(path.read_text(encoding="utf-8"))
                errors = _schema_errors(registry, _registry_schema(str(base_url or "https://invalid.example").rstrip("/")))
                base_result["schema_errors"].extend([f"{rel}: {e}" for e in errors])
                if registry.get("coordinate") != cell.get("coordinate") or registry.get("registry_type") != expected_type:
                    base_result["cross_reference_errors"].append(f"registry mismatch: {rel}")
            except (OSError, json.JSONDecodeError, AttributeError):
                base_result["schema_errors"].append(f"invalid registry: {rel}")

    for key in ("missing_resources", "changed_resources", "unsafe_resources", "cross_reference_errors", "schema_errors"):
        base_result[key] = sorted(set(base_result[key]))
    base_result.update({
        "coordinate": cell.get("coordinate"),
        "checked_resources": len(resources),
        "cell_sha256": _sha256_bytes(cell_path.read_bytes()),
        "controller_signature_status": (cell.get("controller") or {}).get("signature_status"),
    })
    base_result["ok"] = not any(base_result[key] for key in ("missing_resources", "changed_resources", "unsafe_resources", "cross_reference_errors", "schema_errors"))
    return base_result
