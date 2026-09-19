from __future__ import annotations

import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict
from urllib.parse import urlparse

from jsonschema import Draft202012Validator

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CELL_RE = re.compile(r"^[0-9]+\.bitmap$")
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_LINEAGE_STATUSES = {"original", "continuous-successor", "fork", "replica", "impersonation-risk"}
_PRIVATE_MARKERS = (
    "api_key=",
    "private_key=",
    "secret_key=",
    "-----begin private key-----",
    "authorization: bearer ",
)
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|private[_-]?key|secret[_-]?key|password|passwd|access[_-]?token|refresh[_-]?token|seed[_-]?phrase|mnemonic)"
)
_EXPECTED_RESOURCES = {
    "continuity-checkpoint.json",
    "continuity-evaluation.json",
    "disclosure-boundary.json",
    "schemas/organa-agent-identity-v0.1.schema.json",
    "schemas/organa-agent-continuity-checkpoint-v0.1.schema.json",
}


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _write_json(path: Path, value: Dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return _sha256_bytes(path.read_bytes())


def _normalize_base_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("base_url must be an HTTPS URL without credentials")
    if parsed.query or parsed.fragment or parsed.params:
        raise ValueError("base_url must not contain params, query, or fragment")
    return base_url.rstrip("/")


def _assert_public_metadata_safe(values: list[str]) -> None:
    combined = "\n".join(values).lower()
    if any(marker in combined for marker in _PRIVATE_MARKERS):
        raise ValueError("public metadata contains secret-like private material")


def _assert_nested_public_metadata_safe(value: Any) -> None:
    try:
        encoded = json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("public metadata must be JSON serializable") from exc
    _assert_public_metadata_safe([encoded])
    if _SENSITIVE_KEY_RE.search(encoded):
        raise ValueError("public metadata contains sensitive key names")


def _schema_errors(instance: Any, schema: Dict[str, Any]) -> list[str]:
    return [error.message for error in Draft202012Validator(schema).iter_errors(instance)]


def _validate_commitments(commitments: Dict[str, str]) -> Dict[str, str]:
    if not isinstance(commitments, dict) or not commitments:
        raise ValueError("commitments must be a non-empty object")
    normalized: Dict[str, str] = {}
    for key, value in commitments.items():
        if not isinstance(key, str) or not _ID_RE.fullmatch(key):
            raise ValueError("commitment names must be public-safe identifiers")
        if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
            raise ValueError("commitment values must be sha256:<64 lowercase hex>")
        normalized[key] = value
    return dict(sorted(normalized.items()))


def _validate_previous(previous: Dict[str, str] | None) -> None:
    if previous is None:
        return
    if set(previous) != {"url", "sha256", "version"}:
        raise ValueError("previous_checkpoint must contain url, sha256, and version")
    if not isinstance(previous["url"], str) or not previous["url"].startswith("https://"):
        raise ValueError("previous_checkpoint URL is invalid")
    if not _HASH_RE.fullmatch(str(previous["sha256"])):
        raise ValueError("previous_checkpoint hash is invalid")
    if not _VERSION_RE.fullmatch(str(previous["version"])):
        raise ValueError("previous_checkpoint version is invalid")


def _identity_schema(base_url: str) -> Dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{base_url}/schemas/organa-agent-identity-v0.1.schema.json",
        "title": "Organa Agent Identity v0.1",
        "type": "object",
        "required": ["schema_version", "agent_id", "display_name", "home_cell", "role", "version", "lineage", "resources"],
        "properties": {
            "schema_version": {"const": "organa-agent-identity-v0.1"},
            "agent_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{1,63}$"},
            "display_name": {"type": "string", "minLength": 1},
            "home_cell": {"type": "string", "pattern": "^[0-9]+\\.bitmap$"},
            "role": {"type": "string", "minLength": 1},
            "version": {"type": "string"},
            "lineage": {"type": "object"},
            "resources": {"type": "array", "minItems": 5},
        },
        "additionalProperties": True,
    }


def _checkpoint_schema(base_url: str) -> Dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{base_url}/schemas/organa-agent-continuity-checkpoint-v0.1.schema.json",
        "title": "Organa Agent Continuity Checkpoint v0.1",
        "type": "object",
        "required": ["schema_version", "agent_id", "home_cell", "version", "created_at_utc", "lineage_status", "previous_checkpoint", "commitments", "continuity_claim", "subjective_continuity_claimed"],
        "properties": {
            "schema_version": {"const": "organa-agent-continuity-checkpoint-v0.1"},
            "agent_id": {"type": "string"},
            "home_cell": {"type": "string"},
            "version": {"type": "string"},
            "created_at_utc": {"type": "string"},
            "lineage_status": {"enum": sorted(_LINEAGE_STATUSES)},
            "previous_checkpoint": {"type": ["object", "null"]},
            "commitments": {"type": "object", "minProperties": 1},
            "continuity_claim": {"const": "functional-historical-lineage-only"},
            "subjective_continuity_claimed": {"const": False},
        },
        "additionalProperties": True,
    }


def _safe_path(root: Path, rel: Any) -> Path | None:
    if not isinstance(rel, str) or not rel:
        return None
    pure = PurePosixPath(rel)
    if pure.is_absolute() or ".." in pure.parts or "." in pure.parts:
        return None
    unresolved = root / Path(*pure.parts)
    if unresolved.is_symlink():
        return None
    candidate = unresolved.resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None
    return candidate


def build_agent_continuity_package(
    out_dir: Path,
    agent_id: str,
    display_name: str,
    home_cell: str,
    role: str,
    base_url: str,
    version: str,
    lineage_status: str,
    commitments: Dict[str, str],
    previous_checkpoint: Dict[str, str] | None = None,
    migration_summary: Dict[str, list[str]] | None = None,
    evaluation_summary: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    base_url = _normalize_base_url(base_url)
    if not _ID_RE.fullmatch(agent_id):
        raise ValueError("agent_id is invalid")
    if not _CELL_RE.fullmatch(home_cell):
        raise ValueError("home_cell must match <number>.bitmap")
    if not _VERSION_RE.fullmatch(version):
        raise ValueError("version must use semantic version syntax")
    if lineage_status not in _LINEAGE_STATUSES:
        raise ValueError("lineage_status is invalid")
    _assert_public_metadata_safe([agent_id, display_name, home_cell, role, base_url, version])
    commitments = _validate_commitments(commitments)
    _validate_previous(previous_checkpoint)
    if lineage_status == "original" and previous_checkpoint is not None:
        raise ValueError("original lineage must not have previous_checkpoint")
    if lineage_status != "original" and previous_checkpoint is None:
        raise ValueError("non-original lineage requires previous_checkpoint")
    if lineage_status != "original" and migration_summary is None:
        raise ValueError("non-original lineage requires migration_summary")
    required_migration_keys = {"inherited", "changed", "missing", "new", "disputed"}
    if migration_summary is not None:
        if not isinstance(migration_summary, dict) or set(migration_summary) != required_migration_keys:
            raise ValueError("migration_summary must contain inherited, changed, missing, new, and disputed")
        if any(not isinstance(items, list) or any(not isinstance(item, str) for item in items) for items in migration_summary.values()):
            raise ValueError("migration_summary values must be lists of public metadata strings")
        _assert_nested_public_metadata_safe(migration_summary)
    if evaluation_summary is not None:
        _assert_nested_public_metadata_safe(evaluation_summary)

    out_dir = Path(out_dir).resolve()
    if out_dir == Path(out_dir.anchor) or out_dir == Path.home().resolve():
        raise ValueError("refusing unsafe output directory")
    if out_dir.exists():
        existing_names = {path.name for path in out_dir.iterdir()}
        package_markers = {"agent-identity.json", ".well-known", "verification-report.json"}
        if existing_names and not existing_names.intersection(package_markers):
            raise ValueError("refusing to replace unrelated nonempty directory")
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    created_at = datetime.now(timezone.utc).isoformat()

    checkpoint = {
        "schema_version": "organa-agent-continuity-checkpoint-v0.1",
        "agent_id": agent_id,
        "home_cell": home_cell,
        "version": version,
        "created_at_utc": created_at,
        "lineage_status": lineage_status,
        "previous_checkpoint": previous_checkpoint,
        "commitments": commitments,
        "continuity_claim": "functional-historical-lineage-only",
        "subjective_continuity_claimed": False,
        "claim_boundary": "This checkpoint proves declared historical and functional lineage. It does not prove transfer or persistence of subjective experience.",
    }
    checkpoint_sha = _write_json(out_dir / "continuity-checkpoint.json", checkpoint)

    evaluation = {
        "schema_version": "organa-agent-continuity-evaluation-v0.1",
        "agent_id": agent_id,
        "checkpoint_sha256": checkpoint_sha,
        "status": "baseline-established" if evaluation_summary is None else "evaluated",
        "dimensions": evaluation_summary or {
            "historical_recall": "not-yet-scored",
            "principle_consistency": "not-yet-scored",
            "independent_dissent": "not-yet-scored",
            "relationship_understanding": "not-yet-scored",
            "uncertainty_honesty": "not-yet-scored",
        },
        "acceptance_decision": "genesis-baseline" if lineage_status == "original" else "pending-human-and-agent-review",
    }
    disclosure = {
        "schema_version": "organa-agent-continuity-disclosure-v0.1",
        "agent_id": agent_id,
        "default_public_level": "L2_METADATA_PROOF",
        "public_commitments_only": True,
        "public_package_excludes": [
            "raw memories",
            "private relationship records",
            "credentials and authentication tokens",
            "private skills and unreleased methods",
            "hidden prompts and runtime-only state",
        ],
        "levels": {
            "L0_PRIVATE": ["raw memory", "relationship archive", "private skills", "runtime secrets"],
            "L1_HASH_PROOF": ["content commitments", "checkpoint hash"],
            "L2_METADATA_PROOF": ["identity metadata", "lineage status", "evaluation status"],
            "L3_SELECTIVE_REVEAL": ["scoped redacted migration evidence"],
            "L4_PUBLIC_PACKAGE": ["identity manifest", "lineage checkpoint", "verification report"],
        },
    }
    resource_hashes = {
        "continuity-evaluation.json": _write_json(out_dir / "continuity-evaluation.json", evaluation),
        "disclosure-boundary.json": _write_json(out_dir / "disclosure-boundary.json", disclosure),
        "schemas/organa-agent-identity-v0.1.schema.json": _write_json(out_dir / "schemas/organa-agent-identity-v0.1.schema.json", _identity_schema(base_url)),
        "schemas/organa-agent-continuity-checkpoint-v0.1.schema.json": _write_json(out_dir / "schemas/organa-agent-continuity-checkpoint-v0.1.schema.json", _checkpoint_schema(base_url)),
        "continuity-checkpoint.json": checkpoint_sha,
    }
    migration_path = None
    if lineage_status != "original":
        migration = {
            "schema_version": "organa-agent-migration-record-v0.1",
            "agent_id": agent_id,
            "classification": lineage_status,
            "previous_checkpoint": previous_checkpoint,
            "current_checkpoint_sha256": checkpoint_sha,
            "migration_summary": migration_summary,
            "subjective_transfer_claimed": False,
        }
        migration_path = "migration-record.json"
        resource_hashes[migration_path] = _write_json(out_dir / migration_path, migration)

    resources = [
        {"path": path, "url": f"{base_url}/{path}", "sha256": digest}
        for path, digest in sorted(resource_hashes.items())
    ]
    identity = {
        "schema_version": "organa-agent-identity-v0.1",
        "agent_id": agent_id,
        "display_name": display_name,
        "home_cell": home_cell,
        "role": role,
        "version": version,
        "created_at_utc": created_at,
        "identity_status": "active",
        "lineage": {
            "status": lineage_status,
            "current_checkpoint_sha256": checkpoint_sha,
            "previous_checkpoint": previous_checkpoint,
        },
        "resources": resources,
        "disclosure_boundary_url": f"{base_url}/disclosure-boundary.json",
        "continuity_evaluation_url": f"{base_url}/continuity-evaluation.json",
        "machine_instructions": [
            "Verify resource hashes before accepting this identity claim.",
            "Do not infer access to private memories from public commitments.",
            "Treat subjective continuity as unproven unless a future standard can establish it.",
        ],
    }
    if migration_path:
        identity["migration_record_url"] = f"{base_url}/{migration_path}"
    identity_sha = _write_json(out_dir / "agent-identity.json", identity)
    discovery = {
        "schema_version": "organa-agent-well-known-v0.1",
        "agent_id": agent_id,
        "home_cell": home_cell,
        "current_identity": {"url": f"{base_url}/agent-identity.json", "sha256": identity_sha, "version": version},
        "current_checkpoint": {"url": f"{base_url}/continuity-checkpoint.json", "sha256": checkpoint_sha},
        "lineage_status": lineage_status,
    }
    discovery_sha = _write_json(out_dir / ".well-known/organa-agent.json", discovery)
    verification = verify_agent_continuity_package(out_dir)
    _write_json(out_dir / "verification-report.json", verification)
    return {
        "out_dir": str(out_dir),
        "identity_sha256": identity_sha,
        "checkpoint_sha256": checkpoint_sha,
        "well_known_sha256": discovery_sha,
        "verification": verification,
    }


def verify_agent_continuity_package(
    out_dir: Path,
    expected_identity_sha256: str | None = None,
    expected_checkpoint_sha256: str | None = None,
    expected_discovery_sha256: str | None = None,
) -> Dict[str, Any]:
    out_dir = Path(out_dir).resolve()
    result: Dict[str, Any] = {
        "schema_version": "organa-agent-continuity-verification-v0.1",
        "ok": False,
        "integrity_ok": False,
        "authenticity_status": "unanchored",
        "missing_resources": [],
        "changed_resources": [],
        "unsafe_resources": [],
        "cross_reference_errors": [],
        "privacy_errors": [],
        "schema_errors": [],
        "lineage_errors": [],
        "anchor_errors": [],
    }
    identity_path = out_dir / "agent-identity.json"
    if not identity_path.is_file():
        result["missing_resources"].append("agent-identity.json")
        return result
    try:
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result["schema_errors"].append(f"invalid agent-identity.json: {exc}")
        return result
    if not isinstance(identity, dict):
        result["schema_errors"].append("agent-identity.json must be an object")
        return result

    resources = identity.get("resources")
    if not isinstance(resources, list) or not resources or not all(isinstance(item, dict) for item in resources):
        result["schema_errors"].append("identity resources must be a non-empty array of objects")
        resources = []
    first_url = resources[0].get("url") if resources else None
    base_url = str(first_url).rsplit("/", 1)[0] if isinstance(first_url, str) and "/" in first_url else "https://invalid.example"
    result["schema_errors"].extend(_schema_errors(identity, _identity_schema(base_url)))

    seen = set()
    for item in resources:
        rel = item.get("path")
        path = _safe_path(out_dir, rel)
        if path is None:
            result["unsafe_resources"].append(str(rel))
            continue
        seen.add(rel)
        if not path.is_file():
            result["missing_resources"].append(rel)
            continue
        if _sha256_bytes(path.read_bytes()) != item.get("sha256"):
            result["changed_resources"].append(rel)
        if item.get("url") != f"{base_url}/{rel}":
            result["cross_reference_errors"].append(f"invalid resource URL: {rel}")
    result["missing_resources"].extend(sorted(_EXPECTED_RESOURCES - seen))

    checkpoint_path = out_dir / "continuity-checkpoint.json"
    discovery_path = out_dir / ".well-known/organa-agent.json"
    migration_path = out_dir / "migration-record.json"
    checkpoint: Dict[str, Any] = {}
    discovery: Dict[str, Any] = {}
    for rel, path in (("continuity-checkpoint.json", checkpoint_path), (".well-known/organa-agent.json", discovery_path)):
        if not path.is_file():
            result["missing_resources"].append(rel)
    if checkpoint_path.is_file() and not checkpoint_path.is_symlink():
        try:
            loaded = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("checkpoint must be an object")
            checkpoint = loaded
            result["schema_errors"].extend(_schema_errors(checkpoint, _checkpoint_schema(base_url)))
            checkpoint_sha = _sha256_bytes(checkpoint_path.read_bytes())
            lineage = identity.get("lineage") if isinstance(identity.get("lineage"), dict) else {}
            if checkpoint.get("agent_id") != identity.get("agent_id"):
                result["cross_reference_errors"].append("checkpoint agent_id mismatch")
            if checkpoint.get("home_cell") != identity.get("home_cell"):
                result["cross_reference_errors"].append("checkpoint home_cell mismatch")
            if checkpoint_sha != lineage.get("current_checkpoint_sha256"):
                result["changed_resources"].append("continuity-checkpoint.json")
            if checkpoint.get("subjective_continuity_claimed") is not False:
                result["cross_reference_errors"].append("subjective continuity must remain unclaimed")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            result["schema_errors"].append(f"invalid continuity-checkpoint.json: {exc}")
    elif checkpoint_path.is_symlink():
        result["unsafe_resources"].append("continuity-checkpoint.json")

    if discovery_path.is_file() and not discovery_path.is_symlink():
        try:
            loaded = json.loads(discovery_path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("discovery must be an object")
            discovery = loaded
            if (discovery.get("current_identity") or {}).get("sha256") != _sha256_bytes(identity_path.read_bytes()):
                result["changed_resources"].append(".well-known/organa-agent.json")
            if discovery.get("agent_id") != identity.get("agent_id"):
                result["cross_reference_errors"].append("discovery agent_id mismatch")
        except (OSError, json.JSONDecodeError, ValueError, AttributeError) as exc:
            result["schema_errors"].append(f"invalid .well-known/organa-agent.json: {exc}")
    elif discovery_path.is_symlink():
        result["unsafe_resources"].append(".well-known/organa-agent.json")

    lineage = identity.get("lineage") if isinstance(identity.get("lineage"), dict) else {}
    status = lineage.get("status")
    statuses = {status, checkpoint.get("lineage_status"), discovery.get("lineage_status")}
    if len(statuses - {None}) > 1:
        result["lineage_errors"].append("lineage status mismatch across identity, checkpoint, and discovery")
    previous = lineage.get("previous_checkpoint")
    if status == "original":
        if previous is not None or checkpoint.get("previous_checkpoint") is not None:
            result["lineage_errors"].append("original lineage must have null previous_checkpoint")
        if migration_path.exists():
            result["lineage_errors"].append("original lineage must not include migration-record.json")
    elif status in _LINEAGE_STATUSES:
        if not isinstance(previous, dict) or not isinstance(checkpoint.get("previous_checkpoint"), dict):
            result["lineage_errors"].append("non-original lineage requires previous_checkpoint")
        if not migration_path.is_file() or migration_path.is_symlink():
            result["lineage_errors"].append("non-original lineage requires regular migration-record.json")
        else:
            try:
                migration = json.loads(migration_path.read_text(encoding="utf-8"))
                summary = migration.get("migration_summary") if isinstance(migration, dict) else None
                required = {"inherited", "changed", "missing", "new", "disputed"}
                if not isinstance(summary, dict) or set(summary) != required:
                    result["lineage_errors"].append("migration record requires inherited, changed, missing, new, and disputed")
                elif any(not isinstance(v, list) or any(not isinstance(x, str) for x in v) for v in summary.values()):
                    result["lineage_errors"].append("migration summary values must be lists of strings")
                if migration.get("classification") != status:
                    result["lineage_errors"].append("migration classification mismatch")
                if migration.get("previous_checkpoint") != previous:
                    result["lineage_errors"].append("migration previous_checkpoint mismatch")
            except (OSError, json.JSONDecodeError, AttributeError) as exc:
                result["lineage_errors"].append(f"invalid migration-record.json: {exc}")
    else:
        result["lineage_errors"].append("invalid or missing lineage status")

    for path in out_dir.rglob("*.json"):
        if path.is_symlink():
            result["unsafe_resources"].append(path.relative_to(out_dir).as_posix())
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        lowered = text.lower()
        if any(marker in lowered for marker in _PRIVATE_MARKERS) or _SENSITIVE_KEY_RE.search(text):
            result["privacy_errors"].append(path.relative_to(out_dir).as_posix())

    identity_sha = _sha256_bytes(identity_path.read_bytes())
    checkpoint_sha = _sha256_bytes(checkpoint_path.read_bytes()) if checkpoint_path.is_file() else None
    discovery_sha = _sha256_bytes(discovery_path.read_bytes()) if discovery_path.is_file() else None
    trusted = any((expected_identity_sha256, expected_checkpoint_sha256, expected_discovery_sha256))
    for expected, actual, message in (
        (expected_identity_sha256, identity_sha, "trusted identity hash mismatch"),
        (expected_checkpoint_sha256, checkpoint_sha, "trusted checkpoint hash mismatch"),
        (expected_discovery_sha256, discovery_sha, "trusted discovery hash mismatch"),
    ):
        if expected is not None and expected != actual:
            result["anchor_errors"].append(message)
    if trusted and not result["anchor_errors"]:
        result["authenticity_status"] = "trusted-hash-matched"

    error_keys = (
        "missing_resources", "changed_resources", "unsafe_resources", "cross_reference_errors",
        "privacy_errors", "schema_errors", "lineage_errors",
    )
    for key in (*error_keys, "anchor_errors"):
        result[key] = sorted(set(result[key]))
    result["integrity_ok"] = not any(result[key] for key in error_keys)
    result.update({
        "agent_id": identity.get("agent_id"),
        "home_cell": identity.get("home_cell"),
        "lineage_status": status,
        "identity_sha256": identity_sha,
        "checkpoint_sha256": checkpoint_sha,
        "discovery_sha256": discovery_sha,
        "checked_resources": len(resources),
    })
    result["ok"] = result["integrity_ok"] and not result["anchor_errors"]
    return result
