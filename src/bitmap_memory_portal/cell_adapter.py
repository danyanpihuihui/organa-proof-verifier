from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Dict, Iterable, List

SCHEMA_VERSION = "organa-cell-adapter-v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_ALLOWED_STATUS = {"planned", "running", "completed", "failed", "blocked"}
_ALLOWED_DISCLOSURE = {
    "L0_PRIVATE",
    "L1_HASH_PROOF",
    "L2_METADATA_PROOF",
    "L3_SELECTIVE_REVEAL",
    "L4_PUBLIC_PACKAGE",
}


def _file_record(path: Path) -> Dict:
    resolved = Path(path).expanduser().resolve()
    payload = resolved.read_bytes()
    return {
        "path": str(resolved),
        "size_bytes": len(payload),
        "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
    }


def build_adapter_envelope(
    *,
    adapter_id: str,
    adapter_version: str,
    capability_type: str,
    source_paths: Iterable[Path],
    configuration: Dict,
    status: str,
    output_paths: Iterable[Path],
    warnings: Iterable[str],
    disclosure_level: str,
    canonical_state_mutation: bool,
    verification: Dict,
) -> Dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "adapter": {
            "id": adapter_id,
            "version": adapter_version,
            "capability_type": capability_type,
        },
        "sources": [_file_record(path) for path in source_paths],
        "configuration": configuration,
        "execution": {"status": status},
        "outputs": [_file_record(path) for path in output_paths],
        "warnings": list(warnings),
        "disclosure_level": disclosure_level,
        "authority": {
            "canonical_state_mutation": canonical_state_mutation,
            "second_runtime_allowed": False,
            "memory_authority_allowed": False,
            "scheduler_authority_allowed": False,
            "credential_authority_allowed": False,
            "approval_required_for_canonical_use": True,
        },
        "verification": verification,
    }


def validate_adapter_envelope(envelope: Dict) -> bool:
    if envelope.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported adapter schema version")
    adapter = envelope.get("adapter") or {}
    for key in ("id", "version", "capability_type"):
        if not adapter.get(key):
            raise ValueError(f"adapter.{key} is required")
    if (envelope.get("execution") or {}).get("status") not in _ALLOWED_STATUS:
        raise ValueError("invalid execution status")
    if envelope.get("disclosure_level") not in _ALLOWED_DISCLOSURE:
        raise ValueError("invalid disclosure level")

    authority = envelope.get("authority") or {}
    if authority.get("canonical_state_mutation") is not False:
        raise ValueError("external adapters cannot mutate canonical state")
    for key in (
        "second_runtime_allowed",
        "memory_authority_allowed",
        "scheduler_authority_allowed",
        "credential_authority_allowed",
    ):
        if authority.get(key) is not False:
            raise ValueError(f"external adapter authority must disable {key}")
    if authority.get("approval_required_for_canonical_use") is not True:
        raise ValueError("canonical use must require approval")

    for group in ("sources", "outputs"):
        records = envelope.get(group)
        if not isinstance(records, list):
            raise ValueError(f"{group} must be a list")
        for record in records:
            if not _SHA256.match(str(record.get("sha256") or "")):
                raise ValueError(f"invalid sha256 in {group}")
            if not record.get("path") or not isinstance(record.get("size_bytes"), int):
                raise ValueError(f"incomplete file record in {group}")

    verification = envelope.get("verification") or {}
    if not verification.get("status"):
        raise ValueError("verification.status is required")
    return True
