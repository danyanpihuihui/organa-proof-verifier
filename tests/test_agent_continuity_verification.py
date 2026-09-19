"""Regression tests: the public verifier must actually verify the agent identity layer.

These tests exist because the deployed proof verifier silently ignored agents entirely
(2026-09-19). Two independent defects combined to hide it:

1. ``cell_resolution.verify_cell_resolution_package`` had no agent-continuity pass at all,
   so agent files were only hash-counted as generic manifest resources. Continuity
   semantics (home_cell binding, declared lineage, the no-subjective-continuity rule,
   discovery<->identity hash agreement) were never checked.
2. Even where a continuity failure did flip ``ok`` to False, ``_verification_response``
   mapped only five error fields to the response body, so ``agent_continuity_errors``
   was dropped. The caller received ``integrity-invalid`` with an empty ``errors`` list
   and no way to learn why.

A verifier that reports "valid" for a cell whose agent identity was tampered with is
worse than no verifier, so these cases are pinned here.
"""

import hashlib
import json
import shutil
from pathlib import Path

from bitmap_memory_portal.agent_continuity import build_agent_continuity_package
from bitmap_memory_portal.cell_resolution import build_cell_resolution_package
from bitmap_memory_portal.proof_verifier import verify_package

COORDINATE = "7187.bitmap"
BASE_URL = "https://resolver.example/cell"
ADDRESS = "bc1ptestcontroller"
AGENT_ID = "hemi"
AGENT_BASE = "https://resolver.example/cell/agents/hemi"
COMMITMENTS = {"identity_principles": "sha256:" + "a" * 64}


def _sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _sync_manifest_resource(package: Path, name: str, path: Path) -> None:
    """Keep declared hashes in step with a mutated artifact, up the whole chain.

    Mutating ``agent-registry.json`` legitimately changes the manifest that hashes it,
    which in turn changes the manifest hash the canonical resolver declares. Refreshing
    the full chain keeps the fixture honest: without it the tests would be measuring a
    hash mismatch instead of the agent-continuity rule under test.
    """
    manifest_path = package / "organa-cell.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for resource in manifest.get("resources", []):
        if resource.get("path") == name:
            resource["sha256"] = _sha256_file(path)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    well_known_path = package / ".well-known" / "organa.json"
    well_known = json.loads(well_known_path.read_text(encoding="utf-8"))
    if isinstance(well_known.get("current_manifest"), dict):
        well_known["current_manifest"]["sha256"] = _sha256_file(manifest_path)
    well_known_path.write_text(json.dumps(well_known, indent=2) + "\n", encoding="utf-8")


def _write_registry(package: Path, entry: dict) -> None:
    registry_path = package / "agent-registry.json"
    registry_path.write_text(
        json.dumps(
            {
                "schema_version": "organa-registry-v0.1",
                "coordinate": COORDINATE,
                "registry_type": "agents",
                "entries": [entry],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    _sync_manifest_resource(package, "agent-registry.json", registry_path)


def _cell_with_agent(tmp_path: Path, *, lineage_status: str = "original") -> tuple[Path, dict]:
    """Build a cell package containing one registered agent continuity package."""
    package = tmp_path / "cell"
    build_cell_resolution_package(package, COORDINATE, BASE_URL, ADDRESS)
    agent_dir = package / "agents" / AGENT_ID
    built = build_agent_continuity_package(
        agent_dir,
        AGENT_ID,
        "Hemi",
        COORDINATE,
        "long-term-collaborative-agent",
        AGENT_BASE,
        "0.1.0",
        lineage_status,
        COMMITMENTS,
    )
    entry = {
        "id": AGENT_ID,
        "name": "Hemi",
        "role": "long-term-collaborative-agent",
        "lifecycle_status": "live",
        "identity": {"url": f"{AGENT_BASE}/agent-identity.json", "sha256": built["identity_sha256"]},
        "continuity_checkpoint": {"url": f"{AGENT_BASE}/continuity-checkpoint.json", "sha256": built["checkpoint_sha256"]},
        "discovery": {"url": f"{AGENT_BASE}/.well-known/organa-agent.json", "sha256": built["well_known_sha256"]},
        "lineage_status": lineage_status,
        "subjective_continuity_claimed": False,
    }
    _write_registry(package, entry)
    return package, entry


def _error_codes(result: dict) -> list[str]:
    return [item.get("code", "") for item in result.get("errors", [])]


def test_agent_continuity_is_reported_and_passes(tmp_path: Path) -> None:
    """A well-formed agent package verifies, and the field is present (not absent)."""
    package, _ = _cell_with_agent(tmp_path)
    result = verify_package(str(package))

    verification = result["verification"]
    assert "agent_continuity_errors" in verification, "agent layer must be part of the verification result"
    assert verification["agent_continuity_errors"] == []
    assert result["ok"] is True
    assert result["status"] == "integrity-valid"


def test_agent_entry_is_actually_walked(tmp_path: Path) -> None:
    """Prove the agent entry is not silently skipped.

    A registry entry is only inspected when it carries an ``identity`` object, so an
    entry without one passes trivially. Dropping the continuity package directory must
    be detected, which shows the entry is followed rather than ignored.
    """
    package, _ = _cell_with_agent(tmp_path)
    shutil.rmtree(package / "agents")
    result = verify_package(str(package))

    assert result["ok"] is False
    assert result["verification"]["agent_continuity_errors"] == [f"missing agent continuity package: {AGENT_ID}"]


def test_tampered_identity_hash_fails_and_surfaces_in_errors(tmp_path: Path) -> None:
    """A registry declaring the wrong identity hash must fail loudly.

    This is the case that was silently ignored before: `ok` went False while the
    response `errors` list stayed empty, leaving the caller nothing to act on.
    """
    package, entry = _cell_with_agent(tmp_path)
    entry["identity"]["sha256"] = "sha256:" + "0" * 64
    _write_registry(package, entry)

    result = verify_package(str(package))

    assert result["ok"] is False
    assert result["status"] == "integrity-invalid"
    assert result["verification"]["agent_continuity_errors"], "failure must be recorded"
    assert "agent-continuity-errors" in _error_codes(result), "failure must reach the HTTP response body"


def test_tampered_agent_artifact_fails(tmp_path: Path) -> None:
    """Editing a published agent artifact after the fact must be caught."""
    package, _ = _cell_with_agent(tmp_path)
    identity_path = package / "agents" / AGENT_ID / "agent-identity.json"
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    identity["display_name"] = "NotHemi"
    identity_path.write_text(json.dumps(identity, indent=2) + "\n", encoding="utf-8")

    result = verify_package(str(package))

    assert result["ok"] is False
    assert result["verification"]["agent_continuity_errors"]
    assert "agent-continuity-errors" in _error_codes(result)


def test_agent_home_cell_mismatch_fails(tmp_path: Path) -> None:
    """An agent cannot claim to belong to a different Cell than the one publishing it."""
    package, _ = _cell_with_agent(tmp_path)
    identity_path = package / "agents" / AGENT_ID / "agent-identity.json"
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    identity["home_cell"] = "999999.bitmap"
    identity_path.write_text(json.dumps(identity, indent=2) + "\n", encoding="utf-8")

    result = verify_package(str(package))

    assert result["ok"] is False
    assert result["verification"]["agent_continuity_errors"]


def test_declared_lineage_must_match_identity(tmp_path: Path) -> None:
    """The registry's lineage label must agree with the identity document."""
    package, entry = _cell_with_agent(tmp_path)
    entry["lineage_status"] = "fork"
    _write_registry(package, entry)

    result = verify_package(str(package))

    assert result["ok"] is False
    assert result["verification"]["agent_continuity_errors"]


def test_subjective_continuity_must_remain_unclaimed(tmp_path: Path) -> None:
    """Organa must never let a registry assert subjective continuity across sessions."""
    package, entry = _cell_with_agent(tmp_path)
    entry["subjective_continuity_claimed"] = True
    _write_registry(package, entry)

    result = verify_package(str(package))

    assert result["ok"] is False
    assert result["verification"]["agent_continuity_errors"]


def test_registry_without_identity_is_skipped_not_failed(tmp_path: Path) -> None:
    """Placeholder agents carry no continuity package and must stay non-fatal."""
    package, _ = _cell_with_agent(tmp_path)
    shutil.rmtree(package / "agents")
    _write_registry(
        package,
        {
            "id": "organa-cell-orchestrator",
            "name": "Organa Cell Orchestrator",
            "role": "orchestrator",
            "lifecycle_status": "live",
        },
    )

    result = verify_package(str(package))

    assert result["verification"]["agent_continuity_errors"] == []
    assert result["ok"] is True
