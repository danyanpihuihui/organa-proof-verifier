import hashlib
import json
from pathlib import Path

import pytest

from bitmap_memory_portal.cell_adapter import (
    build_adapter_envelope,
    validate_adapter_envelope,
)


def _write(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def test_build_and_validate_adapter_envelope(tmp_path):
    source = _write(tmp_path / "source.json", '{"source":"public-safe"}')
    output = _write(tmp_path / "result.json", '{"status":"ok"}')

    envelope = build_adapter_envelope(
        adapter_id="example-adapter",
        adapter_version="1.2.3",
        capability_type="derived-analysis",
        source_paths=[source],
        configuration={"mode": "read-only"},
        status="completed",
        output_paths=[output],
        warnings=["derived evidence only"],
        disclosure_level="L2_METADATA_PROOF",
        canonical_state_mutation=False,
        verification={"status": "passed", "checks": ["hashes"]},
    )

    validate_adapter_envelope(envelope)
    assert envelope["schema_version"] == "organa-cell-adapter-v1"
    assert envelope["authority"]["second_runtime_allowed"] is False
    assert envelope["authority"]["memory_authority_allowed"] is False
    assert envelope["authority"]["scheduler_authority_allowed"] is False
    assert envelope["authority"]["canonical_state_mutation"] is False
    assert envelope["sources"][0]["sha256"].startswith("sha256:")
    assert envelope["outputs"][0]["sha256"].startswith("sha256:")


def test_adapter_contract_rejects_canonical_mutation_and_bad_hash(tmp_path):
    source = _write(tmp_path / "source.json", "{}")
    output = _write(tmp_path / "result.json", "{}")
    envelope = build_adapter_envelope(
        adapter_id="unsafe",
        adapter_version="0.1",
        capability_type="test",
        source_paths=[source],
        configuration={},
        status="completed",
        output_paths=[output],
        warnings=[],
        disclosure_level="L1_HASH_PROOF",
        canonical_state_mutation=False,
        verification={"status": "passed"},
    )

    envelope["authority"]["canonical_state_mutation"] = True
    with pytest.raises(ValueError, match="canonical state"):
        validate_adapter_envelope(envelope)

    envelope["authority"]["canonical_state_mutation"] = False
    envelope["outputs"][0]["sha256"] = "sha256:bad"
    with pytest.raises(ValueError, match="sha256"):
        validate_adapter_envelope(envelope)
