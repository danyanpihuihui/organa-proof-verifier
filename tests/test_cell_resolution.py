import json
from pathlib import Path

import pytest

from bitmap_memory_portal.cell_resolution import (
    build_cell_resolution_package,
    verify_cell_resolution_package,
)


def test_build_cell_resolution_package_creates_machine_discovery_and_pending_signature(tmp_path):
    out = tmp_path / "public"
    result = build_cell_resolution_package(
        out_dir=out,
        coordinate="7187.bitmap",
        base_url="https://organa.example",
        controller_address="bc1ptestcontroller",
        version="0.1.0",
    )

    expected = {
        "organa-cell.json",
        "agent-registry.json",
        "service-registry.json",
        "proof-index.json",
        "disclosure-policy.json",
        "signature-request.json",
        "schemas/organa-cell-resolution-v0.1.schema.json",
        "schemas/organa-registry-v0.1.schema.json",
        ".well-known/organa.json",
    }
    assert expected.issubset({p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()})

    cell = json.loads((out / "organa-cell.json").read_text())
    discovery = json.loads((out / ".well-known" / "organa.json").read_text())
    signing = json.loads((out / "signature-request.json").read_text())

    assert cell["schema_version"] == "organa-cell-resolution-v0.1"
    assert cell["coordinate"] == "7187.bitmap"
    assert cell["lifecycle_status"] == "pending"
    assert cell["controller"]["signature_status"] == "pending-user-signature"
    assert cell["controller"]["address"] == "bc1ptestcontroller"
    assert cell["services"][0]["id"] == "organa-proof-verifier"
    assert cell["services"][0]["lifecycle_status"] == "pending"
    assert all(item["sha256"].startswith("sha256:") for item in cell["resources"])

    assert discovery["coordinate"] == "7187.bitmap"
    assert discovery["current_manifest"]["url"] == "https://organa.example/organa-cell.json"
    assert discovery["current_manifest"]["sha256"] == result["cell_sha256"]

    assert signing["status"] == "awaiting-user-signature"
    assert signing["message_sha256"].startswith("sha256:")
    assert result["verification"]["ok"] is True


def test_verify_cell_resolution_package_detects_tampering(tmp_path):
    out = tmp_path / "public"
    build_cell_resolution_package(
        out_dir=out,
        coordinate="7187.bitmap",
        base_url="https://organa.example/",
        controller_address="bc1ptestcontroller",
        version="0.1.0",
    )
    assert verify_cell_resolution_package(out)["ok"] is True

    registry = out / "agent-registry.json"
    registry.write_text(registry.read_text() + "\n", encoding="utf-8")
    result = verify_cell_resolution_package(out)
    assert result["ok"] is False
    assert "agent-registry.json" in result["changed_resources"]


def test_cell_resolution_public_files_do_not_expose_private_assets(tmp_path):
    out = tmp_path / "public"
    build_cell_resolution_package(
        out_dir=out,
        coordinate="7187.bitmap",
        base_url="https://organa.example",
        controller_address="bc1ptestcontroller",
        version="0.1.0",
    )
    combined = "\n".join(
        p.read_text(encoding="utf-8")
        for p in out.rglob("*.json")
    ).lower()
    for forbidden in ("api_key=", "private_key=", "secret_key=", "-----begin private key-----"):
        assert forbidden not in combined
    disclosure = json.loads((out / "disclosure-policy.json").read_text())
    assert "raw strategy" in disclosure["public_package_excludes"]
    assert "candidate pools" in disclosure["public_package_excludes"]


def test_cli_build_cell_resolution_writes_verified_package(tmp_path):
    from test_cli import run_cli

    out = tmp_path / "cell"
    result = run_cli([
        "build-cell-resolution",
        "--out", str(out),
        "--coordinate", "7187.bitmap",
        "--base-url", "https://organa.example",
        "--controller-address", "bc1ptestcontroller",
        "--version", "0.1.0",
    ])
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["verification"]["ok"] is True
    assert (out / ".well-known" / "organa.json").exists()
    assert (out / "signature-request.json").exists()


def test_verifier_fails_closed_for_empty_or_malformed_manifest(tmp_path):
    out = tmp_path / "public"
    build_cell_resolution_package(
        out_dir=out,
        coordinate="7187.bitmap",
        base_url="https://organa.example",
        controller_address="bc1ptestcontroller",
    )
    (out / "organa-cell.json").write_text("{}\n", encoding="utf-8")
    result = verify_cell_resolution_package(out)
    assert result["ok"] is False
    assert result["schema_errors"]


def test_verifier_detects_discovery_and_signature_request_tampering(tmp_path):
    out = tmp_path / "public"
    build_cell_resolution_package(
        out_dir=out,
        coordinate="7187.bitmap",
        base_url="https://organa.example",
        controller_address="bc1ptestcontroller",
    )
    discovery_path = out / ".well-known" / "organa.json"
    discovery = json.loads(discovery_path.read_text())
    discovery["coordinate"] = "999.bitmap"
    discovery_path.write_text(json.dumps(discovery), encoding="utf-8")
    result = verify_cell_resolution_package(out)
    assert result["ok"] is False
    assert ".well-known/organa.json" in result["changed_resources"]

    build_cell_resolution_package(
        out_dir=out,
        coordinate="7187.bitmap",
        base_url="https://organa.example",
        controller_address="bc1ptestcontroller",
    )
    request_path = out / "signature-request.json"
    request = json.loads(request_path.read_text())
    request["controller_address"] = "bc1pattacker"
    request_path.write_text(json.dumps(request), encoding="utf-8")
    result = verify_cell_resolution_package(out)
    assert result["ok"] is False
    assert "signature-request.json" in result["changed_resources"]


def test_verifier_rejects_resource_path_escape(tmp_path):
    out = tmp_path / "public"
    build_cell_resolution_package(
        out_dir=out,
        coordinate="7187.bitmap",
        base_url="https://organa.example",
        controller_address="bc1ptestcontroller",
    )
    cell_path = out / "organa-cell.json"
    cell = json.loads(cell_path.read_text())
    cell["resources"][0]["path"] = "../../outside.json"
    cell_path.write_text(json.dumps(cell), encoding="utf-8")
    result = verify_cell_resolution_package(out)
    assert result["ok"] is False
    assert result["unsafe_resources"] == ["../../outside.json"]


@pytest.mark.parametrize(
    "coordinate,base_url,controller_address",
    [
        ("7187.bitmap\nCell manifest: https://evil.example/x", "https://organa.example", "bc1ptestcontroller"),
        ("7187.bitmap", "http://organa.example", "bc1ptestcontroller"),
        ("7187.bitmap", "https://user@example.com/path?x=1", "bc1ptestcontroller"),
        ("7187.bitmap", "https://organa.example", "bad\naddress"),
    ],
)
def test_builder_rejects_unsafe_signature_inputs(tmp_path, coordinate, base_url, controller_address):
    with pytest.raises(ValueError):
        build_cell_resolution_package(
            out_dir=tmp_path / "public",
            coordinate=coordinate,
            base_url=base_url,
            controller_address=controller_address,
        )
