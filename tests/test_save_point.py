import json
import zipfile

from test_cli import run_cli


def test_cli_build_package_includes_real_world_save_point_files(tmp_path):
    source = tmp_path / "source"
    out = tmp_path / "out"
    source.mkdir()
    (source / "memory.md").write_text("Patoshi memory and Bitmap research", encoding="utf-8")
    (source / "market.md").write_text("Bitmap marketplace notes", encoding="utf-8")

    result = run_cli([
        "build-package",
        "--source", str(source),
        "--out", str(out),
        "--bitmap", "7187.bitmap",
        "--title", "Patoshi Real-world Save Point",
        "--version", "v9",
        "--description", "anchored save point package",
        "--claim", "claims/claim_7187_v3_unisat.json",
        "--citations", "demo_citations_7187.json",
        "--zip-name", "save-point.zip",
    ])

    assert result.returncode == 0, result.stderr
    demo = out / "demo"
    for name in ["save_point.json", "anchor_request.json", "verify_report.json"]:
        assert (demo / name).exists()
        assert (out / "public" / "demo" / name).exists()

    save_point = json.loads((demo / "save_point.json").read_text(encoding="utf-8"))
    assert save_point["save_point_type"] == "real-world-save-point"
    assert save_point["coordinate"] == "7187.bitmap"
    assert save_point["checkpoint_policy"] == "milestone-only"
    assert save_point["storage_boundary"] == "Bitmap is the canonical coordinate and proof root, not the bulk storage layer."
    assert save_point["canonical_status"] == "local-verified-pending-timestamp"
    assert save_point["timestamp_status"] == "pending"
    assert save_point["checkpoint_hashes"]["manifest_json"].startswith("sha256:")
    assert save_point["checkpoint_hashes"]["task_root_json"].startswith("sha256:")
    assert save_point["checkpoint_hashes"]["save_point_json"].startswith("sha256:")

    anchor_request = json.loads((demo / "anchor_request.json").read_text(encoding="utf-8"))
    assert anchor_request["anchor_request_type"] == "opentimestamps-request"
    assert anchor_request["status"] == "pending"
    assert anchor_request["hash_to_anchor"] == save_point["checkpoint_hashes"]["save_point_json"]
    assert "ots stamp" in anchor_request["recommended_commands"][0]

    verify_report = json.loads((demo / "verify_report.json").read_text(encoding="utf-8"))
    assert verify_report["verify_report_type"] == "real-world-save-point-verify-report"
    assert verify_report["overall_status"] == "valid-local-pending-timestamp"
    assert verify_report["checks"]["manifest_files"]["ok"] is True
    assert verify_report["checks"]["wallet_claim"]["status"] == "locally-verified"
    assert verify_report["checks"]["timestamp_anchor"]["status"] == "pending"

    manifest = json.loads((demo / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["save_point"]["save_point_type"] == "real-world-save-point"
    assert manifest["anchor_request"]["status"] == "pending"
    assert manifest["verify_report"]["overall_status"] == "valid-local-pending-timestamp"

    portal = (demo / "portal.html").read_text(encoding="utf-8")
    assert "Real-world Save Point" in portal
    assert "save_point.json" in portal
    assert "anchor_request.json" in portal
    assert "verify_report.json" in portal
    assert "valid-local-pending-timestamp" in portal

    with zipfile.ZipFile(out / "save-point.zip") as z:
        names = set(z.namelist())
        assert "demo/save_point.json" in names
        assert "demo/anchor_request.json" in names
        assert "demo/verify_report.json" in names
