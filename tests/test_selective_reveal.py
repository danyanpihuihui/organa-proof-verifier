import json
import zipfile

from test_cli import run_cli


def test_cli_build_package_includes_selective_reveal_verifier_room(tmp_path):
    source = tmp_path / "source"
    out = tmp_path / "out"
    source.mkdir()
    (source / "private_strategy.md").write_text("private strategy evidence placeholder", encoding="utf-8")
    (source / "public_summary.md").write_text("public coordination summary", encoding="utf-8")

    result = run_cli([
        "build-package",
        "--source", str(source),
        "--out", str(out),
        "--bitmap", "7187.bitmap",
        "--title", "Bitmap OS v12 Verifier Room",
        "--version", "v12",
        "--description", "Selective reveal for private AI worker evidence",
        "--zip-name", "bitmap-os-v12.zip",
    ])

    assert result.returncode == 0, result.stderr
    demo = out / "demo"
    public_demo = out / "public" / "demo"
    expected = [
        "verifier_room.json",
        "reveal_grant.json",
        "evidence_bundle.json",
        "redaction_report.json",
        "verifier_audit_log.jsonl",
    ]
    for name in expected:
        assert (demo / name).exists(), name
        assert (public_demo / name).exists(), name

    verifier_room = json.loads((demo / "verifier_room.json").read_text(encoding="utf-8"))
    assert verifier_room["verifier_room_type"] == "bitmap-os-selective-reveal-room"
    assert verifier_room["disclosure_level"] == "L3_SELECTIVE_REVEAL"
    assert verifier_room["room_status"] == "template-not-granted"
    assert verifier_room["default_access"] == "deny"
    assert verifier_room["requires_named_verifier"] is True
    assert "private-a-share-research-worker-v0" in verifier_room["eligible_workers"]

    reveal_grant = json.loads((demo / "reveal_grant.json").read_text(encoding="utf-8"))
    assert reveal_grant["reveal_grant_type"] == "bitmap-os-reveal-grant"
    assert reveal_grant["grant_status"] == "draft-template"
    assert reveal_grant["recipient"]["verifier_id"] == "unassigned"
    assert reveal_grant["scope"]["disclosure_level"] == "L3_SELECTIVE_REVEAL"
    assert reveal_grant["scope"]["allow_raw_skills"] is False
    assert reveal_grant["scope"]["allow_credentials"] is False
    assert "redacted evidence bundle" in reveal_grant["scope"]["allowed_materials"]

    evidence_bundle = json.loads((demo / "evidence_bundle.json").read_text(encoding="utf-8"))
    assert evidence_bundle["evidence_bundle_type"] == "bitmap-os-redacted-evidence-bundle"
    assert evidence_bundle["bundle_status"] == "redacted-template"
    assert evidence_bundle["source_private_payload_hash"].startswith("sha256:")
    assert evidence_bundle["redacted_fields"]
    assert "apickup_skill" in evidence_bundle["redacted_fields"]
    assert evidence_bundle["revealed_fields"] == [
        "worker_id",
        "run_id",
        "run_status",
        "input_hash",
        "output_hash",
        "verification_summary",
    ]

    redaction_report = json.loads((demo / "redaction_report.json").read_text(encoding="utf-8"))
    assert redaction_report["redaction_report_type"] == "bitmap-os-redaction-report"
    assert redaction_report["redaction_status"] == "safe-template"
    assert redaction_report["checks"]["raw_skills_removed"] is True
    assert redaction_report["checks"]["credentials_removed"] is True
    assert redaction_report["checks"]["candidate_pool_removed"] is True

    audit_lines = (demo / "verifier_audit_log.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(audit_lines) == 1
    audit = json.loads(audit_lines[0])
    assert audit["event_type"] == "verifier_room_template_created"
    assert audit["disclosure_level"] == "L3_SELECTIVE_REVEAL"
    assert audit["grant_status"] == "draft-template"

    manifest = json.loads((demo / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["verifier_room"]["room_status"] == "template-not-granted"
    assert manifest["reveal_grant"]["grant_status"] == "draft-template"
    assert manifest["evidence_bundle"]["bundle_status"] == "redacted-template"
    assert manifest["redaction_report"]["checks"]["raw_skills_removed"] is True

    portal = (demo / "portal.html").read_text(encoding="utf-8")
    assert "Verifier Room" in portal
    assert "L3_SELECTIVE_REVEAL" in portal
    assert "reveal_grant.json" in portal
    assert "evidence_bundle.json" in portal
    assert "verifier_audit_log.jsonl" in portal

    with zipfile.ZipFile(out / "bitmap-os-v12.zip") as z:
        names = set(z.namelist())
        assert "demo/verifier_room.json" in names
        assert "demo/reveal_grant.json" in names
        assert "demo/evidence_bundle.json" in names
        assert "demo/redaction_report.json" in names
        assert "demo/verifier_audit_log.jsonl" in names
