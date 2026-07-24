import json
import zipfile

from test_cli import run_cli


def test_cli_build_package_includes_active_named_verifier_grant(tmp_path):
    source = tmp_path / "source"
    out = tmp_path / "out"
    source.mkdir()
    (source / "private_strategy.md").write_text("private strategy evidence placeholder", encoding="utf-8")
    (source / "verification_summary.md").write_text("verification summary placeholder", encoding="utf-8")

    result = run_cli([
        "build-package",
        "--source", str(source),
        "--out", str(out),
        "--bitmap", "7187.bitmap",
        "--title", "Bitmap OS v13 Active Grant",
        "--version", "v13",
        "--description", "Named verifier active grant simulation",
        "--zip-name", "bitmap-os-v13.zip",
    ])

    assert result.returncode == 0, result.stderr
    demo = out / "demo"
    public_demo = out / "public" / "demo"
    expected = [
        "active_reveal_grant.json",
        "verifier_result.json",
        "active_verifier_audit_log.jsonl",
    ]
    for name in expected:
        assert (demo / name).exists(), name
        assert (public_demo / name).exists(), name

    active_grant = json.loads((demo / "active_reveal_grant.json").read_text(encoding="utf-8"))
    assert active_grant["active_grant_type"] == "bitmap-os-active-reveal-grant"
    assert active_grant["grant_status"] == "active-simulation"
    assert active_grant["recipient"]["verifier_id"] == "verifier-demo-001"
    assert active_grant["scope"]["disclosure_level"] == "L3_SELECTIVE_REVEAL"
    assert active_grant["scope"]["allow_raw_skills"] is False
    assert active_grant["scope"]["allow_credentials"] is False
    assert active_grant["scope"]["allow_candidate_pool"] is False
    assert active_grant["expires_at_utc"] is not None
    assert active_grant["evidence_bundle_hash"].startswith("sha256:")

    verifier_result = json.loads((demo / "verifier_result.json").read_text(encoding="utf-8"))
    assert verifier_result["verifier_result_type"] == "bitmap-os-verifier-result"
    assert verifier_result["verifier_id"] == "verifier-demo-001"
    assert verifier_result["result_status"] == "limited-verification-passed"
    assert verifier_result["checked_materials"] == [
        "hash_proof.json",
        "public_manifest.json",
        "evidence_bundle.json",
        "redaction_report.json",
    ]
    assert verifier_result["cannot_verify"]
    assert "raw APICKUP or gushen skill logic" in verifier_result["cannot_verify"]
    assert verifier_result["redaction_checks"]["raw_skills_removed"] is True
    assert verifier_result["grant_hash"].startswith("sha256:")

    audit_lines = (demo / "active_verifier_audit_log.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(audit_lines) == 3
    events = [json.loads(line) for line in audit_lines]
    assert [event["event_type"] for event in events] == [
        "active_grant_created",
        "redacted_evidence_reviewed",
        "verifier_result_issued",
    ]
    assert all(event["verifier_id"] == "verifier-demo-001" for event in events)

    manifest = json.loads((demo / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["active_reveal_grant"]["grant_status"] == "active-simulation"
    assert manifest["verifier_result"]["result_status"] == "limited-verification-passed"
    assert len(manifest["active_verifier_audit_log"]) == 3

    portal = (demo / "portal.html").read_text(encoding="utf-8")
    assert "Active Grant" in portal
    assert "verifier-demo-001" in portal
    assert "limited-verification-passed" in portal
    assert "active_reveal_grant.json" in portal
    assert "verifier_result.json" in portal
    assert "active_verifier_audit_log.jsonl" in portal

    with zipfile.ZipFile(out / "bitmap-os-v13.zip") as z:
        names = set(z.namelist())
        assert "demo/active_reveal_grant.json" in names
        assert "demo/verifier_result.json" in names
        assert "demo/active_verifier_audit_log.jsonl" in names
