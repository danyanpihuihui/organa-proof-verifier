import json
import zipfile

from test_cli import run_cli


def test_cli_build_package_includes_bitmap_os_public_private_layers(tmp_path):
    source = tmp_path / "source"
    out = tmp_path / "out"
    source.mkdir()
    (source / "private_a_share_review.md").write_text("private APICKUP review placeholder", encoding="utf-8")
    (source / "public_bounty_note.md").write_text("public bounty quest note", encoding="utf-8")

    result = run_cli([
        "build-package",
        "--source", str(source),
        "--out", str(out),
        "--bitmap", "7187.bitmap",
        "--title", "Bitmap OS v11 Demo",
        "--version", "v11",
        "--description", "Public proof for private work",
        "--zip-name", "bitmap-os-v11.zip",
    ])

    assert result.returncode == 0, result.stderr
    demo = out / "demo"
    public_demo = out / "public" / "demo"
    expected = [
        "bitmap_os_thesis.json",
        "worker.json",
        "workflow.json",
        "task_inbox.json",
        "run_log.jsonl",
        "disclosure_policy.json",
        "public_manifest.json",
        "private_manifest.json",
        "hash_proof.json",
        "selective_reveal_policy.json",
    ]
    for name in expected:
        assert (demo / name).exists(), name
        assert (public_demo / name).exists(), name

    worker = json.loads((demo / "worker.json").read_text(encoding="utf-8"))
    assert worker["worker_id"] == "private-a-share-research-worker-v0"
    assert worker["default_disclosure_level"] == "L1_HASH_PROOF"
    assert worker["publish_requires_approval"] is True
    assert "apickup_skill" in worker["private_assets"]

    public_manifest = json.loads((demo / "public_manifest.json").read_text(encoding="utf-8"))
    assert public_manifest["public_manifest_type"] == "bitmap-os-public-manifest"
    assert public_manifest["principle"] == "Public coordination, private execution."
    assert public_manifest["worker_id"] == worker["worker_id"]
    assert public_manifest["default_disclosure_level"] == "L1_HASH_PROOF"
    assert "input_hash" in public_manifest["public_fields"]
    assert "apickup_skill" not in json.dumps(public_manifest)

    private_manifest = json.loads((demo / "private_manifest.json").read_text(encoding="utf-8"))
    assert private_manifest["private_manifest_type"] == "bitmap-os-private-manifest"
    assert private_manifest["visibility"] == "private-demo-placeholder"
    assert "apickup_skill" in private_manifest["private_assets"]
    assert private_manifest["not_for_public_release"] is True

    hash_proof = json.loads((demo / "hash_proof.json").read_text(encoding="utf-8"))
    assert hash_proof["hash_proof_type"] == "private-work-public-proof"
    assert hash_proof["proves"] == "A private worker run existed at this version without revealing execution know-how."
    assert hash_proof["private_payload_hash"].startswith("sha256:")
    assert hash_proof["public_manifest_hash"].startswith("sha256:")

    disclosure = json.loads((demo / "disclosure_policy.json").read_text(encoding="utf-8"))
    assert disclosure["disclosure_policy_type"] == "bitmap-os-disclosure-policy"
    assert disclosure["default_rule"] == "private-by-default"
    assert disclosure["levels"]["L0"]["name"] == "Private Only"
    assert disclosure["task_type_defaults"]["a_share_apickup_review"] == "L0_OR_L1"

    run_log = (demo / "run_log.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(run_log) == 2
    private_run = json.loads(run_log[0])
    public_run = json.loads(run_log[1])
    assert private_run["worker_id"] == "private-a-share-research-worker-v0"
    assert private_run["disclosure_level"] == "L1_HASH_PROOF"
    assert public_run["worker_id"] == "public-bounty-quest-worker-v0"
    assert public_run["disclosure_level"] == "L4_PUBLIC_PACKAGE"

    manifest = json.loads((demo / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["bitmap_os"]["product_thesis"] == "Public proof for private work."
    assert manifest["public_manifest"]["worker_id"] == "private-a-share-research-worker-v0"
    assert manifest["hash_proof"]["private_payload_hash"].startswith("sha256:")

    portal = (demo / "portal.html").read_text(encoding="utf-8")
    assert "Bitmap OS v0" in portal
    assert "Public proof for private work" in portal
    assert "disclosure_policy.json" in portal
    assert "hash_proof.json" in portal
    assert "private-a-share-research-worker-v0" in portal

    with zipfile.ZipFile(out / "bitmap-os-v11.zip") as z:
        names = set(z.namelist())
        assert "demo/public_manifest.json" in names
        assert "demo/private_manifest.json" in names
        assert "demo/disclosure_policy.json" in names
        assert "demo/hash_proof.json" in names
        assert "demo/run_log.jsonl" in names
