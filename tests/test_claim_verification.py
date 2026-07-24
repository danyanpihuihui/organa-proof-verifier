import json

from bitmap_memory_portal.claims import verify_claim_signature
from test_cli import run_cli


def test_verify_real_unisat_claim_signature_is_locally_verified():
    claim = json.loads(open("claims/claim_7187_v3_unisat.json", encoding="utf-8").read())

    verified = verify_claim_signature(claim)

    assert verified["signature_verification"] == "locally-verified-bip322-js"
    assert verified["signature_valid"] is True


def test_cli_build_package_upgrades_signed_claim_to_locally_verified(tmp_path):
    source = tmp_path / "source"
    out = tmp_path / "out"
    source.mkdir()
    (source / "memory.md").write_text("hello verified claim", encoding="utf-8")

    result = run_cli([
        "build-package",
        "--source", str(source),
        "--out", str(out),
        "--bitmap", "7187.bitmap",
        "--title", "Verified Claim Portal",
        "--version", "v5",
        "--description", "verified claim package",
        "--claim", "claims/claim_7187_v3_unisat.json",
        "--zip-name", "verified.zip",
    ])

    assert result.returncode == 0, result.stderr
    manifest = json.loads((out / "demo" / "manifest.json").read_text(encoding="utf-8"))
    claim = manifest["claim"]
    assert claim["signature_verification"] == "locally-verified-bip322-js"
    assert claim["signature_valid"] is True
    portal = (out / "demo" / "portal.html").read_text(encoding="utf-8")
    assert "locally-verified-bip322-js" in portal
