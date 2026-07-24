import json
import zipfile

from test_cli import run_cli


def test_cli_build_package_includes_signed_claim_in_demo_public_zip_and_portal(tmp_path):
    source = tmp_path / "source"
    out = tmp_path / "out"
    claim = tmp_path / "claim_7187.json"
    source.mkdir()
    (source / "memory.md").write_text("hello signed claim", encoding="utf-8")
    claim.write_text(json.dumps({
        "claim_type": "bitmap-memory-portal-claim",
        "bitmap": "7187.bitmap",
        "steward": "Patoshi.bitmap",
        "claim_status": "signed-wallet-claim",
        "signing_address": "bc1ptest",
        "signature_method": "UniSat signMessage",
        "signature_verification": "not-locally-verified",
        "message": "Bitmap Memory Portal Claim",
        "signature": "sig-demo",
    }), encoding="utf-8")

    result = run_cli([
        "build-package",
        "--source", str(source),
        "--out", str(out),
        "--bitmap", "7187.bitmap",
        "--title", "Signed Claim Portal",
        "--version", "v4",
        "--description", "signed claim package",
        "--claim", str(claim),
        "--zip-name", "signed.zip",
    ])

    assert result.returncode == 0, result.stderr
    assert (out / "demo" / "claim_7187.json").exists()
    assert (out / "public" / "demo" / "claim_7187.json").exists()
    portal = (out / "demo" / "portal.html").read_text(encoding="utf-8")
    assert "Signed Wallet Claim" in portal
    assert "bc1ptest" in portal
    assert "UniSat signMessage" in portal
    assert "locally-invalid-bip322-js" in portal
    manifest = json.loads((out / "demo" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["claim"]["claim_status"] == "signed-wallet-claim"
    assert manifest["claim"]["signature_valid"] is False
    with zipfile.ZipFile(out / "signed.zip") as z:
        assert "demo/claim_7187.json" in set(z.namelist())
