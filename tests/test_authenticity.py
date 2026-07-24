import json
import zipfile

from test_cli import run_cli


def test_cli_build_package_includes_authenticity_label(tmp_path):
    source = tmp_path / "source"
    out = tmp_path / "out"
    source.mkdir()
    (source / "memory.md").write_text("hello authenticity", encoding="utf-8")

    result = run_cli([
        "build-package",
        "--source", str(source),
        "--out", str(out),
        "--bitmap", "7187.bitmap",
        "--title", "Authenticity Portal",
        "--version", "v7",
        "--description", "authenticity label package",
        "--claim", "claims/claim_7187_v3_unisat.json",
        "--zip-name", "authenticity.zip",
    ])

    assert result.returncode == 0, result.stderr
    authenticity_path = out / "demo" / "authenticity.json"
    assert authenticity_path.exists()
    assert (out / "public" / "demo" / "authenticity.json").exists()
    authenticity = json.loads(authenticity_path.read_text(encoding="utf-8"))
    assert authenticity["coordinate"] == "7187.bitmap"
    assert authenticity["authenticity_status"] == "coordinate-claimed-and-wallet-verified"
    layers = {layer["layer"]: layer for layer in authenticity["evidence_layers"]}
    assert layers["coordinate"]["status"] == "declared"
    assert layers["file-integrity"]["status"] == "verified"
    assert layers["wallet-attestation"]["status"] == "locally-verified"
    assert layers["timestamp-anchor"]["status"] == "missing"
    assert "It does not prove every statement in the files is true." in authenticity["what_this_does_not_prove"]

    manifest = json.loads((out / "demo" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["authenticity"]["authenticity_status"] == "coordinate-claimed-and-wallet-verified"
    portal = (out / "demo" / "portal.html").read_text(encoding="utf-8")
    assert "Authenticity Label" in portal
    assert "coordinate-claimed-and-wallet-verified" in portal
    assert "timestamp-anchor" in portal
    assert "authenticity.json" in portal
    with zipfile.ZipFile(out / "authenticity.zip") as z:
        assert "demo/authenticity.json" in set(z.namelist())
