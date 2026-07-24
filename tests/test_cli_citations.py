import json
import zipfile

from test_cli import run_cli


def test_cli_build_package_includes_bitmap_citations(tmp_path):
    source = tmp_path / "source"
    out = tmp_path / "out"
    citations = tmp_path / "citations.json"
    source.mkdir()
    (source / "memory.md").write_text("hello citations", encoding="utf-8")
    citations.write_text(json.dumps({
        "source_bitmap": "7187.bitmap",
        "schema_version": "0.1.0",
        "citations": [
            {
                "target_bitmap": "0.bitmap",
                "relation": "conceptual-anchor",
                "weight": "strong",
                "note": "Genesis-like reference for Bitmap citation graph examples.",
                "evidence": "manual-demo",
                "verification_status": "declared"
            }
        ]
    }), encoding="utf-8")

    result = run_cli([
        "build-package",
        "--source", str(source),
        "--out", str(out),
        "--bitmap", "7187.bitmap",
        "--title", "Citation Portal",
        "--version", "v6",
        "--description", "citation package",
        "--citations", str(citations),
        "--zip-name", "citations.zip",
    ])

    assert result.returncode == 0, result.stderr
    assert (out / "demo" / "citations.json").exists()
    assert (out / "public" / "demo" / "citations.json").exists()
    manifest = json.loads((out / "demo" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["citations"]["source_bitmap"] == "7187.bitmap"
    portal = (out / "demo" / "portal.html").read_text(encoding="utf-8")
    assert "Bitmap Citation Graph" in portal
    assert "0.bitmap" in portal
    assert "conceptual-anchor" in portal
    with zipfile.ZipFile(out / "citations.zip") as z:
        assert "demo/citations.json" in set(z.namelist())
