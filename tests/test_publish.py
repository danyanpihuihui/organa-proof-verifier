import json
from pathlib import Path

from bitmap_memory_portal.publish import publish_static_site


def test_publish_static_site_creates_public_layout(tmp_path):
    landing = tmp_path / "landing.html"
    demo_dir = tmp_path / "demo-src"
    out = tmp_path / "public"
    demo_dir.mkdir()
    landing.write_text('<a href="../demo-patoshi-bitmap-v2/portal.html">Open demo</a>', encoding="utf-8")
    (demo_dir / "portal.html").write_text("portal", encoding="utf-8")
    (demo_dir / "manifest.json").write_text(json.dumps({"bitmap": "981213.bitmap", "files_count": 1}), encoding="utf-8")
    (demo_dir / "proof.json").write_text(json.dumps({"ok": True}), encoding="utf-8")

    result = publish_static_site(
        landing_html=landing,
        demo_dir=demo_dir,
        out_dir=out,
        project_name="Bitmap Memory Portal",
    )

    assert (out / "index.html").exists()
    assert (out / "demo" / "portal.html").exists()
    assert (out / "demo" / "manifest.json").exists()
    assert (out / "demo" / "proof.json").exists()
    assert (out / "README_publish.md").exists()
    assert "demo/portal.html" in (out / "index.html").read_text()
    assert "Bitmap Memory Portal" in (out / "README_publish.md").read_text()
    assert result["index_html_path"] == str(out / "index.html")
    assert result["demo_files_copied"] >= 3
