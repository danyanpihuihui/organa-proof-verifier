import json
from pathlib import Path

from bitmap_memory_portal.publish import publish_static_site


def test_publish_static_site_copies_agent_json_and_documents_agent_root(tmp_path):
    landing = tmp_path / "landing.html"
    demo_dir = tmp_path / "demo-src"
    out = tmp_path / "public"
    demo_dir.mkdir()
    landing.write_text('<a href="../demo-patoshi-agent-root-v1/portal.html">Open agent root</a>', encoding="utf-8")
    (demo_dir / "portal.html").write_text("portal", encoding="utf-8")
    (demo_dir / "manifest.json").write_text(json.dumps({
        "bitmap": "981213.bitmap",
        "title": "Agent Root Portal",
        "version": "v1",
        "files_count": 1,
        "manifest_hash": "sha256:demo",
        "merkle_root": "abc123",
        "agent_root": {"agent_name": "Patoshi Bitmap Memory Guardian", "agent_root_type": "bitmap-agent-root"},
    }), encoding="utf-8")
    (demo_dir / "proof.json").write_text(json.dumps({"ok": True}), encoding="utf-8")
    (demo_dir / "agent.json").write_text(json.dumps({"agent_name": "Patoshi Bitmap Memory Guardian"}), encoding="utf-8")

    result = publish_static_site(
        landing_html=landing,
        demo_dir=demo_dir,
        out_dir=out,
        project_name="Bitmap Agent Root Portal",
    )

    assert (out / "demo" / "agent.json").exists()
    readme = (out / "README_publish.md").read_text()
    assert "demo/agent.json" in readme
    assert "Patoshi Bitmap Memory Guardian" in readme
    assert "bitmap-agent-root" in readme
    assert "demo/portal.html" in (out / "index.html").read_text()
    assert result["agent_name"] == "Patoshi Bitmap Memory Guardian"
