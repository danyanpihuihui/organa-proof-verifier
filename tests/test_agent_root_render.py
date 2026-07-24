from bitmap_memory_portal.core import build_agent_root, build_manifest, build_proof
from bitmap_memory_portal.render import render_portal_html


def test_manifest_and_proof_include_agent_root(tmp_path):
    (tmp_path / "memory.md").write_text("hello agent root", encoding="utf-8")
    agent_root = build_agent_root(
        bitmap="981213.bitmap",
        title="Agent Root Portal",
        version="v1",
        agent_name="Family Memory Guardian",
    )

    manifest = build_manifest(
        source_dir=tmp_path,
        bitmap="981213.bitmap",
        title="Agent Root Portal",
        version="v1",
        agent_root=agent_root,
    )
    proof = build_proof(manifest)
    html = render_portal_html(manifest, proof)

    assert manifest["agent_root"] == agent_root
    assert manifest["ai_readable_summary"]["agent_root_rule"] == "Load agent_root before interpreting this Bitmap Memory Portal as an AI-operable memory root."
    assert proof["agent_root_type"] == "bitmap-agent-root"
    assert proof["agent_name"] == "Family Memory Guardian"
    assert "AI Agent Root" in html
    assert "Family Memory Guardian" in html
    assert "family-memory-curation" in html
    assert "Expose summaries, hashes, and proofs" in html
