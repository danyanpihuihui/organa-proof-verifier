from bitmap_memory_portal.landing import render_landing_html


def test_render_landing_html_can_position_bitmap_agent_root():
    html = render_landing_html(
        demo_portal_path="demo/portal.html",
        demo_manifest_hash="sha256:demo",
        demo_merkle_root="abc123",
        demo_files_count=12,
        agent_name="Patoshi Bitmap Memory Guardian",
        demo_agent_root_type="bitmap-agent-root",
        demo_skills_count=4,
    )

    assert "Turn your Bitmap into an AI Agent Root" in html
    assert "Memory + Proofs + AI Roles + Skills" in html
    assert "Patoshi Bitmap Memory Guardian" in html
    assert "bitmap-agent-root" in html
    assert "4 skills" in html
    assert "Agent-readable root" in html
    assert "Privacy-aware trust policy" in html
    assert "not a storage layer" in html
