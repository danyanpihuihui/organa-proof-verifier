from bitmap_memory_portal.landing import render_landing_html


def test_render_landing_html_contains_public_project_story_and_cta():
    html = render_landing_html(
        demo_portal_path="output/demo-patoshi-bitmap-v2/portal.html",
        demo_manifest_hash="sha256:demo",
        demo_merkle_root="abc123",
        demo_files_count=12,
    )

    assert "Turn your Bitmap into a Memory Portal" in html
    assert "Root on Bitcoin / Bitmap, Remember with AI" in html
    assert "Human-readable portal" in html
    assert "AI-readable manifest" in html
    assert "Tamper verification" in html
    assert "Family Trust Root" in html
    assert "output/demo-patoshi-bitmap-v2/portal.html" in html
    assert "sha256:demo" in html
    assert "abc123" in html
    assert "12 files" in html
