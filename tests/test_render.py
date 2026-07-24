from pathlib import Path

from bitmap_memory_portal.core import build_manifest, build_proof
from bitmap_memory_portal.render import render_portal_html


def test_render_portal_html_contains_core_trust_root_fields(tmp_path):
    (tmp_path / "note.md").write_text("# Demo", encoding="utf-8")
    manifest = build_manifest(
        source_dir=tmp_path,
        bitmap="981213.bitmap",
        title="Demo Portal",
        version="v1",
        description="A first Bitmap trust-root demo",
    )
    proof = build_proof(manifest)

    html = render_portal_html(manifest, proof)

    assert "Demo Portal" in html
    assert "981213.bitmap" in html
    assert manifest["manifest_hash"] in html
    assert manifest["merkle_root"] in html
    assert "AI-readable Manifest" in html
    assert "Ask AI about this Bitmap" in html
    assert "ask_ai_prompt.md" in html
    assert "Do not claim verified chain ownership" in html
    assert "Source-backed facts" in html
    assert "note.md" in html
    assert "Root on Bitcoin / Bitmap, Remember with AI" in html
