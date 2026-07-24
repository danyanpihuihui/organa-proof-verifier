from bitmap_memory_portal.core import build_manifest, build_proof
from bitmap_memory_portal.render import render_portal_html


def test_manifest_and_portal_include_manual_signer_signature_and_anchor(tmp_path):
    (tmp_path / "note.md").write_text("hello", encoding="utf-8")

    manifest = build_manifest(
        source_dir=tmp_path,
        bitmap="981213.bitmap",
        title="Signed Demo",
        version="v1",
        signers=["bc1p-demo-signer"],
        signatures=[{"signer": "bc1p-demo-signer", "signature": "demo-signature", "method": "manual"}],
        anchors=[{"type": "opentimestamps", "status": "planned", "value": "ots://demo"}],
    )
    proof = build_proof(manifest)
    html = render_portal_html(manifest, proof)

    assert manifest["trusted_signers"] == ["bc1p-demo-signer"]
    assert manifest["signatures"][0]["signature"] == "demo-signature"
    assert manifest["anchors"][0]["type"] == "opentimestamps"
    assert proof["signatures_count"] == 1
    assert proof["anchors_count"] == 1
    assert "bc1p-demo-signer" in html
    assert "demo-signature" in html
    assert "opentimestamps" in html
