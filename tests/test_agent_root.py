from bitmap_memory_portal.core import build_agent_root


def test_build_agent_root_defaults_to_bitmap_memory_guardian():
    agent = build_agent_root(
        bitmap="981213.bitmap",
        title="Patoshi Bitmap Research Memory Portal",
        version="2026-05-agent-root",
    )

    assert agent["agent_root_type"] == "bitmap-agent-root"
    assert agent["schema_version"] == "0.1.0"
    assert agent["bitmap"] == "981213.bitmap"
    assert agent["agent_name"] == "Bitmap Memory Guardian"
    assert "memory_curator" in agent["roles"]
    assert "archive_verifier" in agent["roles"]
    assert agent["trust_policy"]["public_portal_rule"] == "Expose summaries, hashes, and proofs; keep sensitive source files private or encrypted."
    assert agent["skills"][0]["id"] == "family-memory-curation"
    assert agent["skills"][0]["visibility"] == "public-summary"
    assert agent["ai_readable_instructions"][0].startswith("Treat the Bitmap coordinate")


def test_build_agent_root_accepts_custom_roles_and_skills():
    agent = build_agent_root(
        bitmap="123.bitmap",
        title="Custom Portal",
        version="v2",
        agent_name="Investment Memory Operator",
        purpose="Preserve investment review workflows.",
        roles=["investment_reviewer"],
        skills=[{"id": "investment-review", "title": "Investment Review", "description": "Review original thesis versus later data."}],
    )

    assert agent["agent_name"] == "Investment Memory Operator"
    assert agent["purpose"] == "Preserve investment review workflows."
    assert agent["roles"] == ["investment_reviewer"]
    assert agent["skills"] == [{"id": "investment-review", "title": "Investment Review", "description": "Review original thesis versus later data.", "visibility": "public-summary"}]
