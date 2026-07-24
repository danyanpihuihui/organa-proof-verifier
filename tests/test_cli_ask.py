import json

from test_cli import run_cli


def test_cli_ask_writes_ai_context_pack_from_manifest_proof_agent_and_sources(tmp_path):
    source = tmp_path / "source"
    demo = tmp_path / "demo"
    out = tmp_path / "ask.md"
    source.mkdir()
    (source / "profile.md").write_text("7187 is a Bitmap trust root.", encoding="utf-8")
    (source / "memory.md").write_text("Human memory belongs in the portal.", encoding="utf-8")

    generated = run_cli([
        "generate",
        "--source", str(source),
        "--out", str(demo),
        "--bitmap", "7187.bitmap",
        "--title", "7187 Bitmap Portal",
        "--version", "v1",
        "--description", "test portal",
        "--agent-name", "7187 Guardian",
    ])
    assert generated.returncode == 0, generated.stderr

    result = run_cli([
        "ask",
        "--source", str(source),
        "--manifest", str(demo / "manifest.json"),
        "--proof", str(demo / "proof.json"),
        "--agent", str(demo / "agent.json"),
        "--question", "What does this Bitmap represent?",
        "--out", str(out),
    ])

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ask_context_path"] == str(out)
    assert payload["included_sources"] == 2
    context = out.read_text(encoding="utf-8")
    assert "# Ask Context Pack: 7187.bitmap" in context
    assert "What does this Bitmap represent?" in context
    assert "manifest.json" in context
    assert "proof.json" in context
    assert "agent.json" in context
    assert "7187 Guardian" in context
    assert "7187 is a Bitmap trust root." in context
    assert "Human memory belongs in the portal." in context
    assert "Do not claim verified chain ownership" in context
    assert "Do not claim verified Bitcoin block attributes" in context
    assert "Do not translate the Bitmap coordinate into a specific Bitcoin block fact" in context
    assert "Say: this portal declares 7187.bitmap as a trust-root coordinate" in context
    assert "Do not infer wallet balances, trades, or real-world identity" in context
    assert "Source-backed facts" in context
    assert "Working thesis" in context
    assert "Unverified assumptions" in context
