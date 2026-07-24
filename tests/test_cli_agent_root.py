import json
from pathlib import Path

from test_cli import run_cli


def test_cli_generate_with_agent_root_writes_agent_json_and_agent_section(tmp_path):
    source = tmp_path / "source"
    out = tmp_path / "out"
    source.mkdir()
    (source / "memory.md").write_text("hello bitmap agent", encoding="utf-8")

    result = run_cli([
        "generate",
        "--source", str(source),
        "--out", str(out),
        "--bitmap", "981213.bitmap",
        "--title", "Agent Root Demo Portal",
        "--version", "v-agent-1",
        "--description", "portal with agent root",
        "--agent-name", "Family Memory Guardian",
        "--agent-purpose", "Preserve family memories for future AI assistants.",
        "--agent-role", "memory_curator",
        "--agent-role", "archive_verifier",
        "--agent-skill", "family-memory-curation", "Family Memory Curation", "Organize trusted memory records.",
    ])

    assert result.returncode == 0, result.stderr
    agent_path = out / "agent.json"
    assert agent_path.exists()
    agent = json.loads(agent_path.read_text())
    manifest = json.loads((out / "manifest.json").read_text())
    portal = (out / "portal.html").read_text()
    assert agent["agent_name"] == "Family Memory Guardian"
    assert agent["roles"] == ["memory_curator", "archive_verifier"]
    assert manifest["agent_root"] == agent
    assert "AI Agent Root" in portal
    assert str(agent_path) in result.stdout
