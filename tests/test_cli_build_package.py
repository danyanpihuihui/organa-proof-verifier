import json
import zipfile

from test_cli import run_cli


def test_cli_build_package_generates_demo_landing_public_zip_and_verify(tmp_path):
    source = tmp_path / "source"
    out = tmp_path / "out"
    source.mkdir()
    (source / "memory.md").write_text("hello toolized portal", encoding="utf-8")

    result = run_cli([
        "build-package",
        "--source", str(source),
        "--out", str(out),
        "--bitmap", "981213.bitmap",
        "--title", "Toolized Agent Root Portal",
        "--version", "v-tool-1",
        "--description", "one command package",
        "--agent-name", "Toolized Memory Guardian",
        "--agent-role", "memory_curator",
        "--agent-skill", "archive-verification", "Archive Verification", "Verify hashes and roots.",
        "--project-name", "Bitmap Agent Root Portal",
    ])

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    public_dir = out / "public"
    assert (out / "demo" / "manifest.json").exists()
    assert (out / "demo" / "proof.json").exists()
    assert (out / "demo" / "agent.json").exists()
    assert (out / "demo" / "portal.html").exists()
    assert (out / "demo" / "ask_ai_prompt.md").exists()
    assert (out / "landing" / "landing.html").exists()
    assert (public_dir / "index.html").exists()
    assert (public_dir / "demo" / "agent.json").exists()
    assert (public_dir / "demo" / "ask_ai_prompt.md").exists()
    assert (out / "verify_ok.json").exists()
    assert (out / "bitmap-agent-root-portal.zip").exists()

    ask_ai_prompt = (out / "demo" / "ask_ai_prompt.md").read_text(encoding="utf-8")
    assert "981213.bitmap" in ask_ai_prompt
    assert "manifest.json" in ask_ai_prompt
    assert "proof.json" in ask_ai_prompt

    verify_payload = json.loads((out / "verify_ok.json").read_text())
    assert verify_payload["ok"] is True
    manifest = json.loads((out / "demo" / "manifest.json").read_text())
    assert manifest["agent_root"]["agent_name"] == "Toolized Memory Guardian"
    assert payload["verify_ok"] is True
    assert payload["zip_path"] == str(out / "bitmap-agent-root-portal.zip")

    with zipfile.ZipFile(out / "bitmap-agent-root-portal.zip") as z:
        names = set(z.namelist())
        assert "index.html" in names
        assert "demo/manifest.json" in names
        assert "demo/agent.json" in names
        assert "demo/portal.html" in names
        assert "demo/ask_ai_prompt.md" in names
