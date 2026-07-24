from test_cli import run_cli


def test_cli_landing_accepts_agent_root_summary_fields(tmp_path):
    out = tmp_path / "out"
    result = run_cli([
        "landing",
        "--out", str(out),
        "--demo-portal", "demo/portal.html",
        "--manifest-hash", "sha256:demo",
        "--merkle-root", "abc123",
        "--files-count", "12",
        "--agent-name", "Patoshi Bitmap Memory Guardian",
        "--agent-root-type", "bitmap-agent-root",
        "--skills-count", "4",
    ])

    assert result.returncode == 0, result.stderr
    html = (out / "landing.html").read_text()
    assert "Patoshi Bitmap Memory Guardian" in html
    assert "bitmap-agent-root" in html
    assert "4 skills" in html
