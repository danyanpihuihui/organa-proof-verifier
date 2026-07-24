import json
import subprocess
import sys
from pathlib import Path


def run_cli(args):
    cmd = [sys.executable, "-m", "bitmap_memory_portal.cli"] + args
    return subprocess.run(cmd, text=True, capture_output=True, cwd=Path(__file__).parents[1], env={"PYTHONPATH": "src"})


def test_cli_generate_writes_manifest_proof_and_portal(tmp_path):
    source = tmp_path / "source"
    out = tmp_path / "out"
    source.mkdir()
    (source / "memory.md").write_text("hello bitmap", encoding="utf-8")

    result = run_cli([
        "generate",
        "--source", str(source),
        "--out", str(out),
        "--bitmap", "981213.bitmap",
        "--title", "CLI Demo Portal",
        "--version", "v1",
        "--description", "cli generated demo",
    ])

    assert result.returncode == 0, result.stderr
    manifest_path = out / "manifest.json"
    proof_path = out / "proof.json"
    html_path = out / "portal.html"
    assert manifest_path.exists()
    assert proof_path.exists()
    assert html_path.exists()
    manifest = json.loads(manifest_path.read_text())
    assert manifest["bitmap"] == "981213.bitmap"
    assert manifest["files_count"] == 1
    assert "CLI Demo Portal" in html_path.read_text()
    assert str(html_path) in result.stdout


def test_cli_verify_returns_zero_for_valid_folder_and_nonzero_for_changed_folder(tmp_path):
    source = tmp_path / "source"
    out = tmp_path / "out"
    source.mkdir()
    (source / "memory.md").write_text("hello bitmap", encoding="utf-8")
    gen = run_cli([
        "generate", "--source", str(source), "--out", str(out),
        "--bitmap", "981213.bitmap", "--title", "CLI Demo Portal", "--version", "v1"
    ])
    assert gen.returncode == 0, gen.stderr

    ok = run_cli(["verify", "--source", str(source), "--manifest", str(out / "manifest.json")])
    assert ok.returncode == 0, ok.stderr
    assert json.loads(ok.stdout)["ok"] is True

    (source / "memory.md").write_text("tampered", encoding="utf-8")
    bad = run_cli(["verify", "--source", str(source), "--manifest", str(out / "manifest.json")])
    assert bad.returncode == 2
    payload = json.loads(bad.stdout)
    assert payload["ok"] is False
    assert payload["changed_files"][0]["path"] == "memory.md"


def test_cli_landing_writes_public_landing_page(tmp_path):
    out = tmp_path / "out"
    result = run_cli([
        "landing",
        "--out", str(out),
        "--demo-portal", "demo/portal.html",
        "--manifest-hash", "sha256:demo",
        "--merkle-root", "abc123",
        "--files-count", "12",
    ])

    assert result.returncode == 0, result.stderr
    landing = out / "landing.html"
    assert landing.exists()
    html = landing.read_text()
    assert "Turn your Bitmap into a Memory Portal" in html
    assert "demo/portal.html" in html
    assert str(landing) in result.stdout


def test_cli_publish_writes_static_public_directory(tmp_path):
    landing = tmp_path / "landing.html"
    demo = tmp_path / "demo"
    out = tmp_path / "public"
    demo.mkdir()
    landing.write_text('<a href="../demo-patoshi-bitmap-v2/portal.html">demo</a>', encoding="utf-8")
    (demo / "portal.html").write_text("portal", encoding="utf-8")
    (demo / "manifest.json").write_text(json.dumps({"bitmap": "981213.bitmap"}), encoding="utf-8")
    (demo / "proof.json").write_text("{}", encoding="utf-8")

    result = run_cli([
        "publish",
        "--landing", str(landing),
        "--demo-dir", str(demo),
        "--out", str(out),
    ])

    assert result.returncode == 0, result.stderr
    assert (out / "index.html").exists()
    assert (out / "demo" / "portal.html").exists()
    assert (out / "README_publish.md").exists()
    assert "demo/portal.html" in (out / "index.html").read_text()
