import json
import zipfile

from test_cli import run_cli


def test_cli_build_package_includes_bitmap_task_root_files(tmp_path):
    source = tmp_path / "source"
    out = tmp_path / "out"
    source.mkdir()
    (source / "memory.md").write_text("Patoshi memory and Bitmap research", encoding="utf-8")
    (source / "market.md").write_text("Bitmap marketplace notes", encoding="utf-8")

    result = run_cli([
        "build-package",
        "--source", str(source),
        "--out", str(out),
        "--bitmap", "7187.bitmap",
        "--title", "Patoshi Bitmap Task Root",
        "--version", "v8",
        "--description", "task root package",
        "--claim", "claims/claim_7187_v3_unisat.json",
        "--citations", "demo_citations_7187.json",
        "--zip-name", "task-root.zip",
    ])

    assert result.returncode == 0, result.stderr
    demo = out / "demo"
    for name in ["task_root.json", "priority_sources.json", "digging_policy.json"]:
        assert (demo / name).exists()
        assert (out / "public" / "demo" / name).exists()

    task_root = json.loads((demo / "task_root.json").read_text(encoding="utf-8"))
    assert task_root["root_type"] == "bitmap-task-root"
    assert task_root["coordinate"] == "7187.bitmap"
    assert task_root["task_identity"]["primary_task"] == "AI context coordinate for a specific person or task"
    assert task_root["boot_sequence"][:4] == [
        "task_root.json",
        "authenticity.json",
        "manifest.json",
        "proof.json",
    ]
    assert "priority_sources.json" in task_root["boot_sequence"]
    assert "digging_policy.json" in task_root["boot_sequence"]
    assert task_root["clone_boundary"]["copying_rule"] == "Public files may be copied; authenticity comes from the signed coordinate, version chain, and citation graph."

    priority_sources = json.loads((demo / "priority_sources.json").read_text(encoding="utf-8"))
    assert priority_sources["coordinate"] == "7187.bitmap"
    assert priority_sources["sources"][0]["path"] == "memory.md"
    assert priority_sources["sources"][0]["deep_dig_priority"] == "high"
    assert priority_sources["sources"][0]["trust_basis"] == "manifest-hash-verified"

    digging_policy = json.loads((demo / "digging_policy.json").read_text(encoding="utf-8"))
    assert digging_policy["policy_type"] == "bitmap-task-root-digging-policy"
    assert "Separate source-backed facts from working thesis." in digging_policy["agent_rules"]
    assert "Do not treat copied public files as the canonical root without checking signatures, version links, and citations." in digging_policy["clone_handling_rules"]

    manifest = json.loads((demo / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["task_root"]["root_type"] == "bitmap-task-root"
    assert manifest["priority_sources"]["sources"][0]["path"] == "memory.md"
    assert manifest["digging_policy"]["policy_type"] == "bitmap-task-root-digging-policy"

    portal = (demo / "portal.html").read_text(encoding="utf-8")
    assert "Bitmap Task Root" in portal
    assert "task_root.json" in portal
    assert "priority_sources.json" in portal
    assert "digging_policy.json" in portal

    with zipfile.ZipFile(out / "task-root.zip") as z:
        names = set(z.namelist())
        assert "demo/task_root.json" in names
        assert "demo/priority_sources.json" in names
        assert "demo/digging_policy.json" in names
