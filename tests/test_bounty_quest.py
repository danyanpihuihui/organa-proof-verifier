import json
import zipfile

from test_cli import run_cli


def test_cli_build_package_includes_bounty_quest_files(tmp_path):
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
        "--title", "Patoshi Bounty Quest",
        "--version", "v10",
        "--description", "distributed bounty quest package",
        "--claim", "claims/claim_7187_v3_unisat.json",
        "--citations", "demo_citations_7187.json",
        "--zip-name", "bounty-quest.zip",
    ])

    assert result.returncode == 0, result.stderr
    demo = out / "demo"
    for name in ["task_bounty.json", "reward_terms.json", "handoff_log.json", "bounty_verification.json"]:
        assert (demo / name).exists()
        assert (out / "public" / "demo" / name).exists()

    task_bounty = json.loads((demo / "task_bounty.json").read_text(encoding="utf-8"))
    assert task_bounty["bounty_type"] == "real-world-bounty-quest"
    assert task_bounty["coordinate"] == "7187.bitmap"
    assert task_bounty["quest_status"] == "open-unfunded"
    assert task_bounty["urgency"] == "high"
    assert task_bounty["importance"] == "high"
    assert task_bounty["owner_token_status"] == "insufficient-or-unspecified"
    assert task_bounty["sponsor_needed"] is True
    assert "researcher" in task_bounty["required_roles"]
    assert "verifier" in task_bounty["required_roles"]
    assert task_bounty["save_point_hash"].startswith("sha256:")

    reward_terms = json.loads((demo / "reward_terms.json").read_text(encoding="utf-8"))
    assert reward_terms["reward_terms_type"] == "bounty-quest-reward-terms"
    assert reward_terms["reward_status"] == "unfunded"
    assert reward_terms["payout_rule"] == "verifier-approved"
    assert "new save_point generated after completion" in reward_terms["acceptance_criteria"]

    handoff_log = json.loads((demo / "handoff_log.json").read_text(encoding="utf-8"))
    assert handoff_log["handoff_log_type"] == "bounty-quest-handoff-log"
    assert handoff_log["current_phase"] == "awaiting-sponsor-or-solver"
    assert handoff_log["handoffs"] == []

    bounty_verification = json.loads((demo / "bounty_verification.json").read_text(encoding="utf-8"))
    assert bounty_verification["verification_type"] == "bounty-quest-verification"
    assert bounty_verification["overall_status"] == "open-unfunded-local-valid"
    assert bounty_verification["checks"]["save_point"]["status"] == "valid-local-pending-timestamp"
    assert bounty_verification["checks"]["reward"]["status"] == "unfunded"

    manifest = json.loads((demo / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["task_bounty"]["bounty_type"] == "real-world-bounty-quest"
    assert manifest["reward_terms"]["reward_status"] == "unfunded"
    assert manifest["handoff_log"]["current_phase"] == "awaiting-sponsor-or-solver"
    assert manifest["bounty_verification"]["overall_status"] == "open-unfunded-local-valid"

    portal = (demo / "portal.html").read_text(encoding="utf-8")
    assert "Bounty Quest" in portal
    assert "task_bounty.json" in portal
    assert "reward_terms.json" in portal
    assert "handoff_log.json" in portal
    assert "open-unfunded-local-valid" in portal

    with zipfile.ZipFile(out / "bounty-quest.zip") as z:
        names = set(z.namelist())
        assert "demo/task_bounty.json" in names
        assert "demo/reward_terms.json" in names
        assert "demo/handoff_log.json" in names
        assert "demo/bounty_verification.json" in names
