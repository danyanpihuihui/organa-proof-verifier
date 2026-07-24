from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict


def build_reward_terms(manifest: Dict) -> Dict:
    return {
        "reward_terms_type": "bounty-quest-reward-terms",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "reward_model": "bounty",
        "reward_asset": "unspecified-token-or-btc",
        "reward_status": "unfunded",
        "payout_rule": "verifier-approved",
        "partial_payout": True,
        "acceptance_criteria": [
            "source-backed answer",
            "all claims cite files or links",
            "verify_report remains valid",
            "new save_point generated after completion",
            "handoff_log records solver scope and completion status",
        ],
        "escrow_status": "not-configured",
    }


def build_handoff_log(manifest: Dict) -> Dict:
    return {
        "handoff_log_type": "bounty-quest-handoff-log",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "current_phase": "awaiting-sponsor-or-solver",
        "handoffs": [],
        "next_handoff_template": {
            "from": "owner-or-sponsor",
            "to": "solver",
            "save_point": manifest.get("version"),
            "assigned_scope": "define before work starts",
            "status": "pending",
        },
    }


def build_task_bounty(manifest: Dict, reward_terms: Dict) -> Dict:
    save_point = manifest.get("save_point") or {}
    return {
        "bounty_type": "real-world-bounty-quest",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "title": manifest.get("title"),
        "version": manifest.get("version"),
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "quest_status": "open-unfunded",
        "urgency": "high",
        "importance": "high",
        "owner_token_status": "insufficient-or-unspecified",
        "sponsor_needed": True,
        "required_roles": ["researcher", "verifier", "archivist"],
        "save_point_hash": (save_point.get("checkpoint_hashes") or {}).get("save_point_json"),
        "reward_status": reward_terms.get("reward_status"),
        "task_entry_files": [
            "save_point.json",
            "task_root.json",
            "priority_sources.json",
            "digging_policy.json",
            "reward_terms.json",
            "handoff_log.json",
        ],
        "quest_rule": "Treat this as a game-like bounty quest for an urgent important real-world task, but verify sources and save-point continuity before work or payout.",
    }


def build_bounty_verification(manifest: Dict, task_bounty: Dict, reward_terms: Dict, handoff_log: Dict) -> Dict:
    save_point_status = (manifest.get("verify_report") or {}).get("overall_status", "missing")
    reward_status = reward_terms.get("reward_status", "missing")
    if save_point_status == "valid-local-pending-timestamp" and reward_status == "unfunded":
        overall = "open-unfunded-local-valid"
    else:
        overall = "needs-review"
    return {
        "verification_type": "bounty-quest-verification",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "overall_status": overall,
        "checks": {
            "save_point": {
                "status": save_point_status,
                "save_point_hash": task_bounty.get("save_point_hash"),
            },
            "reward": {
                "status": reward_status,
                "payout_rule": reward_terms.get("payout_rule"),
            },
            "handoff": {
                "status": handoff_log.get("current_phase"),
                "handoffs_count": len(handoff_log.get("handoffs") or []),
            },
        },
        "next_steps": [
            "Find sponsor or fund bounty.",
            "Assign solver scope and record first handoff.",
            "Require verifier-approved output and a new save_point before payout.",
        ],
    }


def build_bounty_quest_bundle(manifest: Dict) -> Dict:
    reward_terms = build_reward_terms(manifest)
    handoff_log = build_handoff_log(manifest)
    task_bounty = build_task_bounty(manifest, reward_terms)
    bounty_verification = build_bounty_verification(manifest, task_bounty, reward_terms, handoff_log)
    return {
        "task_bounty": task_bounty,
        "reward_terms": reward_terms,
        "handoff_log": handoff_log,
        "bounty_verification": bounty_verification,
    }
