from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, List


def canonical_json_hash(payload: Dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _file_hash_lookup(manifest: Dict) -> Dict[str, str]:
    return {item.get("path"): item.get("sha256") for item in (manifest.get("files") or [])}


def build_disclosure_policy(manifest: Dict) -> Dict:
    return {
        "disclosure_policy_type": "bitmap-os-disclosure-policy",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "principle": "Public coordination, private execution.",
        "default_rule": "private-by-default",
        "publish_requires_approval": True,
        "levels": {
            "L0": {
                "name": "Private Only",
                "meaning": "Do not publish content, metadata, or hash proof.",
                "default_for": ["strategy skills", "customer data", "internal SOP", "alpha sources"],
            },
            "L1": {
                "name": "Hash Proof",
                "meaning": "Publish only hashes, timestamps, and existence proof.",
                "default_for": ["private research reports", "A-share reviews", "contracts"],
            },
            "L2": {
                "name": "Metadata Proof",
                "meaning": "Publish task type, status, version, and verification summary without execution details.",
                "default_for": ["internal task audit", "partner progress proof"],
            },
            "L3": {
                "name": "Selective Reveal",
                "meaning": "Reveal scoped evidence to named verifiers or collaborators.",
                "default_for": ["due diligence", "paid audit", "verifier review"],
            },
            "L4": {
                "name": "Public Package",
                "meaning": "Publish the complete task package.",
                "default_for": ["bounty quests", "open research", "public articles"],
            },
        },
        "task_type_defaults": {
            "a_share_apickup_review": "L0_OR_L1",
            "company_internal_workflow": "L1_OR_L2",
            "public_bounty_quest": "L4",
            "public_research_report": "L3_OR_L4",
            "published_article": "L4",
        },
        "never_publish_by_default": [
            "skill bodies",
            "memory entries",
            "tool credentials",
            "private sample databases",
            "candidate pools",
            "buy/sell discipline",
            "customer raw data",
        ],
    }


def build_private_worker(manifest: Dict) -> Dict:
    return {
        "worker_type": "bitmap-os-worker",
        "schema_version": "0.1.0",
        "worker_id": "private-a-share-research-worker-v0",
        "coordinate": manifest.get("bitmap"),
        "mission": "Run private A-share research, review, and strategy workflows while publishing only proof-safe metadata.",
        "owner": "Patoshi Bitmap",
        "status": "active-draft",
        "visibility": "private",
        "default_disclosure_level": "L1_HASH_PROOF",
        "publish_requires_approval": True,
        "inputs": [
            "market data snapshots",
            "private review notes",
            "private sample database",
            "manual Telegram instructions",
        ],
        "tools": ["local files", "market data APIs", "Hermes worker runtime"],
        "public_fields": [
            "worker_id",
            "task_date",
            "run_status",
            "input_hash",
            "output_hash",
            "timestamp_status",
            "verification_summary",
            "disclosure_level",
        ],
        "private_assets": [
            "apickup_skill",
            "gushen_skill",
            "sample_database",
            "candidate_pool",
            "buy_sell_discipline",
            "review_notes",
        ],
        "approval_policy": {
            "publish_public_package": "explicit-human-approval-required",
            "selective_reveal": "named-recipient-and-scope-required",
            "private_run": "allowed",
        },
        "outputs": ["private review report", "hash proof", "optional public article after approval"],
        "verification": {
            "public": "hashes and run status only",
            "private": "full report and strategy trace remain private",
        },
    }


def build_public_bounty_worker(manifest: Dict) -> Dict:
    return {
        "worker_type": "bitmap-os-worker",
        "schema_version": "0.1.0",
        "worker_id": "public-bounty-quest-worker-v0",
        "coordinate": manifest.get("bitmap"),
        "mission": "Publish public bounty tasks with open acceptance criteria, handoff, and verifier-approved payout rules.",
        "visibility": "public",
        "default_disclosure_level": "L4_PUBLIC_PACKAGE",
        "public_assets": ["task_bounty.json", "reward_terms.json", "handoff_log.json", "bounty_verification.json"],
        "private_assets": ["solver private method may remain private unless reward terms require disclosure"],
    }


def build_workflow(manifest: Dict, private_worker: Dict, public_worker: Dict) -> Dict:
    return {
        "workflow_type": "bitmap-os-workflow",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "workflow_id": "bitmap-os-v11-public-private-demo",
        "principle": "Public coordination, private execution.",
        "nodes": [
            {
                "worker_id": private_worker["worker_id"],
                "role": "private execution worker",
                "default_disclosure_level": private_worker["default_disclosure_level"],
            },
            {
                "worker_id": "bitmap-verification-worker-v0",
                "role": "verifier",
                "default_disclosure_level": "L2_METADATA_PROOF",
            },
            {
                "worker_id": "bitmap-archivist-worker-v0",
                "role": "save point archivist",
                "default_disclosure_level": "L1_HASH_PROOF",
            },
            {
                "worker_id": public_worker["worker_id"],
                "role": "public bounty worker",
                "default_disclosure_level": public_worker["default_disclosure_level"],
            },
        ],
        "edges": [
            [private_worker["worker_id"], "bitmap-verification-worker-v0"],
            ["bitmap-verification-worker-v0", "bitmap-archivist-worker-v0"],
            ["bitmap-archivist-worker-v0", public_worker["worker_id"]],
        ],
        "handoff_rule": "Private work can produce public proof; public release requires an explicit disclosure level decision.",
    }


def build_task_inbox(manifest: Dict) -> Dict:
    return {
        "task_inbox_type": "bitmap-os-task-inbox",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "tasks": [
            {
                "task_id": "private-a-share-review-demo",
                "title": "Run private A-share research worker and publish hash proof only.",
                "assigned_worker": "private-a-share-research-worker-v0",
                "default_disclosure_level": "L1_HASH_PROOF",
                "status": "completed-demo",
            },
            {
                "task_id": "public-bounty-quest-demo",
                "title": "Publish a public bounty quest package.",
                "assigned_worker": "public-bounty-quest-worker-v0",
                "default_disclosure_level": "L4_PUBLIC_PACKAGE",
                "status": "open-unfunded-demo",
            },
        ],
    }


def build_private_manifest(manifest: Dict, private_worker: Dict) -> Dict:
    file_hashes = _file_hash_lookup(manifest)
    return {
        "private_manifest_type": "bitmap-os-private-manifest",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "visibility": "private-demo-placeholder",
        "not_for_public_release": True,
        "worker_id": private_worker["worker_id"],
        "private_assets": private_worker["private_assets"],
        "private_source_hashes": file_hashes,
        "redaction_note": "This demo names private asset categories but does not include real APICKUP rules, samples, candidate pools, or buy/sell discipline.",
    }


def build_public_manifest(manifest: Dict, private_worker: Dict) -> Dict:
    return {
        "public_manifest_type": "bitmap-os-public-manifest",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "title": manifest.get("title"),
        "version": manifest.get("version"),
        "principle": "Public coordination, private execution.",
        "worker_id": private_worker["worker_id"],
        "default_disclosure_level": private_worker["default_disclosure_level"],
        "public_fields": private_worker["public_fields"],
        "public_status": {
            "run_status": "completed-demo",
            "timestamp_status": "pending",
            "verification_summary": "private worker run represented by hash proof only",
        },
        "excluded_private_assets_count": len(private_worker["private_assets"]),
    }


def build_hash_proof(manifest: Dict, public_manifest: Dict, private_manifest: Dict) -> Dict:
    return {
        "hash_proof_type": "private-work-public-proof",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "proves": "A private worker run existed at this version without revealing execution know-how.",
        "does_not_reveal": [
            "APICKUP scoring rules",
            "gushen model details",
            "sample database",
            "candidate pool",
            "buy/sell discipline",
        ],
        "public_manifest_hash": canonical_json_hash(public_manifest),
        "private_payload_hash": canonical_json_hash(private_manifest),
        "timestamp_status": "pending",
        "recommended_anchor": "OpenTimestamps or equivalent Bitcoin timestamp proof",
    }


def build_selective_reveal_policy(manifest: Dict) -> Dict:
    return {
        "selective_reveal_policy_type": "bitmap-os-selective-reveal-policy",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "default_status": "disabled-until-approved",
        "requirements": [
            "named verifier or collaborator",
            "explicit reveal scope",
            "expiration time",
            "audit log entry",
            "no credential or raw skill leakage unless separately approved",
        ],
        "allowed_targets": ["verifier", "collaborator", "customer", "investor-after-approval"],
    }


def build_run_log_lines(manifest: Dict, hash_proof: Dict) -> List[Dict]:
    now = datetime.now(timezone.utc).isoformat()
    return [
        {
            "run_id": "private-a-share-review-demo-run",
            "worker_id": "private-a-share-research-worker-v0",
            "started_at_utc": now,
            "task": "private A-share research review demo",
            "status": "completed-demo",
            "disclosure_level": "L1_HASH_PROOF",
            "output_path": "private_manifest.json",
            "verification": {
                "public_proof": "hash_proof.json",
                "private_payload_hash": hash_proof["private_payload_hash"],
            },
        },
        {
            "run_id": "public-bounty-quest-demo-run",
            "worker_id": "public-bounty-quest-worker-v0",
            "started_at_utc": now,
            "task": "public bounty quest package demo",
            "status": (manifest.get("task_bounty") or {}).get("quest_status", "open-unfunded"),
            "disclosure_level": "L4_PUBLIC_PACKAGE",
            "output_path": "task_bounty.json",
            "verification": {
                "bounty_verification": "bounty_verification.json",
            },
        },
    ]


def build_bitmap_os_bundle(manifest: Dict) -> Dict:
    private_worker = build_private_worker(manifest)
    public_worker = build_public_bounty_worker(manifest)
    workflow = build_workflow(manifest, private_worker, public_worker)
    task_inbox = build_task_inbox(manifest)
    disclosure_policy = build_disclosure_policy(manifest)
    private_manifest = build_private_manifest(manifest, private_worker)
    public_manifest = build_public_manifest(manifest, private_worker)
    hash_proof = build_hash_proof(manifest, public_manifest, private_manifest)
    selective_reveal_policy = build_selective_reveal_policy(manifest)
    run_log = build_run_log_lines(manifest, hash_proof)
    bitmap_os_thesis = {
        "bitmap_os_type": "bitmap-os-v0-product-thesis",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "version": manifest.get("version"),
        "product_thesis": "Public proof for private work.",
        "principle": "Public coordination, private execution.",
        "private_worker": private_worker["worker_id"],
        "public_worker": public_worker["worker_id"],
        "disclosure_levels": ["L0", "L1", "L2", "L3", "L4"],
    }
    return {
        "bitmap_os": bitmap_os_thesis,
        "worker": private_worker,
        "public_bounty_worker": public_worker,
        "workflow": workflow,
        "task_inbox": task_inbox,
        "run_log": run_log,
        "disclosure_policy": disclosure_policy,
        "public_manifest": public_manifest,
        "private_manifest": private_manifest,
        "hash_proof": hash_proof,
        "selective_reveal_policy": selective_reveal_policy,
    }
