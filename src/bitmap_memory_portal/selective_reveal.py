from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Dict, List


def build_verifier_room(manifest: Dict) -> Dict:
    return {
        "verifier_room_type": "bitmap-os-selective-reveal-room",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "disclosure_level": "L3_SELECTIVE_REVEAL",
        "room_status": "template-not-granted",
        "default_access": "deny",
        "requires_named_verifier": True,
        "eligible_workers": ["private-a-share-research-worker-v0"],
        "purpose": "Allow a named verifier to inspect a redacted evidence bundle without exposing raw skills, credentials, or candidate pools.",
        "entry_files": [
            "reveal_grant.json",
            "evidence_bundle.json",
            "redaction_report.json",
            "verifier_audit_log.jsonl",
        ],
    }


def build_reveal_grant(manifest: Dict) -> Dict:
    return {
        "reveal_grant_type": "bitmap-os-reveal-grant",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "grant_status": "draft-template",
        "recipient": {
            "verifier_id": "unassigned",
            "verifier_name": None,
            "contact": None,
        },
        "scope": {
            "disclosure_level": "L3_SELECTIVE_REVEAL",
            "allowed_materials": [
                "redacted evidence bundle",
                "hash proof",
                "public manifest",
                "run status",
                "verification summary",
            ],
            "allow_raw_skills": False,
            "allow_credentials": False,
            "allow_candidate_pool": False,
            "allow_private_memory": False,
        },
        "expires_at_utc": None,
        "activation_rule": "A human owner must assign verifier identity, scope, and expiration before this grant becomes active.",
    }


def build_evidence_bundle(manifest: Dict) -> Dict:
    hash_proof = manifest.get("hash_proof") or {}
    return {
        "evidence_bundle_type": "bitmap-os-redacted-evidence-bundle",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "bundle_status": "redacted-template",
        "source_private_payload_hash": hash_proof.get("private_payload_hash"),
        "revealed_fields": [
            "worker_id",
            "run_id",
            "run_status",
            "input_hash",
            "output_hash",
            "verification_summary",
        ],
        "redacted_fields": [
            "apickup_skill",
            "gushen_skill",
            "sample_database",
            "candidate_pool",
            "buy_sell_discipline",
            "raw_private_memory",
            "tool_credentials",
        ],
        "evidence_items": [
            {
                "item_id": "private-worker-run-proof",
                "visibility": "redacted",
                "hash": hash_proof.get("private_payload_hash"),
                "summary": "Private worker run exists and is bound to this hash proof.",
            }
        ],
    }


def build_redaction_report(evidence_bundle: Dict) -> Dict:
    return {
        "redaction_report_type": "bitmap-os-redaction-report",
        "schema_version": "0.1.0",
        "coordinate": evidence_bundle.get("coordinate"),
        "redaction_status": "safe-template",
        "checks": {
            "raw_skills_removed": True,
            "credentials_removed": True,
            "candidate_pool_removed": True,
            "private_memory_removed": True,
            "only_hashes_and_summaries_revealed": True,
        },
        "redacted_fields": evidence_bundle.get("redacted_fields") or [],
        "review_note": "Template evidence bundle is safe because it carries proof references and redaction categories, not live strategy content.",
    }


def build_verifier_audit_log(reveal_grant: Dict) -> List[Dict]:
    return [
        {
            "event_type": "verifier_room_template_created",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "coordinate": reveal_grant.get("coordinate"),
            "disclosure_level": "L3_SELECTIVE_REVEAL",
            "grant_status": reveal_grant.get("grant_status"),
            "verifier_id": reveal_grant.get("recipient", {}).get("verifier_id"),
            "note": "No verifier access has been granted yet; this is a room and grant template.",
        }
    ]


def build_selective_reveal_bundle(manifest: Dict) -> Dict:
    verifier_room = build_verifier_room(manifest)
    reveal_grant = build_reveal_grant(manifest)
    evidence_bundle = build_evidence_bundle(manifest)
    redaction_report = build_redaction_report(evidence_bundle)
    verifier_audit_log = build_verifier_audit_log(reveal_grant)
    return {
        "verifier_room": verifier_room,
        "reveal_grant": reveal_grant,
        "evidence_bundle": evidence_bundle,
        "redaction_report": redaction_report,
        "verifier_audit_log": verifier_audit_log,
    }
