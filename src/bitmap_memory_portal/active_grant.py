from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, List


def canonical_json_hash(payload: Dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def build_active_reveal_grant(manifest: Dict) -> Dict:
    now = datetime.now(timezone.utc)
    evidence_bundle = manifest.get("evidence_bundle") or {}
    return {
        "active_grant_type": "bitmap-os-active-reveal-grant",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "grant_status": "active-simulation",
        "activated_at_utc": now.isoformat(),
        "expires_at_utc": (now + timedelta(days=7)).isoformat(),
        "recipient": {
            "verifier_id": "verifier-demo-001",
            "verifier_name": "Demo Verifier",
            "contact": "demo-verifier@example.invalid",
        },
        "scope": {
            "disclosure_level": "L3_SELECTIVE_REVEAL",
            "allowed_materials": [
                "hash_proof.json",
                "public_manifest.json",
                "evidence_bundle.json",
                "redaction_report.json",
            ],
            "allow_raw_skills": False,
            "allow_credentials": False,
            "allow_candidate_pool": False,
            "allow_private_memory": False,
        },
        "evidence_bundle_hash": canonical_json_hash(evidence_bundle),
        "activation_note": "Simulation grant only; no real external verifier access has been issued.",
    }


def build_verifier_result(manifest: Dict, active_grant: Dict) -> Dict:
    redaction_report = manifest.get("redaction_report") or {}
    return {
        "verifier_result_type": "bitmap-os-verifier-result",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "verifier_id": active_grant.get("recipient", {}).get("verifier_id"),
        "result_status": "limited-verification-passed",
        "issued_at_utc": datetime.now(timezone.utc).isoformat(),
        "grant_hash": canonical_json_hash(active_grant),
        "checked_materials": [
            "hash_proof.json",
            "public_manifest.json",
            "evidence_bundle.json",
            "redaction_report.json",
        ],
        "verified_claims": [
            "The private worker run is represented by a private payload hash.",
            "The evidence bundle is redacted and does not include raw skills or credentials.",
            "The disclosure level is L3 selective reveal, not public release.",
        ],
        "cannot_verify": [
            "raw APICKUP or gushen skill logic",
            "full private sample database",
            "candidate pool quality",
            "buy/sell discipline correctness",
        ],
        "redaction_checks": redaction_report.get("checks") or {},
        "verifier_note": "Limited verification passed for disclosure safety and hash continuity; this does not validate the private strategy edge itself.",
    }


def build_active_verifier_audit_log(active_grant: Dict, verifier_result: Dict) -> List[Dict]:
    now = datetime.now(timezone.utc).isoformat()
    verifier_id = active_grant.get("recipient", {}).get("verifier_id")
    return [
        {
            "event_type": "active_grant_created",
            "created_at_utc": active_grant.get("activated_at_utc") or now,
            "verifier_id": verifier_id,
            "grant_status": active_grant.get("grant_status"),
            "grant_hash": canonical_json_hash(active_grant),
        },
        {
            "event_type": "redacted_evidence_reviewed",
            "created_at_utc": now,
            "verifier_id": verifier_id,
            "evidence_bundle_hash": active_grant.get("evidence_bundle_hash"),
            "materials_count": len(active_grant.get("scope", {}).get("allowed_materials") or []),
        },
        {
            "event_type": "verifier_result_issued",
            "created_at_utc": verifier_result.get("issued_at_utc") or now,
            "verifier_id": verifier_id,
            "result_status": verifier_result.get("result_status"),
            "result_hash": canonical_json_hash(verifier_result),
        },
    ]


def build_active_grant_bundle(manifest: Dict) -> Dict:
    active_reveal_grant = build_active_reveal_grant(manifest)
    verifier_result = build_verifier_result(manifest, active_reveal_grant)
    active_verifier_audit_log = build_active_verifier_audit_log(active_reveal_grant, verifier_result)
    return {
        "active_reveal_grant": active_reveal_grant,
        "verifier_result": verifier_result,
        "active_verifier_audit_log": active_verifier_audit_log,
    }
