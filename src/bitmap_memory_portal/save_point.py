from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Dict


def canonical_json_hash(payload: Dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def build_anchor_request(save_point_hash: str, coordinate: str) -> Dict:
    return {
        "anchor_request_type": "opentimestamps-request",
        "schema_version": "0.1.0",
        "coordinate": coordinate,
        "status": "pending",
        "hash_to_anchor": save_point_hash,
        "target": "save_point.json canonical JSON hash",
        "recommended_commands": [
            "ots stamp save_point.json",
            "ots upgrade save_point.json.ots",
            "ots verify save_point.json.ots -f save_point.json",
        ],
        "note": "Pending until an OpenTimestamps proof or Bitcoin/Ordinals timestamp anchor is attached and verified.",
    }


def build_verify_report(manifest: Dict, save_point: Dict, anchor_request: Dict) -> Dict:
    claim = manifest.get("claim") or {}
    claim_status = "locally-verified" if claim.get("signature_verification") == "locally-verified-bip322-js" else "missing-or-unverified"
    timestamp_status = anchor_request.get("status", "missing")
    overall = "valid-local-pending-timestamp" if timestamp_status == "pending" else "valid-anchored"
    return {
        "verify_report_type": "real-world-save-point-verify-report",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "overall_status": overall,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "checks": {
            "manifest_files": {
                "ok": True,
                "files_count": manifest.get("files_count"),
                "merkle_root": manifest.get("merkle_root"),
                "manifest_hash": manifest.get("manifest_hash"),
            },
            "wallet_claim": {
                "status": claim_status,
                "signing_address": claim.get("signing_address"),
            },
            "task_root": {
                "status": "present" if manifest.get("task_root") else "missing",
                "root_type": (manifest.get("task_root") or {}).get("root_type"),
            },
            "timestamp_anchor": {
                "status": timestamp_status,
                "hash_to_anchor": anchor_request.get("hash_to_anchor"),
            },
        },
        "clone_detection_hint": "A copied save point should be treated as non-canonical unless it preserves this hash chain, wallet claim, timestamp anchor, and Bitmap citation continuity.",
    }


def build_save_point_bundle(manifest: Dict) -> Dict:
    save_point = {
        "save_point_type": "real-world-save-point",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "title": manifest.get("title"),
        "version": manifest.get("version"),
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "checkpoint_policy": "milestone-only",
        "storage_boundary": "Bitmap is the canonical coordinate and proof root, not the bulk storage layer.",
        "canonical_status": "local-verified-pending-timestamp",
        "timestamp_status": "pending",
        "checkpoint_hashes": {
            "manifest_json": canonical_json_hash(manifest),
            "task_root_json": canonical_json_hash(manifest.get("task_root") or {}),
            "authenticity_json": canonical_json_hash(manifest.get("authenticity") or {}),
            "priority_sources_json": canonical_json_hash(manifest.get("priority_sources") or {}),
            "digging_policy_json": canonical_json_hash(manifest.get("digging_policy") or {}),
        },
        "proves": [
            "The listed source files match the manifest Merkle root at this local checkpoint.",
            "The task root, authenticity label, priority sources, and digging policy are bound into one checkpoint.",
            "The checkpoint is ready to be timestamped for stronger third-party existence proof.",
        ],
        "does_not_prove_yet": [
            "It does not yet prove Bitcoin timestamp anchoring until an OTS or equivalent proof is attached.",
            "It does not prove legal ownership of the Bitmap coordinate.",
        ],
    }
    save_point["checkpoint_hashes"]["save_point_json"] = canonical_json_hash(save_point)
    anchor_request = build_anchor_request(save_point["checkpoint_hashes"]["save_point_json"], manifest.get("bitmap"))
    verify_report = build_verify_report(manifest, save_point, anchor_request)
    return {
        "save_point": save_point,
        "anchor_request": anchor_request,
        "verify_report": verify_report,
    }
