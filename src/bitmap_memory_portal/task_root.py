from __future__ import annotations

from pathlib import Path
from typing import Dict, List


def _source_priority(path: str) -> int:
    name = path.lower()
    if "memory" in name or "agent" in name or "trust" in name:
        return 0
    if "claim" in name or "proof" in name or "manifest" in name:
        return 1
    if "market" in name or "bitmap" in name:
        return 2
    return 3


def build_priority_sources(manifest: Dict) -> Dict:
    files = sorted(manifest.get("files") or [], key=lambda item: (_source_priority(item.get("path", "")), item.get("path", "")))
    sources: List[Dict] = []
    for index, item in enumerate(files):
        priority = "high" if index < 3 else "normal"
        sources.append(
            {
                "path": item.get("path"),
                "mime_type": item.get("mime_type"),
                "sha256": item.get("sha256"),
                "deep_dig_priority": priority,
                "trust_basis": "manifest-hash-verified",
                "use_for": [
                    "source-backed facts",
                    "task history reconstruction",
                    "high-signal context retrieval",
                ],
            }
        )
    return {
        "source_list_type": "bitmap-task-root-priority-sources",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "sources": sources,
    }


def build_digging_policy(manifest: Dict) -> Dict:
    return {
        "policy_type": "bitmap-task-root-digging-policy",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "agent_rules": [
            "Separate source-backed facts from working thesis.",
            "Check authenticity.json, manifest.json, proof.json, and agent.json before deep interpretation.",
            "Prefer high-priority sources before broad exploration.",
            "Cite source file names when making claims.",
            "Say what evidence is missing instead of filling gaps with plausible narrative.",
        ],
        "clone_handling_rules": [
            "Do not treat copied public files as the canonical root without checking signatures, version links, and citations.",
            "Treat the Bitmap coordinate as the task root entry point, not as the full data store.",
            "Canonicality depends on the signed coordinate, manifest version chain, timestamp anchors, and citation graph.",
        ],
        "deep_dig_frequency": {
            "high": "load first and revisit whenever the question touches identity, task history, or claims of truth",
            "normal": "load when the user question directly touches the file topic",
        },
    }


def build_task_root(manifest: Dict, authenticity: Dict, priority_sources: Dict, digging_policy: Dict) -> Dict:
    agent_root = manifest.get("agent_root") or {}
    return {
        "root_type": "bitmap-task-root",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "title": manifest.get("title"),
        "version": manifest.get("version"),
        "manifest_hash": manifest.get("manifest_hash"),
        "merkle_root": manifest.get("merkle_root"),
        "task_identity": {
            "primary_task": "AI context coordinate for a specific person or task",
            "agent_name": agent_root.get("agent_name"),
            "agent_root_type": agent_root.get("agent_root_type"),
        },
        "boot_sequence": [
            "task_root.json",
            "authenticity.json",
            "manifest.json",
            "proof.json",
            "agent.json",
            "priority_sources.json",
            "digging_policy.json",
            "claim_7187.json",
            "citations.json",
        ],
        "authenticity_status": authenticity.get("authenticity_status"),
        "priority_sources_count": len(priority_sources.get("sources") or []),
        "clone_boundary": {
            "copying_rule": "Public files may be copied; authenticity comes from the signed coordinate, version chain, and citation graph.",
            "canonicality_rule": "A clone is not canonical unless it can prove continuity with the coordinate's signed task root and manifest chain.",
        },
        "linked_files": {
            "authenticity": "authenticity.json",
            "manifest": "manifest.json",
            "proof": "proof.json",
            "agent": "agent.json",
            "priority_sources": "priority_sources.json",
            "digging_policy": "digging_policy.json",
            "claim": "claim_7187.json" if manifest.get("claim") else None,
            "citations": "citations.json" if manifest.get("citations") else None,
        },
    }


def build_task_root_bundle(manifest: Dict, authenticity: Dict) -> Dict:
    priority_sources = build_priority_sources(manifest)
    digging_policy = build_digging_policy(manifest)
    task_root = build_task_root(manifest, authenticity, priority_sources, digging_policy)
    return {
        "task_root": task_root,
        "priority_sources": priority_sources,
        "digging_policy": digging_policy,
    }