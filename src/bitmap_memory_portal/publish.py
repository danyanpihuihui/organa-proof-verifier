from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Dict


def _rewrite_landing_links(html: str) -> str:
    replacements = {
        "../demo-patoshi-bitmap-v2/portal.html": "demo/portal.html",
        "../demo-patoshi-agent-root-v1/portal.html": "demo/portal.html",
        "../demo/portal.html": "demo/portal.html",
    }
    for old, new in replacements.items():
        html = html.replace(old, new)
    return html


def _copy_demo_files(demo_dir: Path, target_demo: Path) -> int:
    target_demo.mkdir(parents=True, exist_ok=True)
    copied = 0
    for src in Path(demo_dir).iterdir():
        if src.is_file() and src.name in {"portal.html", "manifest.json", "proof.json", "agent.json", "ask_ai_prompt.md", "claim_7187.json", "citations.json", "authenticity.json", "task_root.json", "priority_sources.json", "digging_policy.json", "save_point.json", "anchor_request.json", "verify_report.json", "task_bounty.json", "reward_terms.json", "handoff_log.json", "bounty_verification.json", "bitmap_os_thesis.json", "worker.json", "workflow.json", "task_inbox.json", "run_log.jsonl", "disclosure_policy.json", "public_manifest.json", "private_manifest.json", "hash_proof.json", "selective_reveal_policy.json", "verifier_room.json", "reveal_grant.json", "evidence_bundle.json", "redaction_report.json", "verifier_audit_log.jsonl", "active_reveal_grant.json", "verifier_result.json", "active_verifier_audit_log.jsonl", "portal.png", "verify_ok.json", "verify_tampered.json"}:
            shutil.copy2(src, target_demo / src.name)
            copied += 1
    return copied


def _read_manifest_summary(target_demo: Path) -> Dict:
    p = target_demo / "manifest.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def publish_static_site(
    landing_html: Path,
    demo_dir: Path,
    out_dir: Path,
    project_name: str = "Bitmap Memory Portal",
) -> Dict:
    landing_html = Path(landing_html)
    demo_dir = Path(demo_dir)
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    target_demo = out_dir / "demo"

    html = _rewrite_landing_links(landing_html.read_text(encoding="utf-8"))
    (out_dir / "index.html").write_text(html, encoding="utf-8")
    copied = _copy_demo_files(demo_dir, target_demo)
    manifest = _read_manifest_summary(target_demo)
    agent_root = manifest.get("agent_root") or {}
    agent_name = agent_root.get("agent_name", "-")
    agent_root_type = agent_root.get("agent_root_type", "-")
    skills_count = len(agent_root.get("skills") or [])

    readme = f"""# {project_name} — Publish Package

This folder is a static publish-ready package.

## Files

- `index.html` — public landing page
- `demo/portal.html` — real demo Bitmap Memory Portal
- `demo/manifest.json` — AI-readable manifest and file hash list
- `demo/proof.json` — proof summary
- `demo/agent.json` — AI Agent Root definition with roles, skills, and trust policy
- `demo/ask_ai_prompt.md` — copy-ready prompt for asking an AI assistant about this Bitmap root
- `demo/claim_7187.json` — signed wallet claim if present
- `demo/citations.json` — Bitmap-to-Bitmap citation graph if present
- `demo/authenticity.json` — human/AI-readable authenticity label
- `demo/task_root.json` — canonical Bitmap Task Root boot sequence and clone boundary
- `demo/priority_sources.json` — source priority list for high-frequency AI digging
- `demo/digging_policy.json` — AI digging rules and clone-handling rules
- `demo/save_point.json` — real-world save point checkpoint summary
- `demo/anchor_request.json` — pending timestamp anchor request for the checkpoint hash
- `demo/verify_report.json` — local verification report for the save point
- `demo/task_bounty.json` — game-like bounty quest layer for urgent important tasks
- `demo/reward_terms.json` — unfunded/funded reward terms and payout rule
- `demo/handoff_log.json` — solver/sponsor/verifier handoff history
- `demo/bounty_verification.json` — bounty quest verification summary
- `demo/bitmap_os_thesis.json` — Bitmap OS v0 thesis: public proof for private work
- `demo/worker.json` — private worker definition with disclosure boundaries
- `demo/workflow.json` — public/private worker workflow graph
- `demo/task_inbox.json` — demo task inbox for private and public worker runs
- `demo/run_log.jsonl` — append-only worker run log
- `demo/disclosure_policy.json` — L0-L4 disclosure policy
- `demo/public_manifest.json` — public metadata and proof-safe fields
- `demo/private_manifest.json` — private asset placeholder manifest and hashes
- `demo/hash_proof.json` — public hash proof for private work
- `demo/selective_reveal_policy.json` — rules for verifier-only disclosure
- `demo/verifier_room.json` — L3 selective reveal room template
- `demo/reveal_grant.json` — draft verifier grant scope and recipient
- `demo/evidence_bundle.json` — redacted evidence bundle template
- `demo/redaction_report.json` — safety report for removed private fields
- `demo/verifier_audit_log.jsonl` — append-only verifier room audit events
- `demo/active_reveal_grant.json` — simulated active named-verifier grant
- `demo/verifier_result.json` — limited verification result for redacted evidence
- `demo/active_verifier_audit_log.jsonl` — active grant and verifier result audit trail
- `demo/portal.png` — screenshot preview if present

## Demo summary

- Bitmap: `{manifest.get('bitmap', '-')}`
- Title: `{manifest.get('title', '-')}`
- Version: `{manifest.get('version', '-')}`
- Files: `{manifest.get('files_count', '-')}`
- Manifest hash: `{manifest.get('manifest_hash', '-')}`
- Merkle root: `{manifest.get('merkle_root', '-')}`
- Agent name: `{agent_name}`
- Agent root type: `{agent_root_type}`
- Skills: `{skills_count}`

## Local preview

Open `index.html` in a browser.

## Deploy

You can upload this whole folder to GitHub Pages, Vercel, Netlify, Cloudflare Pages, or any static hosting service.
"""
    (out_dir / "README_publish.md").write_text(readme, encoding="utf-8")

    return {
        "public_dir": str(out_dir),
        "index_html_path": str(out_dir / "index.html"),
        "demo_portal_path": str(target_demo / "portal.html"),
        "readme_path": str(out_dir / "README_publish.md"),
        "demo_files_copied": copied,
        "manifest_hash": manifest.get("manifest_hash"),
        "files_count": manifest.get("files_count"),
        "agent_name": agent_name,
        "agent_root_type": agent_root_type,
        "skills_count": skills_count,
    }
