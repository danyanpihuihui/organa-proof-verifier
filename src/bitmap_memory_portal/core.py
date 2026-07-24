from __future__ import annotations

import hashlib
import json
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def merkle_root(leaves: Iterable[str]) -> str:
    level = list(leaves)
    if not level:
        return hashlib.sha256(b"").hexdigest()
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level = []
        for i in range(0, len(level), 2):
            next_level.append(
                hashlib.sha256(bytes.fromhex(level[i]) + bytes.fromhex(level[i + 1])).hexdigest()
            )
        level = next_level
    return level[0]


def _canonical_manifest_hash(manifest_without_hash: Dict) -> str:
    payload = json.dumps(manifest_without_hash, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def iter_files(source_dir: Path) -> List[Path]:
    source_dir = Path(source_dir)
    return sorted([p for p in source_dir.rglob("*") if p.is_file() and not p.name.startswith(".")], key=lambda p: p.relative_to(source_dir).as_posix())


def build_agent_root(
    bitmap: str,
    title: str,
    version: str,
    agent_name: str = "Bitmap Memory Guardian",
    purpose: Optional[str] = None,
    roles: Optional[List[str]] = None,
    skills: Optional[List[Dict]] = None,
) -> Dict:
    normalized_skills = []
    default_skills = [
        {
            "id": "family-memory-curation",
            "title": "Family Memory Curation",
            "description": "Organize human memories, letters, photos, and archive notes into a verifiable long-term memory root.",
        },
        {
            "id": "archive-verification",
            "title": "Archive Verification",
            "description": "Recompute hashes, check Merkle roots, and report changed, missing, or unexpected files.",
        },
        {
            "id": "legacy-storytelling",
            "title": "Legacy Storytelling",
            "description": "Turn verified records into warm human-readable stories while preserving source provenance.",
        },
    ]
    for skill in (skills or default_skills):
        item = dict(skill)
        item.setdefault("visibility", "public-summary")
        normalized_skills.append(item)

    return {
        "agent_root_type": "bitmap-agent-root",
        "schema_version": "0.1.0",
        "bitmap": bitmap,
        "title": title,
        "version": version,
        "agent_name": agent_name,
        "purpose": purpose or "Preserve, verify, and explain the memory root attached to this Bitmap coordinate for future AI assistants and human heirs.",
        "roles": roles or ["memory_curator", "archive_verifier", "family_storyteller"],
        "skills": normalized_skills,
        "trust_policy": {
            "public_portal_rule": "Expose summaries, hashes, and proofs; keep sensitive source files private or encrypted.",
            "verification_rule": "Do not trust narrative claims until manifest_hash, file hashes, and Merkle root are recomputed against the source archive.",
            "mutation_rule": "New memories should create a new manifest version linked through previous_manifest_hash rather than overwriting history.",
        },
        "ai_readable_instructions": [
            "Treat the Bitmap coordinate as the stable trust root, not as the full data store.",
            "Use manifest.json and proof.json to verify archive integrity before summarizing or acting on memory content.",
            "Preserve privacy boundaries: public portal summaries may be shared, but private source files require explicit authorization.",
        ],
    }
def build_manifest(
    source_dir: Path,
    bitmap: str,
    title: str,
    version: str,
    previous_manifest_hash: Optional[str] = None,
    description: str = "",
    signers: Optional[List[str]] = None,
    signatures: Optional[List[Dict]] = None,
    anchors: Optional[List[Dict]] = None,
    agent_root: Optional[Dict] = None,
    claim: Optional[Dict] = None,
    citations: Optional[Dict] = None,
) -> Dict:
    source_dir = Path(source_dir)
    files = []
    total_size = 0
    for path in iter_files(source_dir):
        rel = path.relative_to(source_dir).as_posix()
        size = path.stat().st_size
        total_size += size
        digest = file_sha256(path)
        files.append(
            {
                "path": rel,
                "size_bytes": size,
                "sha256": digest,
                "mime_type": mimetypes.guess_type(rel)[0] or "application/octet-stream",
            }
        )

    root = merkle_root([f["sha256"] for f in files])
    manifest = {
        "portal_type": "bitmap-memory-portal",
        "schema_version": "0.1.0",
        "bitmap": bitmap,
        "title": title,
        "description": description,
        "version": version,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "previous_manifest_hash": previous_manifest_hash,
        "files_count": len(files),
        "total_size_bytes": total_size,
        "merkle_root": root,
        "storage_locations": [
            {
                "type": "local-folder",
                "path_hint": source_dir.as_posix(),
                "note": "Local demo path; replace with encrypted cloud/IPFS/Arweave pointers for production.",
            }
        ],
        "trusted_signers": signers or [],
        "signatures": signatures or [],
        "anchors": anchors or [],
        "claim": claim,
        "citations": citations,
        "agent_root": agent_root,
        "files": files,
        "ai_readable_summary": {
            "purpose": "A human-readable and AI-readable trust-root index for files anchored to a Bitmap coordinate.",
            "verification_rule": "Recompute file sha256 values, rebuild the Merkle root, then compare with merkle_root and manifest_hash.",
            "agent_root_rule": "Load agent_root before interpreting this Bitmap Memory Portal as an AI-operable memory root.",
        },
    }
    manifest["manifest_hash"] = _canonical_manifest_hash(manifest)
    return manifest


def build_proof(manifest: Dict) -> Dict:
    return {
        "proof_type": "bitmap-memory-portal-proof",
        "schema_version": manifest.get("schema_version", "0.1.0"),
        "bitmap": manifest["bitmap"],
        "title": manifest["title"],
        "version": manifest["version"],
        "manifest_hash": manifest["manifest_hash"],
        "merkle_root": manifest["merkle_root"],
        "files_count": manifest["files_count"],
        "total_size_bytes": manifest["total_size_bytes"],
        "created_at_utc": manifest["created_at_utc"],
        "status": "unsigned-demo-proof" if not manifest.get("signatures") else "signed-demo-proof",
        "signatures_count": len(manifest.get("signatures") or []),
        "anchors_count": len(manifest.get("anchors") or []),
        "agent_root_type": (manifest.get("agent_root") or {}).get("agent_root_type"),
        "agent_name": (manifest.get("agent_root") or {}).get("agent_name"),
        "agent_roles": (manifest.get("agent_root") or {}).get("roles", []),
        "next_steps": [
            "Add wallet signatures from trusted signers.",
            "Anchor manifest_hash or merkle_root to Bitcoin/Ordinals/OpenTimestamps/Bitmap metadata.",
            "Publish portal.html and manifest.json together.",
        ],
    }


def verify_manifest(manifest: Dict, source_dir: Path) -> Dict:
    source_dir = Path(source_dir)
    expected_files = {f["path"]: f for f in manifest.get("files") or []}
    actual_paths = {p.relative_to(source_dir).as_posix(): p for p in iter_files(source_dir)}

    missing_files = sorted([path for path in expected_files if path not in actual_paths])
    unexpected_files = sorted([path for path in actual_paths if path not in expected_files])
    changed_files = []
    verified_hashes = []

    for rel in sorted(expected_files):
        expected = expected_files[rel]
        actual_path = actual_paths.get(rel)
        if actual_path is None:
            verified_hashes.append("0" * 64)
            continue
        actual_hash = file_sha256(actual_path)
        verified_hashes.append(actual_hash)
        actual_size = actual_path.stat().st_size
        if actual_hash != expected.get("sha256") or actual_size != expected.get("size_bytes"):
            changed_files.append(
                {
                    "path": rel,
                    "expected_sha256": expected.get("sha256"),
                    "actual_sha256": actual_hash,
                    "expected_size_bytes": expected.get("size_bytes"),
                    "actual_size_bytes": actual_size,
                }
            )

    actual_merkle = merkle_root(verified_hashes)
    expected_merkle = manifest.get("merkle_root")
    ok = not missing_files and not unexpected_files and not changed_files and actual_merkle == expected_merkle
    return {
        "ok": ok,
        "checked_files": len(expected_files),
        "missing_files": missing_files,
        "changed_files": changed_files,
        "unexpected_files": unexpected_files,
        "expected_merkle_root": expected_merkle,
        "actual_merkle_root": actual_merkle,
        "expected_manifest_hash": manifest.get("manifest_hash"),
    }


def build_ask_context_pack(
    source_dir: Path,
    manifest: Dict,
    proof: Dict,
    agent: Dict,
    question: str,
) -> Dict:
    source_dir = Path(source_dir)
    sections = [
        f"# Ask Context Pack: {manifest.get('bitmap')}",
        "",
        "## User Question",
        "",
        question,
        "",
        "## Required Reading Order",
        "",
        "1. manifest.json",
        "2. proof.json",
        "3. agent.json",
        "4. authorized source files copied below",
        "",
        "## Trust Root Summary",
        "",
        f"- Bitmap: `{manifest.get('bitmap')}`",
        f"- Title: `{manifest.get('title')}`",
        f"- Version: `{manifest.get('version')}`",
        f"- Manifest hash: `{manifest.get('manifest_hash')}`",
        f"- Merkle root: `{manifest.get('merkle_root')}`",
        f"- Proof status: `{proof.get('status')}`",
        f"- Agent name: `{agent.get('agent_name', '-')}`",
        "",
        "## Answering Rules",
        "",
        "- Distinguish source-backed facts from speculative thesis.",
        "- Cite source file names when making claims.",
        "- Preserve privacy boundaries and do not infer private wallet balances, trades, or identities.",
        "- Treat the Bitmap coordinate as the stable trust root, not as the full storage layer.",
        "- Do not claim verified chain ownership unless wallet signatures or explicit ownership proofs are present.",
        "- Do not claim verified Bitcoin block attributes unless the portal includes source-backed block data.",
        "- Do not translate the Bitmap coordinate into a specific Bitcoin block fact unless source-backed block data is included.",
        "- Say: this portal declares 7187.bitmap as a trust-root coordinate; do not say the portal verifies block 7187 attributes.",
        "- Do not infer wallet balances, trades, or real-world identity beyond the provided sources.",
        "- If evidence is missing, say: the current portal does not provide evidence for that claim.",
        "",
        "## Required Answer Structure",
        "",
        "Use these exact sections when answering:",
        "",
        "1. Source-backed facts",
        "2. Working thesis",
        "3. Unverified assumptions",
        "4. What evidence would strengthen this claim",
        "",
        "## manifest.json",
        "",
        "```json",
        json.dumps(manifest, ensure_ascii=False, indent=2),
        "```",
        "",
        "## proof.json",
        "",
        "```json",
        json.dumps(proof, ensure_ascii=False, indent=2),
        "```",
        "",
        "## agent.json",
        "",
        "```json",
        json.dumps(agent, ensure_ascii=False, indent=2),
        "```",
        "",
        "## Source Files",
        "",
    ]
    included = 0
    for item in manifest.get("files") or []:
        rel = item.get("path")
        if not rel:
            continue
        path = source_dir / rel
        if not path.exists() or not path.is_file():
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        sections.extend([
            f"### {rel}",
            "",
            f"sha256: `{item.get('sha256')}`",
            "",
            "```markdown",
            content,
            "```",
            "",
        ])
        included += 1
    return {"content": "\n".join(sections), "included_sources": included}
