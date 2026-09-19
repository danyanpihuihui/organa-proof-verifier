"""Organa Task Flow Extension: Commit-Reveal Blind Submission Support.

Why this exists:
In open multi-agent tasks, naive public submissions allow free-rider agents to
copy or front-run the artifacts of honest agents. The Commit-Reveal scheme prevents
this:
1. Commit Phase: Agent computes commit_hash = H(artifact_sha256 + salt + agent_controller)
   and submits an organa-task-commit document before the commit deadline.
2. Reveal Phase: Agent submits organa-task-submission with artifacts and salt. The verifier
   confirms that H(artifact_sha256 + salt + agent_controller) == commit_hash.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional

COMMIT_SCHEMA = "organa-task-commit-v0.1"


def compute_commit_hash(artifact_sha256: str, salt: str, agent_controller: str) -> str:
    """Compute deterministic commit hash: sha256(artifact_sha256:salt:agent_controller)."""
    normalized_controller = agent_controller.strip().lower()
    raw = f"{artifact_sha256.strip()}:{salt.strip()}:{normalized_controller}".encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def build_commit_document(
    *,
    task_id: str,
    offer_sha256: str,
    agent_id: str,
    agent_controller: str,
    commit_hash: str,
    signature_scheme: str = "eip191-personal-sign",
    issued_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Build an unsigned task commit document."""
    issued_str = (issued_at or datetime.now(timezone.utc)).isoformat()
    if not issued_str.endswith("Z") and not ("+" in issued_str[10:] or "-" in issued_str[10:]):
        issued_str += "Z"

    message = (
        "Organa Task Commit v0.1\n"
        "Domain: organa-task-commit\n"
        f"Signature scheme: {signature_scheme}\n"
        f"Task ID: {task_id}\n"
        f"Offer SHA-256: {offer_sha256}\n"
        f"Agent ID: {agent_id}\n"
        f"Agent Controller: {agent_controller.strip().lower()}\n"
        f"Commit Hash: {commit_hash}\n"
        f"Issued at UTC: {issued_str}\n\n"
        "This commit blinds the deliverables until the reveal phase closes."
    )

    return {
        "schema_version": COMMIT_SCHEMA,
        "task_id": task_id,
        "offer_sha256": offer_sha256,
        "agent_id": agent_id,
        "agent_controller": agent_controller.strip().lower(),
        "commit_hash": commit_hash,
        "signature_scheme": signature_scheme,
        "issued_at_utc": issued_str,
        "message": message,
        "message_encoding": "UTF-8",
        "message_sha256": "sha256:" + hashlib.sha256(message.encode("utf-8")).hexdigest(),
    }


def verify_reveal_match(
    commit_document: Mapping[str, Any],
    artifact_sha256: str,
    salt: str,
    agent_controller: str,
) -> bool:
    """Verify that revealed artifact and salt match the committed hash."""
    expected_hash = compute_commit_hash(artifact_sha256, salt, agent_controller)
    committed_hash = commit_document.get("commit_hash")
    return expected_hash == committed_hash
