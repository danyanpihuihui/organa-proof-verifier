from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, Iterable


def _file_record(path: Path) -> Dict[str, str]:
    resolved = Path(path).expanduser().resolve()
    digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    return {"path": str(resolved), "sha256": f"sha256:{digest}"}


def load_vibe_tool_policy(path: Path) -> Dict:
    policy = json.loads(Path(path).expanduser().resolve().read_text(encoding="utf-8"))
    if policy.get("adapter_id") != "vibe-trading":
        raise ValueError("not a Vibe-Trading adapter policy")
    if policy.get("unknown_tools_fail_closed") is not True:
        raise ValueError("Vibe-Trading policy must fail closed for unknown tools")
    return policy


def validate_vibe_tool_request(tool_name: str, policy: Dict) -> bool:
    allowed = set(policy.get("allowed_tools") or [])
    if tool_name in allowed:
        return True
    denied = policy.get("denied_tools") or {}
    reason = denied.get(tool_name, "unknown tool rejected by fail-closed policy")
    raise PermissionError(f"Vibe-Trading tool {tool_name!r} denied: {reason}")


def build_vibe_validation_artifact(
    claim: str,
    sample_id: str,
    source_manifest_path: Path,
    result_path: Path,
    tool_name: str,
    tool_arguments: Dict,
    warnings: Iterable[str] = (),
) -> Dict:
    return {
        "artifact_type": "organa-finance-validation-cell-result",
        "adapter_id": "vibe-trading",
        "adapter_version": "0.1.11",
        "mode": "read-only-shadow-validation",
        "sample_id": sample_id,
        "claim": claim,
        "tool": {"name": tool_name, "arguments": tool_arguments},
        "source_manifest": _file_record(source_manifest_path),
        "result": _file_record(result_path),
        "warnings": list(warnings),
        "canonical_state_mutation": False,
        "trade_execution_allowed": False,
        "model_rule_changes_allowed": False,
        "approval_required_for_model_use": True,
    }
