from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict


def _node_command() -> str:
    found = shutil.which("node")
    if found:
        return found
    local = Path.home() / ".local" / "bin" / "node"
    if local.exists():
        return str(local)
    return "node"


def verify_claim_signature(claim: Dict) -> Dict:
    result = dict(claim)
    script = Path(__file__).resolve().parents[2] / "scripts" / "verify_claim.js"
    try:
        proc = subprocess.run(
            [_node_command(), str(script)],
            input=json.dumps(claim, ensure_ascii=False),
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
        payload = json.loads(proc.stdout or "{}")
    except Exception as exc:
        result["signature_valid"] = False
        result["signature_verification"] = "verifier-unavailable"
        result["verification_error"] = str(exc)
        return result

    if proc.returncode == 0 and payload.get("ok") is True:
        result["signature_valid"] = True
        result["signature_verification"] = "locally-verified-bip322-js"
        result.pop("verification_error", None)
    else:
        result["signature_valid"] = False
        result["signature_verification"] = "locally-invalid-bip322-js"
        result["verification_error"] = payload.get("error") or proc.stderr or "signature verification failed"
    return result
