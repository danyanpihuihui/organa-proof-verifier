from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict


_SCHEME_SCRIPTS = {
    "bip322-simple": "verify_claim.js",
    "eip191-personal-sign": "verify_evm_message.js",
}


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
    scheme = claim.get("signing_scheme") or "bip322-simple"
    script_name = _SCHEME_SCRIPTS.get(scheme)
    if script_name is None:
        result["signature_valid"] = False
        result["signature_verification"] = "unsupported-signature-scheme"
        result["verification_error"] = f"no verifier for signing_scheme {scheme!r}"
        return result
    verifier_label = "bip322-js" if scheme == "bip322-simple" else "eip191-noble"
    script = Path(__file__).resolve().parents[2] / "scripts" / script_name
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
        result["signature_verification"] = f"locally-verified-{verifier_label}"
        result.pop("verification_error", None)
    else:
        result["signature_valid"] = False
        result["signature_verification"] = f"locally-invalid-{verifier_label}"
        result["verification_error"] = (
            payload.get("error") or proc.stderr or "signature verification failed"
        )
    if payload.get("recovered"):
        result["recovered_address"] = payload["recovered"]
    return result
