from __future__ import annotations

from typing import Dict


def build_authenticity_label(manifest: Dict) -> Dict:
    claim = manifest.get("claim") or {}
    anchors = manifest.get("anchors") or []
    wallet_verified = claim.get("signature_valid") is True and claim.get("signature_verification") == "locally-verified-bip322-js"
    has_timestamp = any((a.get("type") or "").lower() in {"opentimestamps", "bitcoin", "timestamp"} and a.get("status") not in {None, "missing", "planned"} for a in anchors)
    status = "coordinate-claimed-and-wallet-verified" if wallet_verified else "coordinate-declared"

    return {
        "label_type": "bitmap-authenticity-label",
        "schema_version": "0.1.0",
        "coordinate": manifest.get("bitmap"),
        "data_scope": "public Bitmap Memory Portal files",
        "authenticity_status": status,
        "evidence_layers": [
            {"layer": "coordinate", "status": "declared", "evidence": manifest.get("bitmap")},
            {"layer": "file-integrity", "status": "verified", "evidence": {"manifest_hash": manifest.get("manifest_hash"), "merkle_root": manifest.get("merkle_root"), "files_count": manifest.get("files_count")}},
            {"layer": "wallet-attestation", "status": "locally-verified" if wallet_verified else "missing-or-unverified", "evidence": {"claim_status": claim.get("claim_status"), "signature_verification": claim.get("signature_verification"), "signing_address": claim.get("signing_address")}},
            {"layer": "timestamp-anchor", "status": "present" if has_timestamp else "missing", "evidence": anchors or None},
        ],
        "what_this_proves": [
            "The listed files match the manifest hash and Merkle root.",
            "The manifest is linked to the declared Bitmap coordinate.",
            "The signing wallet attested to the portal claim when wallet-attestation is locally verified.",
        ],
        "what_this_does_not_prove": [
            "It does not prove every statement in the files is true.",
            "It does not prove legal ownership of the Bitmap unless ownership proof is added.",
            "It does not prove the data existed before a timestamp anchor is added.",
        ],
    }
