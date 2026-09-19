"""Shared core for Organa signed claims.

Every signed document in Organa (controller claims, agent registration, task offers,
claims and submissions) rests on the same three steps:

1. derive a canonical UTF-8 message from the document's own fields,
2. compare it with the message the submitter says was signed,
3. only then ask a BIP-322 verifier about that exact message.

Step 2 is the security-critical one. Without it a valid signature over one document could
be replayed against a different document, because a signature says nothing about the JSON
that carries it. This module exists so that check has exactly one implementation instead
of one per document type, where any single omission would be a silent forgery hole.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, Mapping

AGENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
CELL_RE = re.compile(r"^[0-9]+\.bitmap$")
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ROLE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

LINEAGE_STATUSES = frozenset(
    {"original", "continuous-successor", "fork", "replica", "impersonation-risk"}
)

# Codes every document type can emit, so callers can switch on them uniformly.
BINDING_MISMATCH = "message-mismatch"
BINDING_OK = "message-bound"


def sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_https_url(value: Any, field: str) -> str:
    """Accept only credential-free, fragment-free HTTPS URLs."""
    if not isinstance(value, str) or not value or CONTROL_RE.search(value):
        raise ValueError(f"{field} must be non-empty text without control characters")
    try:
        from urllib.parse import urlparse

        parsed = urlparse(value)
    except ValueError as exc:
        raise ValueError(f"{field} is not a valid URL") from exc
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"{field} must be an absolute HTTPS URL")
    if parsed.username or parsed.password:
        raise ValueError(f"{field} must not contain credentials")
    if parsed.fragment:
        raise ValueError(f"{field} must not contain a fragment")
    return value


def require_hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or not HASH_RE.fullmatch(value):
        raise ValueError(f"{field} must be a sha256:<64 hex> digest")
    return value


def require_agent_id(value: Any) -> str:
    if not isinstance(value, str) or not AGENT_ID_RE.fullmatch(value):
        raise ValueError("agent_id must match ^[a-z0-9][a-z0-9._-]{1,63}$")
    return value


def require_home_cell(value: Any) -> str:
    if not isinstance(value, str) or not CELL_RE.fullmatch(value):
        raise ValueError("home_cell must match <number>.bitmap")
    return value


def require_role(value: Any) -> str:
    if not isinstance(value, str) or not ROLE_RE.fullmatch(value):
        raise ValueError("role must match ^[a-z0-9][a-z0-9-]{1,63}$")
    return value


def require_address(value: Any) -> str:
    """Bitcoin-style address: loose on purpose, the signature is what actually binds it."""
    if not isinstance(value, str) or not (14 <= len(value) <= 90):
        raise ValueError("controller address must be 14-90 characters")
    if not value.isascii() or any(ch.isspace() for ch in value):
        raise ValueError("controller address must be ASCII without whitespace")
    return value


def parse_utc(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be an ISO-8601 UTC timestamp")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must carry an explicit UTC offset")
    return parsed.astimezone(timezone.utc)


def build_message(title: str, domain: str, lines: Iterable[str], footer: str) -> str:
    """Join a document's binding facts into the exact bytes its author must sign."""
    return "\n".join(
        [title, f"Domain: {domain}", "Bitcoin network: mainnet", *lines, "", footer]
    )


def check_message_binding(
    claim: Any,
    *,
    build: Callable[[Mapping[str, Any]], str],
) -> Dict[str, Any]:
    """Re-derive the message from the claim's fields and compare with the declared one.

    Returns ``{"bound": bool, "code": str, "message": str|None}``. A caller must not ask
    a signature verifier about the message unless ``bound`` is true.
    """
    message = claim.get("message") if isinstance(claim, Mapping) else None
    if not isinstance(message, str) or not message:
        return {"bound": False, "code": "missing-message", "message": None}
    expected = build(claim)
    if expected != message:
        return {"bound": False, "code": BINDING_MISMATCH, "message": message}
    return {"bound": True, "code": BINDING_OK, "message": message}


def verify_signature_over_message(
    *,
    address: Any,
    message: str,
    signature: Any,
    signature_verifier: Callable[[Dict[str, Any]], Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    """Ask the BIP-322 verifier about exactly one address/message/signature triple.

    An unavailable verifier is reported distinctly from an invalid signature: conflating
    the two would turn an outage into a silent accusation of forgery.
    """
    if not isinstance(signature, str) or not signature.strip():
        return {"checked": False, "valid": None, "code": "missing-signature"}
    verifier = signature_verifier or default_signature_verifier
    try:
        verified = verifier(
            {"signing_address": address, "message": message, "signature": signature}
        )
    except Exception as exc:  # noqa: BLE001 - surface any verifier failure as unavailable
        return {
            "checked": False,
            "valid": None,
            "code": "verifier-unavailable",
            "detail": str(exc),
        }
    if not isinstance(verified, Mapping):
        return {"checked": False, "valid": None, "code": "verifier-unavailable"}
    if verified.get("signature_verification") == "verifier-unavailable":
        return {
            "checked": False,
            "valid": None,
            "code": "verifier-unavailable",
            "detail": str(verified.get("verification_error", "")),
        }
    valid = verified.get("signature_valid") is True
    return {
        "checked": True,
        "valid": valid,
        "code": "signature-valid" if valid else "invalid-signature",
        "detail": str(verified.get("verification_error", "")),
        "verification": dict(verified),
    }


def default_signature_verifier(claim: Dict[str, Any]) -> Dict[str, Any]:
    """Late import so this module stays importable without the node toolchain present."""
    from .claims import verify_claim_signature

    return verify_claim_signature(claim)


def reject_conflicting_aliases(
    claim: Mapping[str, Any],
    bound_blocks: Iterable[tuple[str, tuple[str, ...]]],
) -> list[str]:
    """Catch stray top-level twins of bound fields.

    The signature covers the bound blocks only, so a claim carrying ``identity_sha256``
    alongside ``identity.sha256`` could show one value to the signed message and another
    to a reader that guesses the flatter key name. A matching twin is harmless; a
    differing one is fatal.
    """
    problems: list[str] = []
    for block_name, keys in bound_blocks:
        block = claim.get(block_name)
        block = block if isinstance(block, Mapping) else {}
        for key in keys:
            twin = f"{block_name}_{key}"
            if twin in claim and claim.get(twin) != block.get(key):
                problems.append(f"{twin} contradicts the bound field {block_name}.{key}")
    return problems
