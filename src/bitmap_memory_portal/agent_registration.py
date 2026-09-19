"""Organa Agent Registration Claim v0.1.

The missing link for self-service agent registration.

Before this module there was no defined format for "an agent asks to be registered".
An agent could build its own identity package, but the only way into a Cell's
``agent-registry.json`` was for the Cell controller to hand-write an entry. That is
not self-registration, and it meant the request could not even be expressed, let
alone independently checked.

This module defines that request as a signed, self-contained document:

* the agent builds its own continuity package and publishes it under a URL it controls;
* it then signs a claim binding its key to that package's three hashes;
* anyone - the Cell controller, a verifier service, a third party - can check the
  claim without trusting the agent, the Cell, or each other.

Design notes
------------

**Canonical message.** The exact UTF-8 message is derived deterministically from the
claim's own fields by :func:`build_registration_message`. Verification *recomputes*
it and compares. Without that step a valid signature over one set of facts could be
replayed against different facts, so the recomputation is the security property, not
a formality.

**This module is copied verbatim into both the engine and the verifier service.**
The message format is the interface between them, so the two copies must not drift.
If you change the message layout you change the wire format.

**What a valid claim does and does not mean.** It proves the signer controls the
declared controller address and asserts a binding to the declared identity hashes.
It does not prove the identity URLs resolve to that content (that needs a fetch), it
does not grant authority over the home Cell, and it says nothing about whether the
agent's work is any good. Callers must not upgrade it into an endorsement.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Mapping
from urllib.parse import urlparse

SCHEMA_VERSION = "organa-agent-registration-claim-v0.1"
VERIFICATION_SCHEMA_VERSION = "organa-agent-registration-verification-v0.1"
MESSAGE_DOMAIN = "organa-agent-registration"
DEFAULT_TTL_DAYS = 7

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_CELL_RE = re.compile(r"^[0-9]+\.bitmap$")
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ROLE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_LINEAGE_STATUSES = {"original", "continuous-successor", "fork", "replica", "impersonation-risk"}

_REQUIRED_HASH_FIELDS = ("identity", "continuity_checkpoint", "discovery")


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalize_https_url(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or _CONTROL_RE.search(value):
        raise ValueError(f"{field} must be a non-empty URL without control characters")
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"{field} must be an absolute HTTPS URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.params:
        raise ValueError(f"{field} must not contain credentials, params, query or fragment")
    return value


def _require_hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise ValueError(f"{field} must be sha256:<64 hex>")
    return value


def _require_agent_id(value: Any) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ValueError("agent_id must match ^[a-z0-9][a-z0-9._-]{1,63}$")
    return value


def _require_home_cell(value: Any) -> str:
    if not isinstance(value, str) or not _CELL_RE.fullmatch(value):
        raise ValueError("home_cell must match <number>.bitmap")
    return value


def _require_role(value: Any) -> str:
    if not isinstance(value, str) or not _ROLE_RE.fullmatch(value):
        raise ValueError("role must match ^[a-z0-9][a-z0-9-]{1,63}$")
    return value


def _require_address(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not (14 <= len(value) <= 90)
        or not value.isascii()
        or any(ch.isspace() for ch in value)
    ):
        raise ValueError("controller_address has invalid syntax")
    return value


def _parse_utc(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be an ISO-8601 UTC timestamp")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must carry a timezone offset")
    return parsed.astimezone(timezone.utc)


def build_registration_message(claim: Mapping[str, Any]) -> str:
    """Derive the canonical signed message from a claim's own fields.

    Verification recomputes this and compares, so any edit to the binding facts
    invalidates the signature. Keep this layout stable: it is the wire format.
    """
    return "\n".join(
        [
            "Organa Agent Registration Claim v0.1",
            f"Domain: {MESSAGE_DOMAIN}",
            "Bitcoin network: mainnet",
            f"Agent ID: {claim.get('agent_id')}",
            f"Display Name: {claim.get('display_name')}",
            f"Home Cell: {claim.get('home_cell')}",
            f"Role: {claim.get('role')}",
            f"Controller Address: {claim.get('controller_address')}",
            f"Lineage Status: {claim.get('lineage_status')}",
            f"Identity URL: {(claim.get('identity') or {}).get('url')}",
            f"Identity SHA-256: {(claim.get('identity') or {}).get('sha256')}",
            f"Checkpoint URL: {(claim.get('continuity_checkpoint') or {}).get('url')}",
            f"Checkpoint SHA-256: {(claim.get('continuity_checkpoint') or {}).get('sha256')}",
            f"Discovery URL: {(claim.get('discovery') or {}).get('url')}",
            f"Discovery SHA-256: {(claim.get('discovery') or {}).get('sha256')}",
            "Subjective Continuity Claimed: false",
            f"Issued at UTC: {claim.get('issued_at_utc')}",
            f"Expires at UTC: {claim.get('expires_at_utc')}",
            "",
            "This claim binds the signing key to the declared agent identity package. "
            "It does not transfer assets, grant authority over the home Cell, or assert "
            "that this agent's work is correct.",
        ]
    )


def build_agent_registration_claim(
    *,
    agent_id: str,
    display_name: str,
    home_cell: str,
    role: str,
    controller_address: str,
    identity_url: str,
    identity_sha256: str,
    checkpoint_url: str,
    checkpoint_sha256: str,
    discovery_url: str,
    discovery_sha256: str,
    lineage_status: str = "original",
    issued_at: datetime | None = None,
    ttl_days: int = DEFAULT_TTL_DAYS,
) -> Dict[str, Any]:
    """Build an unsigned registration claim, including the message to sign.

    The returned document carries ``message`` but no ``signature``. Sign that exact
    UTF-8 message with the controller key (BIP-322) and attach it with
    :func:`finalize_agent_registration_claim`.
    """
    agent_id = _require_agent_id(agent_id)
    home_cell = _require_home_cell(home_cell)
    role = _require_role(role)
    controller_address = _require_address(controller_address)
    if not isinstance(display_name, str) or not display_name.strip() or _CONTROL_RE.search(display_name):
        raise ValueError("display_name must be non-empty text without control characters")
    if lineage_status not in _LINEAGE_STATUSES:
        raise ValueError("lineage_status is invalid")
    if not isinstance(ttl_days, int) or ttl_days < 1:
        raise ValueError("ttl_days must be a positive integer")

    issued = (issued_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires = issued + timedelta(days=ttl_days)

    claim: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "agent_id": agent_id,
        "display_name": display_name,
        "home_cell": home_cell,
        "role": role,
        "lineage_status": lineage_status,
        "controller_address": controller_address,
        "identity": {"url": _normalize_https_url(identity_url, "identity.url"), "sha256": _require_hash(identity_sha256, "identity.sha256")},
        "continuity_checkpoint": {
            "url": _normalize_https_url(checkpoint_url, "continuity_checkpoint.url"),
            "sha256": _require_hash(checkpoint_sha256, "continuity_checkpoint.sha256"),
        },
        "discovery": {"url": _normalize_https_url(discovery_url, "discovery.url"), "sha256": _require_hash(discovery_sha256, "discovery.sha256")},
        "subjective_continuity_claimed": False,
        "signature_method": "BIP-322-simple-message-signature",
        "message_encoding": "UTF-8",
        "issued_at_utc": issued.isoformat(),
        "expires_at_utc": expires.isoformat(),
        "registration_boundary": (
            "Registering proves control of the controller address and a binding to the declared "
            "identity hashes. It grants no authority over the home Cell and makes no claim about "
            "the quality of this agent's work."
        ),
    }
    claim["message"] = build_registration_message(claim)
    claim["message_sha256"] = _sha256_text(claim["message"])
    return claim


def finalize_agent_registration_claim(claim: Mapping[str, Any], signature: str) -> Dict[str, Any]:
    """Attach a BIP-322 signature over the claim's canonical message."""
    if not isinstance(signature, str) or not signature.strip():
        raise ValueError("signature must be a non-empty string")
    if not isinstance(claim, Mapping) or not isinstance(claim.get("message"), str):
        raise ValueError("claim must carry a message built by build_agent_registration_claim")
    finalized = dict(claim)
    finalized["signature"] = signature
    return finalized


def _default_signature_verifier(claim: Dict[str, Any]) -> Dict[str, Any]:
    from .claims import verify_claim_signature

    return verify_claim_signature(claim)


def verify_agent_registration_claim(
    claim: Any,
    *,
    signature_verifier: Callable[[Dict[str, Any]], Dict[str, Any]] | None = None,
    now: datetime | None = None,
) -> Dict[str, Any]:
    """Independently check a registration claim.

    Offline check only: it validates structure, re-derives the message, enforces the
    continuity rules, checks freshness, and verifies the BIP-322 signature. It does
    NOT fetch the identity URLs - a claim can verify while the published package is
    missing or altered, so callers wanting that must resolve the URLs themselves.
    """
    errors: list[Dict[str, str]] = []
    warnings: list[str] = []

    def fail(code: str, message: str) -> None:
        errors.append({"code": code, "message": message})

    result: Dict[str, Any] = {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "ok": False,
        "agent_id": None,
        "home_cell": None,
        "binding_ok": False,
        "signature_valid": None,
        "expired": None,
        "errors": errors,
        "warnings": warnings,
        "boundary": (
            "A valid registration claim proves control of the controller address and a declared "
            "binding to the identity hashes. It does not prove the identity URLs resolve to that "
            "content, grant authority over the home Cell, or vouch for the agent's work."
        ),
    }

    if not isinstance(claim, Mapping):
        fail("malformed-claim", "claim must be a JSON object")
        return result
    if claim.get("schema_version") != SCHEMA_VERSION:
        fail("unsupported-schema", f"schema_version must be {SCHEMA_VERSION}")

    try:
        result["agent_id"] = _require_agent_id(claim.get("agent_id"))
    except ValueError as exc:
        fail("invalid-agent-id", str(exc))
    try:
        result["home_cell"] = _require_home_cell(claim.get("home_cell"))
    except ValueError as exc:
        fail("invalid-home-cell", str(exc))
    try:
        _require_role(claim.get("role"))
    except ValueError as exc:
        fail("invalid-role", str(exc))
    try:
        _require_address(claim.get("controller_address"))
    except ValueError as exc:
        fail("invalid-controller-address", str(exc))

    for field in _REQUIRED_HASH_FIELDS:
        block = claim.get(field)
        if not isinstance(block, Mapping):
            fail("missing-binding", f"{field} must be an object with url and sha256")
            continue
        try:
            _normalize_https_url(block.get("url"), f"{field}.url")
        except ValueError as exc:
            fail("invalid-binding-url", str(exc))
        try:
            _require_hash(block.get("sha256"), f"{field}.sha256")
        except ValueError as exc:
            fail("invalid-binding-hash", str(exc))

    # A claim must not carry a stray top-level twin of a bound field. The signature only
    # covers the bound fields, so a differing twin would let the claim show one value to
    # the signed message and another to a reader that guesses the flatter key name.
    for field in _REQUIRED_HASH_FIELDS:
        block = claim.get(field)
        block = block if isinstance(block, Mapping) else {}
        for key in ("url", "sha256"):
            twin = f"{field}_{key}"
            if twin in claim and claim.get(twin) != block.get(key):
                fail("conflicting-alias", f"{twin} contradicts the bound field {field}.{key}")

    lineage = claim.get("lineage_status")
    if lineage not in _LINEAGE_STATUSES:
        fail("invalid-lineage", "lineage_status is not a recognised value")
    elif lineage != "original":
        warnings.append(
            "Non-original lineage: this claim does not carry the previous checkpoint or migration "
            "record, so successor/fork/replica lineage is asserted but not substantiated here."
        )

    if claim.get("subjective_continuity_claimed") is not False:
        fail("subjective-continuity-claimed", "subjective_continuity_claimed must be false")

    # Freshness.
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires_at = None
    try:
        expires_at = _parse_utc(claim.get("expires_at_utc"), "expires_at_utc")
        result["expired"] = expires_at <= moment
        if result["expired"]:
            fail("claim-expired", "claim authorization window has passed")
    except ValueError as exc:
        fail("invalid-expiry", str(exc))
    try:
        _parse_utc(claim.get("issued_at_utc"), "issued_at_utc")
    except ValueError as exc:
        fail("invalid-issued-at", str(exc))

    # The security-critical step: re-derive the message from the claim's own fields.
    message = claim.get("message")
    if not isinstance(message, str) or not message:
        fail("missing-message", "claim must include the exact signed message")
    else:
        expected = build_registration_message(claim)
        if expected != message:
            fail(
                "message-mismatch",
                "the signed message does not match the claim's fields; the signature is over different content",
            )
        else:
            result["binding_ok"] = True
        declared_message_sha = claim.get("message_sha256")
        if isinstance(declared_message_sha, str) and declared_message_sha != _sha256_text(message):
            fail("message-hash-mismatch", "message_sha256 does not match the message")

    result["expires_at_utc"] = expires_at.isoformat() if expires_at else None

    signature = claim.get("signature")
    if not isinstance(signature, str) or not signature.strip():
        fail("missing-signature", "claim must carry a BIP-322 signature")
    elif not result["binding_ok"]:
        # Verifying a signature over unbound content would prove nothing useful.
        fail("unverified-signature", "signature not checked because the message is not bound to the claim fields")
    else:
        verifier = signature_verifier or _default_signature_verifier
        try:
            verified = verifier(
                {
                    "signing_address": claim.get("controller_address"),
                    "message": message,
                    "signature": signature,
                }
            )
        except Exception as exc:  # pragma: no cover - defensive
            fail("verifier-unavailable", str(exc))
        else:
            if not isinstance(verified, Mapping):
                fail("verifier-unavailable", "signature verifier returned an unexpected result")
            elif verified.get("signature_verification") == "verifier-unavailable":
                fail("verifier-unavailable", str(verified.get("verification_error", "signature verifier unavailable")))
            else:
                result["signature_valid"] = verified.get("signature_valid") is True
                if not result["signature_valid"]:
                    fail("invalid-signature", str(verified.get("verification_error", "signature verification failed")))

    result["errors"] = errors
    result["ok"] = not errors
    return result


def registration_claim_to_registry_entry(
    claim: Mapping[str, Any],
    *,
    lifecycle_status: str = "pending",
) -> Dict[str, Any]:
    """Project a verified claim into the registry entry shape.

    Only call this on a claim that passed :func:`verify_agent_registration_claim`.
    The projection deliberately drops the signature: a registry entry is a claim
    about what was published, while the signed claim is the evidence for it.

    ``lifecycle_status`` defaults to ``pending`` and must be set to ``live`` only by a
    caller that has actually resolved the declared URLs: verification proves the
    controller binding and the declared hashes, not that the package exists.
    """
    return {
        "id": claim.get("agent_id"),
        "name": claim.get("display_name"),
        "role": claim.get("role"),
        "lifecycle_status": lifecycle_status,
        "identity": dict(claim.get("identity") or {}),
        "continuity_checkpoint": dict(claim.get("continuity_checkpoint") or {}),
        "discovery": dict(claim.get("discovery") or {}),
        "lineage_status": claim.get("lineage_status"),
        "subjective_continuity_claimed": False,
        "registration": {
            "schema_version": SCHEMA_VERSION,
            "controller_address": claim.get("controller_address"),
            "issued_at_utc": claim.get("issued_at_utc"),
            "expires_at_utc": claim.get("expires_at_utc"),
            "message_sha256": claim.get("message_sha256"),
            "verified_by": "self-registration-claim",
        },
    }


def dump_registration_claim(claim: Mapping[str, Any]) -> str:
    return json.dumps(claim, ensure_ascii=False, indent=2) + "\n"
