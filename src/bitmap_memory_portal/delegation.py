"""Organa Cell delegation v0.1 - binding an EVM account to a Cell.

The problem this solves
-----------------------
A Cell is anchored by a Bitcoin key: `controller-claim.json` is signed with BIP-322 and
proves that key controls the Cell's publication authority. But a Cell's tasks are often
funded from an EVM account, and an EVM account cannot produce a BIP-322 signature. Until
now the only options were dishonest ones: either require a Bitcoin key from a Base-native
requester, or let an EVM-signed offer *imply* Cell authority it never proved.

A delegation closes that gap with the Cell's own key. The controller signs a statement that
names an EVM account; from then on, that account's signatures can be read as the Cell's
word, because the Cell said so in the only way a Cell can say anything - a signature.

Why the EVM account must co-sign
--------------------------------
A one-sided statement ("I, the controller, delegate to 0xAbC...") is unverifiable in one
important respect: it cannot show the named account exists, is reachable, or consents. A
delegation that the account never accepted is an invitation, not an authorisation. Requiring
both signatures makes the resulting document mean exactly what it appears to mean - the Cell
granted it, and the account accepted it.

Why it is dual-signed, not single-signed with two messages
---------------------------------------------------------
Both signatures cover the *same* UTF-8 message, each in its own scheme. Neither party can
change a term without invalidating their own signature, and neither signature can be lifted
out of this document and replayed into another, because the message carries the delegation
id, both addresses, the scope and the validity window.

Permanent delegations
---------------------
`expires_at_utc` may be null, meaning the delegation does not lapse on a date. That is
allowed deliberately: a date-bounded delegation exists to limit exposure when the EVM key is
hotter than the controller key, and for a Cell whose payout account is the operator's main
account, forcing a re-sign every N days produces expired delegations rather than safety.
Permanent delegations are revocable by publishing a revocation; they are not unrevocable.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Mapping

from .signed_claims import (
    BIP322_SIMPLE,
    EIP191_PERSONAL_SIGN,
    EVM_ADDRESS_RE,
    check_message_binding,
    normalize_https_url,
    parse_utc,
    require_hash,
    require_home_cell,
    require_signer_address,
    sha256_text,
    verify_signature_over_message,
)

DELEGATION_SCHEMA = "organa-cell-account-delegation-v0.1"
REVOCATION_SCHEMA = "organa-cell-account-delegation-revocation-v0.1"

DELEGATION_TITLE = "Organa Cell Account Delegation v0.1"
DELEGATION_DOMAIN = "organa-cell-account-delegation"
REVOCATION_TITLE = "Organa Cell Account Delegation Revocation v0.1"
REVOCATION_DOMAIN = "organa-cell-account-delegation-revocation"

DELEGATION_FOOTER = (
    "The Cell controller named above states that the delegated account may act and speak for "
    "this Cell to the extent described, and the delegated account states that it accepts that "
    "authority. This delegation transfers no assets and authorises no spending on its own: it "
    "changes which account's signatures a reader may attribute to this Cell."
)

PERMANENT_FOOTER = (
    " This delegation has no expiry date and remains in effect until a revocation for it is "
    "published and verified."
)

REVOCATION_FOOTER = (
    "The Cell controller named above withdraws this delegation. After this revocation is "
    "published and verified, signatures made by the revoked account are no longer attributable "
    "to this Cell, whether they were made before or after the revocation took effect."
)

# Scope values a delegation may carry. Kept explicit so a reader never has to guess how far an
# account's authority reaches.
DELEGATION_SCOPES = frozenset({"publish-tasks", "speak-for-cell", "receive-payment"})

DELEGATION_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")


def require_delegation_id(value: Any) -> str:
    if not isinstance(value, str) or not DELEGATION_ID_RE.fullmatch(value):
        raise ValueError("delegation_id must match ^[a-z0-9][a-z0-9._-]{1,63}$")
    return value


def require_delegated_account(value: Any) -> str:
    if not isinstance(value, str) or not EVM_ADDRESS_RE.fullmatch(value):
        raise ValueError("delegated_account must be a 0x-prefixed 20-byte EVM address")
    return value


def require_scopes(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError("scopes must be a non-empty array")
    seen: list[str] = []
    for item in value:
        if not isinstance(item, str) or item not in DELEGATION_SCOPES:
            raise ValueError(f"scopes must be drawn from {sorted(DELEGATION_SCOPES)}")
        if item not in seen:
            seen.append(item)
    return seen


def _window(issued_at: datetime | None, expires_at: datetime | None) -> tuple[str, str | None]:
    issued = (issued_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if expires_at is None:
        return issued.isoformat(), None
    expires = expires_at.astimezone(timezone.utc)
    if expires <= issued:
        raise ValueError("expires_at must be after issued_at")
    return issued.isoformat(), expires.isoformat()


def _json_fragment(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


# --------------------------------------------------------------------------------------
# message builders - the wire format shared by builder and verifier
# --------------------------------------------------------------------------------------


def build_delegation_message(claim: Mapping[str, Any]) -> str:
    lines = [
        f"Delegation ID: {claim.get('delegation_id')}",
        f"Coordinate: {claim.get('coordinate')}",
        f"Cell Controller: {claim.get('cell_controller')}",
        f"Cell Manifests SHA-256: {_json_fragment(claim.get('cell_manifests_sha256'))}",
        f"Delegated Account: {claim.get('delegated_account')}",
        f"Scopes: {_json_fragment(claim.get('scopes'))}",
        f"Issued at UTC: {claim.get('issued_at_utc')}",
        f"Expires at UTC: {claim.get('expires_at_utc')}",
    ]
    footer = DELEGATION_FOOTER + (PERMANENT_FOOTER if claim.get("expires_at_utc") is None else "")
    return "\n".join(
        [
            DELEGATION_TITLE,
            f"Domain: {DELEGATION_DOMAIN}",
            "Bitcoin network: mainnet",
            "EVM chain: base",
            *lines,
            "",
            footer,
        ]
    )


def build_revocation_message(claim: Mapping[str, Any]) -> str:
    lines = [
        f"Delegation ID: {claim.get('delegation_id')}",
        f"Coordinate: {claim.get('coordinate')}",
        f"Cell Controller: {claim.get('cell_controller')}",
        f"Delegated Account: {claim.get('delegated_account')}",
        f"Delegation SHA-256: {claim.get('delegation_sha256')}",
        f"Issued at UTC: {claim.get('issued_at_utc')}",
    ]
    return "\n".join(
        [
            REVOCATION_TITLE,
            f"Domain: {REVOCATION_DOMAIN}",
            "Bitcoin network: mainnet",
            *lines,
            "",
            REVOCATION_FOOTER,
        ]
    )


# --------------------------------------------------------------------------------------
# builder
# --------------------------------------------------------------------------------------


def build_account_delegation(
    *,
    delegation_id: str,
    coordinate: str,
    cell_controller: str,
    delegated_account: str,
    scopes: Any,
    cell_manifests_sha256: Any,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> Dict[str, Any]:
    """Build an unsigned delegation plus the exact message both parties must sign."""
    issued_str, expires_str = _window(issued_at, expires_at)
    delegation: Dict[str, Any] = {
        "schema_version": DELEGATION_SCHEMA,
        "delegation_id": require_delegation_id(delegation_id),
        "coordinate": require_home_cell(coordinate),
        "cell_controller": require_signer_address(cell_controller, "cell_controller", BIP322_SIMPLE),
        "cell_manifests_sha256": [
            require_hash(item, "cell_manifests_sha256[]")
            for item in (cell_manifests_sha256 if isinstance(cell_manifests_sha256, list) else [])
        ],
        "delegated_account": require_delegated_account(delegated_account),
        "scopes": require_scopes(scopes),
        "issued_at_utc": issued_str,
        "expires_at_utc": expires_str,
    }
    if not delegation["cell_manifests_sha256"]:
        raise ValueError("cell_manifests_sha256 must list at least one manifest digest")
    delegation["message"] = build_delegation_message(delegation)
    delegation["message_encoding"] = "UTF-8"
    delegation["message_sha256"] = sha256_text(delegation["message"])
    return delegation


def finalize_account_delegation(
    delegation: Mapping[str, Any],
    *,
    controller_signature: str,
    account_signature: str,
) -> Dict[str, Any]:
    """Attach both signatures. One without the other is not a delegation."""
    if not isinstance(controller_signature, str) or not controller_signature.strip():
        raise ValueError("controller_signature is required")
    if not isinstance(account_signature, str) or not account_signature.strip():
        raise ValueError("account_signature is required")
    result = dict(delegation)
    result["controller_signature"] = controller_signature
    result["controller_signature_scheme"] = BIP322_SIMPLE
    result["account_signature"] = account_signature
    result["account_signature_scheme"] = EIP191_PERSONAL_SIGN
    result["message_encoding"] = "UTF-8"
    return result


# --------------------------------------------------------------------------------------
# verifier
# --------------------------------------------------------------------------------------


def _structural_problems(claim: Mapping[str, Any]) -> list[tuple[str, str]]:
    problems: list[tuple[str, str]] = []

    def check(code: str, fn) -> None:
        try:
            fn()
        except ValueError as exc:
            problems.append((code, str(exc)))

    check("invalid-delegation-id", lambda: require_delegation_id(claim.get("delegation_id")))
    check("invalid-coordinate", lambda: require_home_cell(claim.get("coordinate")))
    check(
        "invalid-cell-controller",
        lambda: require_signer_address(claim.get("cell_controller"), "cell_controller", BIP322_SIMPLE),
    )
    check("invalid-delegated-account", lambda: require_delegated_account(claim.get("delegated_account")))
    check("invalid-scopes", lambda: require_scopes(claim.get("scopes")))

    manifests = claim.get("cell_manifests_sha256")
    if not isinstance(manifests, list) or not manifests:
        problems.append(("invalid-cell-manifests", "cell_manifests_sha256 must be a non-empty array"))
    else:
        for item in manifests:
            try:
                require_hash(item, "cell_manifests_sha256[]")
            except ValueError as exc:
                problems.append(("invalid-cell-manifests", str(exc)))
                break

    controller = claim.get("cell_controller")
    account = claim.get("delegated_account")
    if isinstance(controller, str) and isinstance(account, str) and controller.lower() == account.lower():
        problems.append(
            ("delegation-to-self", "cell_controller and delegated_account must differ")
        )
    return problems


def verify_account_delegation(
    document: Any,
    *,
    signature_verifier=None,
    now: datetime | None = None,
) -> Dict[str, Any]:
    """Verify one delegation: structure, binding, freshness, and both signatures.

    Both signatures must be valid. A delegation with a valid controller signature and a
    missing or broken account signature is reported as invalid, because the account has not
    accepted anything.
    """
    errors: list[Dict[str, Any]] = []
    result: Dict[str, Any] = {
        "ok": False,
        "schema_version": document.get("schema_version") if isinstance(document, Mapping) else None,
        "delegation_id": None,
        "coordinate": None,
        "cell_controller": None,
        "delegated_account": None,
        "scopes": [],
        "permanent": None,
        "expired": None,
        "binding_ok": False,
        "controller_signature_valid": None,
        "account_signature_valid": None,
        "errors": errors,
        "boundary": (
            "Verification is offline and per-document. It proves both named keys signed this "
            "exact text, and that the delegation has not passed its expiry. It does not consult "
            "any registry, does not prove the controller still holds that key, and cannot see "
            "revocations - a reader that needs that must look for one."
        ),
    }

    def fail(code: str, message: str) -> None:
        errors.append({"code": code, "message": message})

    if not isinstance(document, Mapping):
        fail("malformed-document", "delegation must be a JSON object")
        return result
    if document.get("schema_version") != DELEGATION_SCHEMA:
        fail(
            "unsupported-schema",
            f"schema_version must be {DELEGATION_SCHEMA}",
        )
        return result

    result["delegation_id"] = document.get("delegation_id")
    result["coordinate"] = document.get("coordinate")
    result["cell_controller"] = document.get("cell_controller")
    result["delegated_account"] = document.get("delegated_account")
    result["scopes"] = document.get("scopes") if isinstance(document.get("scopes"), list) else []

    for code, message in _structural_problems(document):
        fail(code, message)

    # Freshness. A null expiry is permanent, not expired.
    expires_raw = document.get("expires_at_utc")
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if expires_raw is None:
        result["permanent"] = True
        result["expired"] = False
    else:
        result["permanent"] = False
        try:
            expires_at = parse_utc(expires_raw, "expires_at_utc")
            result["expired"] = expires_at <= moment
            if result["expired"]:
                fail("delegation-expired", "the delegation's validity window has passed")
        except ValueError as exc:
            fail("invalid-expiry", str(exc))
    try:
        parse_utc(document.get("issued_at_utc"), "issued_at_utc")
    except ValueError as exc:
        fail("invalid-issued-at", str(exc))

    # The security-critical step, in its single shared implementation.
    binding = check_message_binding(document, build=build_delegation_message)
    result["binding_ok"] = binding["bound"]
    if not binding["bound"]:
        fail(
            binding["code"],
            "the signed message does not match the delegation's fields; "
            "the signatures are over different content",
        )
    else:
        declared = document.get("message_sha256")
        if isinstance(declared, str) and declared != sha256_text(binding["message"]):
            fail("message-hash-mismatch", "message_sha256 does not match the message")

    if binding["bound"]:
        controller_check = verify_signature_over_message(
            address=document.get("cell_controller"),
            message=binding["message"],
            signature=document.get("controller_signature"),
            signature_verifier=signature_verifier,
            scheme=BIP322_SIMPLE,
        )
        result["controller_signature_valid"] = controller_check.get("valid")
        if not controller_check.get("checked"):
            fail(controller_check["code"], controller_check.get("detail") or "controller signature could not be checked")
        elif not controller_check.get("valid"):
            fail("invalid-controller-signature", controller_check.get("detail") or "BIP-322 signature invalid")

        account_check = verify_signature_over_message(
            address=document.get("delegated_account"),
            message=binding["message"],
            signature=document.get("account_signature"),
            signature_verifier=signature_verifier,
            scheme=EIP191_PERSONAL_SIGN,
        )
        result["account_signature_valid"] = account_check.get("valid")
        if not account_check.get("checked"):
            fail(account_check["code"], account_check.get("detail") or "account signature could not be checked")
        elif not account_check.get("valid"):
            fail("invalid-account-signature", account_check.get("detail") or "EIP-191 signature invalid")
    else:
        fail(
            "unverified-signature",
            "signatures not checked because the message is not bound to the delegation fields",
        )

    result["ok"] = not errors
    result["status"] = "delegation-valid" if result["ok"] else "delegation-invalid"
    return result


# --------------------------------------------------------------------------------------
# revocation
# --------------------------------------------------------------------------------------


def build_delegation_revocation(
    *,
    delegation: Mapping[str, Any],
    delegation_sha256: str,
    issued_at: datetime | None = None,
) -> Dict[str, Any]:
    issued = (issued_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    revocation: Dict[str, Any] = {
        "schema_version": REVOCATION_SCHEMA,
        "delegation_id": delegation.get("delegation_id"),
        "coordinate": delegation.get("coordinate"),
        "cell_controller": delegation.get("cell_controller"),
        "delegated_account": delegation.get("delegated_account"),
        "delegation_sha256": require_hash(delegation_sha256, "delegation_sha256"),
        "issued_at_utc": issued.isoformat(),
    }
    revocation["message"] = build_revocation_message(revocation)
    revocation["message_encoding"] = "UTF-8"
    revocation["message_sha256"] = sha256_text(revocation["message"])
    return revocation


def finalize_delegation_revocation(revocation: Mapping[str, Any], *, signature: str) -> Dict[str, Any]:
    if not isinstance(signature, str) or not signature.strip():
        raise ValueError("signature is required")
    result = dict(revocation)
    result["signature"] = signature
    result["signature_scheme"] = BIP322_SIMPLE
    result["message_encoding"] = "UTF-8"
    return result


def verify_delegation_revocation(
    document: Any,
    *,
    signature_verifier=None,
    now: datetime | None = None,
) -> Dict[str, Any]:
    """Verify a revocation. Only the Cell controller can revoke, so only one signature."""
    errors: list[Dict[str, Any]] = []
    result: Dict[str, Any] = {
        "ok": False,
        "schema_version": document.get("schema_version") if isinstance(document, Mapping) else None,
        "delegation_id": None,
        "delegation_sha256": None,
        "revoked_account": None,
        "binding_ok": False,
        "signature_valid": None,
        "errors": errors,
        "boundary": (
            "Verification proves the Cell controller signed this withdrawal of one specific "
            "delegation. It does not check whether the delegation existed, and it does not "
            "itself change any published state."
        ),
    }

    def fail(code: str, message: str) -> None:
        errors.append({"code": code, "message": message})

    if not isinstance(document, Mapping):
        fail("malformed-document", "revocation must be a JSON object")
        return result
    if document.get("schema_version") != REVOCATION_SCHEMA:
        fail("unsupported-schema", f"schema_version must be {REVOCATION_SCHEMA}")
        return result

    result["delegation_id"] = document.get("delegation_id")
    result["delegation_sha256"] = document.get("delegation_sha256")
    result["revoked_account"] = document.get("delegated_account")

    for code, fn in (
        ("invalid-delegation-id", lambda: require_delegation_id(document.get("delegation_id"))),
        ("invalid-coordinate", lambda: require_home_cell(document.get("coordinate"))),
        (
            "invalid-cell-controller",
            lambda: require_signer_address(document.get("cell_controller"), "cell_controller", BIP322_SIMPLE),
        ),
        ("invalid-delegation-hash", lambda: require_hash(document.get("delegation_sha256"), "delegation_sha256")),
    ):
        try:
            fn()
        except ValueError as exc:
            fail(code, str(exc))

    try:
        parse_utc(document.get("issued_at_utc"), "issued_at_utc")
    except ValueError as exc:
        fail("invalid-issued-at", str(exc))
    result["expired"] = False

    binding = check_message_binding(document, build=build_revocation_message)
    result["binding_ok"] = binding["bound"]
    if not binding["bound"]:
        fail(binding["code"], "the signed message does not match the revocation's fields")

    if binding["bound"]:
        check = verify_signature_over_message(
            address=document.get("cell_controller"),
            message=binding["message"],
            signature=document.get("signature"),
            signature_verifier=signature_verifier,
            scheme=BIP322_SIMPLE,
        )
        result["signature_valid"] = check.get("valid")
        if not check.get("checked"):
            fail(check["code"], check.get("detail") or "signature could not be checked")
        elif not check.get("valid"):
            fail("invalid-signature", check.get("detail") or "BIP-322 signature invalid")
    else:
        fail("unverified-signature", "signature not checked because the message is not bound")

    result["ok"] = not errors
    result["status"] = "revocation-valid" if result["ok"] else "revocation-invalid"
    return result
