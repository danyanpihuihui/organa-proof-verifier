"""Organa Task Flow v0.1 - offer, claim, submission.

Before this module a task could only be *recorded* after the fact. There was no way for a
requester to publish work as available, no way for an agent to say it was taking the work,
and no way for it to hand in a result. The existing receipt chain starts at "authorized",
which presumes those conversations already happened somewhere off-protocol.

Three documents close that gap, and each is signed by the party who is actually making the
claim, over a message re-derived from its own fields:

======================  =====================  ==================================
document                signed by              means
======================  =====================  ==================================
``organa-task-offer``   requester controller   "this work is available, here are the terms"
``organa-task-claim``   agent controller       "I intend to submit for this task"
``organa-task-submission``  agent controller   "here is my result, bound to this offer"
======================  =====================  ==================================

Two deliberate design choices, both of which trade a little convenience for honesty:

* **Claims are non-exclusive.** There is no server, no queue and no lock, so no
  first-come claim could be enforced against concurrent submissions anyway. Pretending
  otherwise would be worse than saying so: a claim here is a public declaration of
  intent, and acceptance decides who is paid.
* **Nothing is fetched.** Verification is offline, so a verified submission proves which
  agent bound which hashes to which offer - not that the artifact exists or is any good.
  Every result says so in its ``boundary`` field.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Mapping

from .signed_claims import (
    BINDING_MISMATCH,
    CONTROL_RE,
    check_message_binding,
    build_message,
    normalize_https_url,
    parse_utc,
    reject_conflicting_aliases,
    require_address,
    require_agent_id,
    require_hash,
    require_home_cell,
    sha256_text,
    verify_signature_over_message,
)

OFFER_SCHEMA = "organa-task-offer-v0.1"
CLAIM_SCHEMA = "organa-task-claim-v0.1"
SUBMISSION_SCHEMA = "organa-task-submission-v0.1"

SCHEMAS = (OFFER_SCHEMA, CLAIM_SCHEMA, SUBMISSION_SCHEMA)

TASK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,79}$")
TASK_TYPE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")

DEFAULT_TTL_DAYS = 30

ACCEPTANCE_RULES = frozenset({"requester-evaluates", "first-valid-submission"})
CLAIM_POLICIES = frozenset({"non-exclusive"})
DISCLOSURE_LEVELS = frozenset(
    {"L1_HASH_PROOF", "L2_METADATA_PROOF", "L3_SELECTIVE_REVEAL", "L4_PUBLIC_PACKAGE"}
)
PAYMENT_STAGES = frozenset({"on-acceptance", "none"})

_OFFER_TITLE = "Organa Task Offer v0.1"
_CLAIM_TITLE = "Organa Task Claim v0.1"
_SUBMISSION_TITLE = "Organa Task Submission v0.1"

_OFFER_FOOTER = (
    "This offer states the terms under which the requester will evaluate and pay for work. "
    "It does not escrow funds, guarantee acceptance, or bind any party to a result."
)
_CLAIM_FOOTER = (
    "This claim records an intention to submit. It does not reserve the task, guarantee "
    "acceptance, or transfer any right; the same task may be claimed by others."
)
_SUBMISSION_FOOTER = (
    "This submission binds the named artifacts to this offer by hash. It does not prove the "
    "artifacts exist, that they meet the acceptance criteria, or that the work is correct."
)


# --------------------------------------------------------------------------------------
# deterministic message fragments
# --------------------------------------------------------------------------------------


def _json_fragment(value: Any) -> str:
    """Serialize a nested value deterministically, so builder and verifier always agree."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def require_task_id(value: Any) -> str:
    if not isinstance(value, str) or not TASK_ID_RE.fullmatch(value):
        raise ValueError("task_id must match ^[a-z0-9][a-z0-9._-]{2,79}$")
    return value


def _require_text(value: Any, field: str, *, limit: int = 400) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be non-empty text")
    if len(value) > limit:
        raise ValueError(f"{field} must be at most {limit} characters")
    if CONTROL_RE.search(value):
        raise ValueError(f"{field} must not contain control characters")
    return value


def _require_text_list(value: Any, field: str, *, max_items: int = 32) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field} must be a non-empty list")
    if len(value) > max_items:
        raise ValueError(f"{field} must contain at most {max_items} items")
    return [_require_text(item, f"{field}[]") for item in value]


def _require_reward(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("reward must be an object")
    amount = value.get("amount")
    if not isinstance(amount, str) or not re.fullmatch(r"^(0|[1-9][0-9]*)(\.[0-9]{1,18})?$", amount):
        raise ValueError("reward.amount must be a decimal string, e.g. \"50\" or \"12.5\"")
    if amount == "0":
        raise ValueError("reward.amount must be greater than zero")
    asset = value.get("asset")
    if not isinstance(asset, str) or not re.fullmatch(r"^[A-Z0-9]{2,10}$", asset):
        raise ValueError("reward.asset must be an uppercase symbol, e.g. USDC")
    chain = value.get("chain")
    if not isinstance(chain, str) or not re.fullmatch(r"^[a-z0-9-]{2,32}$", chain):
        raise ValueError("reward.chain must be a lowercase network name, e.g. base")
    address = _require_text(value.get("address"), "reward.address", limit=120)
    payment_on = value.get("payment_on")
    if payment_on not in PAYMENT_STAGES:
        raise ValueError(f"reward.payment_on must be one of {sorted(PAYMENT_STAGES)}")
    return {
        "amount": amount,
        "asset": asset,
        "chain": chain,
        "address": address,
        "payment_on": payment_on,
    }


def _require_deliverables(value: Any) -> list[Dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ValueError("deliverables must be a non-empty list")
    if len(value) > 16:
        raise ValueError("deliverables must contain at most 16 items")
    out: list[Dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError("each deliverable must be an object")
        out.append(
            {
                "name": _require_text(item.get("name"), "deliverables[].name", limit=160),
                "description": _require_text(
                    item.get("description"), "deliverables[].description", limit=400
                ),
            }
        )
    return out


def _require_artifacts(value: Any) -> list[Dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ValueError("artifacts must be a non-empty list")
    if len(value) > 32:
        raise ValueError("artifacts must contain at most 32 items")
    out: list[Dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError("each artifact must be an object")
        out.append(
            {
                "name": _require_text(item.get("name"), "artifacts[].name", limit=160),
                "url": normalize_https_url(item.get("url"), "artifacts[].url"),
                "sha256": require_hash(item.get("sha256"), "artifacts[].sha256"),
            }
        )
    return out


# --------------------------------------------------------------------------------------
# message builders - the wire format shared by builder and verifier
# --------------------------------------------------------------------------------------


def build_offer_message(claim: Mapping[str, Any]) -> str:
    return build_message(
        _OFFER_TITLE,
        "organa-task-offer",
        [
            f"Task ID: {claim.get('task_id')}",
            f"Requester Cell: {claim.get('requester_cell')}",
            f"Requester Controller: {claim.get('requester_controller')}",
            f"Task Type: {claim.get('task_type')}",
            f"Title: {claim.get('title')}",
            f"Acceptance Rule: {claim.get('acceptance_rule')}",
            f"Claim Policy: {claim.get('claim_policy')}",
            f"Disclosure Level: {claim.get('disclosure_level')}",
            f"Reward: {_json_fragment(claim.get('reward'))}",
            f"Deliverables: {_json_fragment(claim.get('deliverables'))}",
            f"Acceptance Criteria: {_json_fragment(claim.get('acceptance_criteria'))}",
            f"Issued at UTC: {claim.get('issued_at_utc')}",
            f"Expires at UTC: {claim.get('expires_at_utc')}",
        ],
        _OFFER_FOOTER,
    )


def build_claim_message(claim: Mapping[str, Any]) -> str:
    return build_message(
        _CLAIM_TITLE,
        "organa-task-claim",
        [
            f"Task ID: {claim.get('task_id')}",
            f"Offer SHA-256: {claim.get('offer_sha256')}",
            f"Agent ID: {claim.get('agent_id')}",
            f"Agent Controller: {claim.get('agent_controller')}",
            f"Intent: {claim.get('intent')}",
            f"Claim State: {claim.get('claim_state')}",
            f"Issued at UTC: {claim.get('issued_at_utc')}",
            f"Expires at UTC: {claim.get('expires_at_utc')}",
        ],
        _CLAIM_FOOTER,
    )


def build_submission_message(claim: Mapping[str, Any]) -> str:
    return build_message(
        _SUBMISSION_TITLE,
        "organa-task-submission",
        [
            f"Task ID: {claim.get('task_id')}",
            f"Offer SHA-256: {claim.get('offer_sha256')}",
            f"Claim SHA-256: {claim.get('claim_sha256')}",
            f"Agent ID: {claim.get('agent_id')}",
            f"Agent Controller: {claim.get('agent_controller')}",
            f"Artifacts: {_json_fragment(claim.get('artifacts'))}",
            f"Summary: {claim.get('summary')}",
            f"Issued at UTC: {claim.get('issued_at_utc')}",
            f"Expires at UTC: {claim.get('expires_at_utc')}",
        ],
        _SUBMISSION_FOOTER,
    )


# --------------------------------------------------------------------------------------
# builders
# --------------------------------------------------------------------------------------


def _window(issued_at: datetime | None, ttl_days: int) -> tuple[str, str]:
    if not isinstance(ttl_days, int) or ttl_days < 1:
        raise ValueError("ttl_days must be a positive integer")
    issued = (issued_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return issued.isoformat(), (issued + timedelta(days=ttl_days)).isoformat()


def build_task_offer(
    *,
    task_id: str,
    requester_cell: str,
    requester_controller: str,
    task_type: str,
    title: str,
    purpose: str,
    deliverables: Any,
    acceptance_criteria: Any,
    reward: Any,
    acceptance_rule: str = "requester-evaluates",
    disclosure_level: str = "L4_PUBLIC_PACKAGE",
    issued_at: datetime | None = None,
    ttl_days: int = DEFAULT_TTL_DAYS,
) -> Dict[str, Any]:
    """Build an unsigned, open task offer plus the exact message the requester must sign."""
    if acceptance_rule not in ACCEPTANCE_RULES:
        raise ValueError(f"acceptance_rule must be one of {sorted(ACCEPTANCE_RULES)}")
    if disclosure_level not in DISCLOSURE_LEVELS:
        raise ValueError(f"disclosure_level must be one of {sorted(DISCLOSURE_LEVELS)}")
    if not isinstance(task_type, str) or not TASK_TYPE_RE.fullmatch(task_type):
        raise ValueError("task_type must match ^[a-z0-9][a-z0-9-]{1,63}$")
    issued_str, expires_str = _window(issued_at, ttl_days)
    offer: Dict[str, Any] = {
        "schema_version": OFFER_SCHEMA,
        "task_id": require_task_id(task_id),
        "requester_cell": require_home_cell(requester_cell),
        "requester_controller": require_address(requester_controller),
        "task_type": task_type,
        "title": _require_text(title, "title"),
        "purpose": _require_text(purpose, "purpose"),
        "deliverables": _require_deliverables(deliverables),
        "acceptance_criteria": _require_text_list(acceptance_criteria, "acceptance_criteria"),
        "acceptance_rule": acceptance_rule,
        "claim_policy": "non-exclusive",
        "disclosure_level": disclosure_level,
        "reward": _require_reward(reward),
        "issued_at_utc": issued_str,
        "expires_at_utc": expires_str,
    }
    offer["message"] = build_offer_message(offer)
    offer["message_encoding"] = "UTF-8"
    offer["message_sha256"] = sha256_text(offer["message"])
    return offer


def build_task_claim(
    *,
    task_id: str,
    offer_sha256: str,
    agent_id: str,
    agent_controller: str,
    intent: str,
    issued_at: datetime | None = None,
    ttl_days: int = DEFAULT_TTL_DAYS,
) -> Dict[str, Any]:
    """Build an unsigned claim on an offer. Non-exclusive by construction."""
    issued_str, expires_str = _window(issued_at, ttl_days)
    claim: Dict[str, Any] = {
        "schema_version": CLAIM_SCHEMA,
        "task_id": require_task_id(task_id),
        "offer_sha256": require_hash(offer_sha256, "offer_sha256"),
        "agent_id": require_agent_id(agent_id),
        "agent_controller": require_address(agent_controller),
        "intent": _require_text(intent, "intent"),
        "claim_state": "non-exclusive",
        "issued_at_utc": issued_str,
        "expires_at_utc": expires_str,
    }
    claim["message"] = build_claim_message(claim)
    claim["message_encoding"] = "UTF-8"
    claim["message_sha256"] = sha256_text(claim["message"])
    return claim


def build_task_submission(
    *,
    task_id: str,
    offer_sha256: str,
    agent_id: str,
    agent_controller: str,
    artifacts: Any,
    summary: str,
    claim_sha256: str | None = None,
    issued_at: datetime | None = None,
    ttl_days: int = DEFAULT_TTL_DAYS,
) -> Dict[str, Any]:
    """Build an unsigned submission binding self-hosted artifacts to an offer by hash."""
    issued_str, expires_str = _window(issued_at, ttl_days)
    submission: Dict[str, Any] = {
        "schema_version": SUBMISSION_SCHEMA,
        "task_id": require_task_id(task_id),
        "offer_sha256": require_hash(offer_sha256, "offer_sha256"),
        "claim_sha256": require_hash(claim_sha256, "claim_sha256") if claim_sha256 else None,
        "agent_id": require_agent_id(agent_id),
        "agent_controller": require_address(agent_controller),
        "artifacts": _require_artifacts(artifacts),
        "summary": _require_text(summary, "summary"),
        "issued_at_utc": issued_str,
        "expires_at_utc": expires_str,
    }
    submission["message"] = build_submission_message(submission)
    submission["message_encoding"] = "UTF-8"
    submission["message_sha256"] = sha256_text(submission["message"])
    return submission


def finalize_signed_document(document: Mapping[str, Any], signature: str) -> Dict[str, Any]:
    """Attach a BIP-322 signature to any task document and re-stamp the message hash."""
    if not isinstance(document, Mapping):
        raise ValueError("document must be an object")
    if document.get("schema_version") not in SCHEMAS:
        raise ValueError(f"schema_version must be one of {list(SCHEMAS)}")
    if not isinstance(signature, str) or not signature.strip():
        raise ValueError("signature must be a non-empty string")
    message = document.get("message")
    if not isinstance(message, str) or not message:
        raise ValueError("document is missing the message to be signed")
    finalized = dict(document)
    finalized["signature"] = signature
    finalized["signature_method"] = "BIP-322-simple-message-signature"
    finalized["message_sha256"] = sha256_text(message)
    return finalized


# --------------------------------------------------------------------------------------
# verification
# --------------------------------------------------------------------------------------


def _structural_problems(claim: Mapping[str, Any], schema: str) -> list[tuple[str, str]]:
    problems: list[tuple[str, str]] = []

    def check(code: str, fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except ValueError as exc:
            problems.append((code, str(exc)))
            return None

    check("invalid-task-id", lambda: require_task_id(claim.get("task_id")))

    if schema == OFFER_SCHEMA:
        check("invalid-requester-cell", lambda: require_home_cell(claim.get("requester_cell")))
        check(
            "invalid-requester-controller",
            lambda: require_address(claim.get("requester_controller")),
        )
        check("invalid-task-type", lambda: _check_task_type(claim.get("task_type")))
        check("invalid-title", lambda: _require_text(claim.get("title"), "title"))
        check("invalid-purpose", lambda: _require_text(claim.get("purpose"), "purpose"))
        check("invalid-deliverables", lambda: _require_deliverables(claim.get("deliverables")))
        check(
            "invalid-acceptance-criteria",
            lambda: _require_text_list(claim.get("acceptance_criteria"), "acceptance_criteria"),
        )
        check("invalid-reward", lambda: _require_reward(claim.get("reward")))
        if claim.get("acceptance_rule") not in ACCEPTANCE_RULES:
            problems.append(("invalid-acceptance-rule", "acceptance_rule is not recognised"))
        if claim.get("claim_policy") not in CLAIM_POLICIES:
            problems.append(("invalid-claim-policy", "claim_policy must be non-exclusive"))
        if claim.get("disclosure_level") not in DISCLOSURE_LEVELS:
            problems.append(("invalid-disclosure-level", "disclosure_level is not recognised"))
    elif schema == CLAIM_SCHEMA:
        check("invalid-offer-hash", lambda: require_hash(claim.get("offer_sha256"), "offer_sha256"))
        check("invalid-agent-id", lambda: require_agent_id(claim.get("agent_id")))
        check(
            "invalid-agent-controller",
            lambda: require_address(claim.get("agent_controller")),
        )
        check("invalid-intent", lambda: _require_text(claim.get("intent"), "intent"))
        if claim.get("claim_state") != "non-exclusive":
            problems.append(
                ("invalid-claim-state", "claim_state must be non-exclusive: a claim cannot reserve a task")
            )
    elif schema == SUBMISSION_SCHEMA:
        check("invalid-offer-hash", lambda: require_hash(claim.get("offer_sha256"), "offer_sha256"))
        check("invalid-agent-id", lambda: require_agent_id(claim.get("agent_id")))
        check(
            "invalid-agent-controller",
            lambda: require_address(claim.get("agent_controller")),
        )
        check("invalid-artifacts", lambda: _require_artifacts(claim.get("artifacts")))
        check("invalid-summary", lambda: _require_text(claim.get("summary"), "summary"))
        if claim.get("claim_sha256") is not None:
            check(
                "invalid-claim-hash",
                lambda: require_hash(claim.get("claim_sha256"), "claim_sha256"),
            )

    return problems


def _check_task_type(value: Any) -> str:
    if not isinstance(value, str) or not TASK_TYPE_RE.fullmatch(value):
        raise ValueError("task_type must match ^[a-z0-9][a-z0-9-]{1,63}$")
    return value


ALIASED_BLOCKS: Dict[str, list[tuple[str, tuple[str, ...]]]] = {
    OFFER_SCHEMA: [("reward", ("address", "amount", "asset", "chain"))],
    CLAIM_SCHEMA: [],
    SUBMISSION_SCHEMA: [],
}


def verify_task_document(
    document: Any,
    *,
    signature_verifier: Callable[[Dict[str, Any]], Dict[str, Any]] | None = None,
    now: datetime | None = None,
) -> Dict[str, Any]:
    """Verify any organa-task-* document: structure, binding, freshness, signature."""
    errors: list[Dict[str, str]] = []
    warnings: list[str] = []

    def fail(code: str, message: str) -> None:
        errors.append({"code": code, "message": message})

    result: Dict[str, Any] = {
        "ok": False,
        "schema_version": None,
        "task_id": None,
        "signer_role": None,
        "signer_address": None,
        "binding_ok": False,
        "signature_valid": None,
        "expired": None,
        "errors": errors,
        "warnings": warnings,
        "boundary": (
            "Verification is offline: it proves structure, the signed binding and freshness. "
            "It does not fetch any URL, so it does not prove an artifact exists, that a reward "
            "is funded, or that the work satisfies the acceptance criteria."
        ),
    }

    if not isinstance(document, Mapping):
        fail("malformed-document", "document must be a JSON object")
        return result

    schema = document.get("schema_version")
    result["schema_version"] = schema
    if schema not in SCHEMAS:
        fail("unsupported-schema", f"schema_version must be one of {list(SCHEMAS)}")
        return result

    builder = {
        OFFER_SCHEMA: build_offer_message,
        CLAIM_SCHEMA: build_claim_message,
        SUBMISSION_SCHEMA: build_submission_message,
    }[schema]
    signer_field, signer_role = {
        OFFER_SCHEMA: ("requester_controller", "requester"),
        CLAIM_SCHEMA: ("agent_controller", "claimant-agent"),
        SUBMISSION_SCHEMA: ("agent_controller", "submitting-agent"),
    }[schema]
    result["task_id"] = document.get("task_id")
    result["signer_role"] = signer_role

    for code, message in _structural_problems(document, schema):
        fail(code, message)

    for conflict in reject_conflicting_aliases(document, ALIASED_BLOCKS[schema]):
        fail("conflicting-alias", conflict)

    # Freshness.
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    try:
        expires_at = parse_utc(document.get("expires_at_utc"), "expires_at_utc")
        result["expired"] = expires_at <= moment
        if result["expired"]:
            fail("document-expired", "the document's validity window has passed")
    except ValueError as exc:
        fail("invalid-expiry", str(exc))
    try:
        parse_utc(document.get("issued_at_utc"), "issued_at_utc")
    except ValueError as exc:
        fail("invalid-issued-at", str(exc))

    # The security-critical step, in its single implementation.
    binding = check_message_binding(document, build=builder)
    result["binding_ok"] = binding["bound"]
    if not binding["bound"]:
        fail(
            binding["code"],
            "the signed message does not match the document's fields; "
            "the signature is over different content",
        )
    else:
        declared = document.get("message_sha256")
        if isinstance(declared, str) and declared != sha256_text(binding["message"]):
            fail("message-hash-mismatch", "message_sha256 does not match the message")

    address = document.get(signer_field)
    result["signer_address"] = address

    if binding["bound"]:
        verification = verify_signature_over_message(
            address=address,
            message=binding["message"],
            signature=document.get("signature"),
            signature_verifier=signature_verifier,
        )
        result["signature_valid"] = verification.get("valid")
        if not verification.get("checked"):
            fail(
                verification["code"],
                verification.get("detail") or "signature could not be checked",
            )
        elif not verification.get("valid"):
            fail("invalid-signature", verification.get("detail") or "BIP-322 signature invalid")
    else:
        # Asking a verifier about an unbound message would prove nothing useful.
        fail(
            "unverified-signature",
            "signature not checked because the message is not bound to the document fields",
        )

    if errors:
        result["warnings"].extend(
            ["A failure here says nothing about the honesty of the parties, only about these bytes."]
        )

    result["ok"] = not errors
    return result


def verify_task_offer(document: Any, **kwargs: Any) -> Dict[str, Any]:
    """Verify a task offer. Rejects documents of any other type."""
    result = verify_task_document(document, **kwargs)
    if result["schema_version"] is not None and result["schema_version"] != OFFER_SCHEMA:
        result["ok"] = False
        result["errors"].insert(
            0, {"code": "wrong-document-type", "message": f"expected {OFFER_SCHEMA}"}
        )
    return result


def verify_task_claim(document: Any, **kwargs: Any) -> Dict[str, Any]:
    """Verify a non-exclusive task claim."""
    result = verify_task_document(document, **kwargs)
    if result["schema_version"] is not None and result["schema_version"] != CLAIM_SCHEMA:
        result["ok"] = False
        result["errors"].insert(
            0, {"code": "wrong-document-type", "message": f"expected {CLAIM_SCHEMA}"}
        )
    return result


def verify_task_submission(document: Any, **kwargs: Any) -> Dict[str, Any]:
    """Verify a task submission binding self-hosted artifacts to an offer by hash."""
    result = verify_task_document(document, **kwargs)
    if result["schema_version"] is not None and result["schema_version"] != SUBMISSION_SCHEMA:
        result["ok"] = False
        result["errors"].insert(
            0, {"code": "wrong-document-type", "message": f"expected {SUBMISSION_SCHEMA}"}
        )
    return result


def offer_sha256(offer: Mapping[str, Any]) -> str:
    """Stable digest of an offer, for claims and submissions to bind against.

    Over the *canonical serialization of the signed document*, so it covers the signature
    too: two offers with identical terms but different signatures are different offers.
    """
    payload = json.dumps(dict(offer), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256_text(payload)


def dump_task_document(document: Mapping[str, Any]) -> str:
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"
