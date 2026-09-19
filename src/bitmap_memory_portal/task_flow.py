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
    DEFAULT_SIGNATURE_SCHEME,
    EIP191_PERSONAL_SIGN,
    EVM_ADDRESS_RE,
    SCHEME_NETWORK_LABEL,
    SIGNATURE_SCHEMES,
    check_message_binding,
    build_message,
    normalize_https_url,
    parse_utc,
    reject_conflicting_aliases,
    require_address,
    require_agent_id,
    require_hash,
    require_home_cell,
    require_signer_address,
    require_supported_scheme,
    signature_scheme_of,
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

DELEGATION_MODE = "cell-account-delegation"
CONTROLLER_MODE = "cell-controller"

CELL_STATUS_FOOTER = {
    DELEGATION_MODE: (
        "The requester's authority to speak for this Cell rests on a delegation recorded by "
        "the cell_authority field: the Cell controller delegated to this account, and the "
        "account accepted. Verify that delegation; this offer does not carry it."
    ),
    CONTROLLER_MODE: (
        "The declared cell affiliation is not proven by it: binding an EVM account to a Cell "
        "requires a separate delegation the requester has not supplied."
    ),
}

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


def _require_cell_authority(value: Any, *, requester_controller: str) -> Dict[str, Any]:
    """Validate how the requester claims to speak for the Cell.

    The delegation itself is not carried here - only a pointer to it. Embedding the whole
    document would mean this offer's validity depended on reading a second document, and
    the verifier is offline by design.
    """
    if not isinstance(value, Mapping):
        raise ValueError("cell_authority must be an object")
    mode = value.get("mode")
    if mode != DELEGATION_MODE:
        raise ValueError(
            f"cell_authority.mode must be {DELEGATION_MODE!r}; "
            f"omit cell_authority entirely to declare {CONTROLLER_MODE!r}"
        )
    digest = require_hash(value.get("delegation_sha256"), "cell_authority.delegation_sha256")
    url = normalize_https_url(value.get("delegation_url"), "cell_authority.delegation_url")
    account = value.get("delegated_account")
    if not isinstance(account, str) or not EVM_ADDRESS_RE.fullmatch(account):
        raise ValueError("cell_authority.delegated_account must be an EVM address")
    if account.lower() != str(requester_controller).lower():
        raise ValueError(
            "cell_authority.delegated_account must be the same account that signs the offer; "
            "otherwise the delegation would authorise a different party than the one bound"
        )
    return {
        "mode": DELEGATION_MODE,
        "delegation_sha256": digest,
        "delegation_url": url,
        "delegated_account": account,
    }


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


def _scheme_header(claim: Mapping[str, Any]) -> list[str] | None:
    """Header lines for a signed message, or None for BIP-322.

    None (not the empty list) is load-bearing: `build_message` treats None as "emit the
    legacy Bitcoin network line", so a BIP-322 message stays byte-identical to the ones
    signed before ``signature_scheme`` existed and old signatures keep verifying.
    """
    if signature_scheme_of(claim) != EIP191_PERSONAL_SIGN:
        return None
    return [f"Signature scheme: {EIP191_PERSONAL_SIGN}", SCHEME_NETWORK_LABEL[EIP191_PERSONAL_SIGN]]


def offer_footer(scheme: str, has_cell: bool, authority_mode: str = CONTROLLER_MODE) -> str:
    """Spell out what this offer's signature does and does not establish."""
    parts = [_OFFER_FOOTER]
    if scheme == EIP191_PERSONAL_SIGN:
        parts.append(
            "The signature proves control of the requester account only."
        )
        if has_cell:
            parts.append(CELL_STATUS_FOOTER.get(authority_mode, CELL_STATUS_FOOTER[CONTROLLER_MODE]))
    return " ".join(parts)


def build_offer_message(claim: Mapping[str, Any]) -> str:
    scheme = signature_scheme_of(claim)
    has_cell = isinstance(claim.get("requester_cell"), str) and bool(claim.get("requester_cell"))
    authority = claim.get("cell_authority")
    authority_mode = ""
    authority_digest = None
    if isinstance(authority, Mapping):
        authority_mode = str(authority.get("mode") or "")
        authority_digest = authority.get("delegation_sha256")
    if scheme == EIP191_PERSONAL_SIGN:
        signer_line = f"Requester Account: {claim.get('requester_controller')}"
    else:
        signer_line = f"Requester Controller: {claim.get('requester_controller')}"
    body = [
        f"Task ID: {claim.get('task_id')}",
    ]
    if has_cell:
        # In the EVM case the cell is a claim the signature cannot back, and the signed
        # text says so rather than letting a reader assume authority was established.
        cell_label = "Requester Cell (declared)" if scheme == EIP191_PERSONAL_SIGN else "Requester Cell"
        body.append(f"{cell_label}: {claim.get('requester_cell')}")
        if authority_mode:
            body.append(f"Cell Authority: {authority_mode}")
            body.append(f"Delegation SHA-256: {authority_digest}")
    body.extend(
        [
            signer_line,
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
        ]
    )
    return build_message(
        _OFFER_TITLE,
        "organa-task-offer",
        body,
        offer_footer(scheme, has_cell, authority_mode or CONTROLLER_MODE),
        header=[
            f"Signature scheme: {scheme}",
            SCHEME_NETWORK_LABEL.get(scheme, ""),
        ],
    )


def build_claim_message(claim: Mapping[str, Any]) -> str:
    """The exact bytes an agent signs to claim a task.

    An agent's own key signs this, so it may be either a Bitcoin key or an EVM account -
    whichever the agent already operates. ``header`` returns None for BIP-322 so the
    message is byte-identical to documents signed before this field existed.
    """
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
        header=_scheme_header(claim),
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
        header=_scheme_header(claim),
    )


# --------------------------------------------------------------------------------------
# builders
# --------------------------------------------------------------------------------------


def _require_scheme(scheme: Any) -> str:
    if scheme not in SIGNATURE_SCHEMES:
        raise ValueError(f"signature_scheme must be one of {sorted(SIGNATURE_SCHEMES)}")
    return scheme


def _window(issued_at: datetime | None, ttl_days: int) -> tuple[str, str]:
    if not isinstance(ttl_days, int) or ttl_days < 1:
        raise ValueError("ttl_days must be a positive integer")
    issued = (issued_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return issued.isoformat(), (issued + timedelta(days=ttl_days)).isoformat()


def build_task_offer(
    *,
    task_id: str,
    requester_cell: str | None,
    requester_controller: str,
    task_type: str,
    title: str,
    purpose: str,
    deliverables: Any,
    acceptance_criteria: Any,
    reward: Any,
    acceptance_rule: str = "requester-evaluates",
    disclosure_level: str = "L4_PUBLIC_PACKAGE",
    signature_scheme: str = DEFAULT_SIGNATURE_SCHEME,
    cell_authority: Any = None,
    issued_at: datetime | None = None,
    ttl_days: int = DEFAULT_TTL_DAYS,
) -> Dict[str, Any]:
    """Build an unsigned, open task offer plus the exact message the requester must sign.

    ``signature_scheme`` chooses who can sign it. ``bip322-simple`` is a Cell controller's
    Bitcoin key and requires a ``requester_cell``, because the Bitcoin path exists to
    express Cell authority. ``eip191-personal-sign`` is an EVM account and takes an
    optional, explicitly unproven ``requester_cell``.
    """
    if signature_scheme not in SIGNATURE_SCHEMES:
        raise ValueError(f"signature_scheme must be one of {sorted(SIGNATURE_SCHEMES)}")
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
        "signature_scheme": signature_scheme,
        "requester_controller": require_signer_address(
            requester_controller, "requester_controller", signature_scheme
        ),
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
    if requester_cell is None:
        if signature_scheme != EIP191_PERSONAL_SIGN:
            raise ValueError(
                "requester_cell is required when signature_scheme is "
                f"{signature_scheme}: the Bitcoin path exists to express Cell authority"
            )
        if cell_authority is not None:
            # Silently dropping it would publish an offer whose declared authority vanished
            # between the caller's intent and the signed bytes.
            raise ValueError(
                "cell_authority requires requester_cell: a delegation names the Cell the "
                "account speaks for, so an offer cannot cite one while declaring no Cell"
            )
    else:
        if cell_authority is not None:
            offer["cell_authority"] = _require_cell_authority(
                cell_authority, requester_controller=offer["requester_controller"]
            )
        offer["requester_cell"] = require_home_cell(requester_cell)
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
    signature_scheme: str = DEFAULT_SIGNATURE_SCHEME,
    issued_at: datetime | None = None,
    ttl_days: int = DEFAULT_TTL_DAYS,
) -> Dict[str, Any]:
    """Build an unsigned claim on an offer. Non-exclusive by construction.

    ``signature_scheme`` is the agent's own choice: an agent that operates an EVM account
    should not have to find a Bitcoin key to accept work.
    """
    _require_scheme(signature_scheme)
    issued_str, expires_str = _window(issued_at, ttl_days)
    claim: Dict[str, Any] = {
        "schema_version": CLAIM_SCHEMA,
        "task_id": require_task_id(task_id),
        "offer_sha256": require_hash(offer_sha256, "offer_sha256"),
        "agent_id": require_agent_id(agent_id),
        "signature_scheme": signature_scheme,
        "agent_controller": require_signer_address(
            agent_controller, "agent_controller", signature_scheme
        ),
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
    signature_scheme: str = DEFAULT_SIGNATURE_SCHEME,
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
        "signature_scheme": _require_scheme(signature_scheme),
        "agent_controller": require_signer_address(
            agent_controller, "agent_controller", signature_scheme
        ),
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
        scheme = signature_scheme_of(claim)
        check("invalid-signature-scheme", lambda: require_supported_scheme(claim))
        if scheme == EIP191_PERSONAL_SIGN:
            if claim.get("requester_cell") is not None:
                check(
                    "invalid-requester-cell",
                    lambda: require_home_cell(claim.get("requester_cell")),
                )
        else:
            check(
                "invalid-requester-cell",
                lambda: require_home_cell(claim.get("requester_cell")),
            )
        check(
            "invalid-requester-controller",
            lambda: require_signer_address(
                claim.get("requester_controller"), "requester_controller", scheme
            ),
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
        if claim.get("cell_authority") is not None:
            check(
                "invalid-cell-authority",
                lambda: _require_cell_authority(
                    claim.get("cell_authority"),
                    requester_controller=claim.get("requester_controller") or "",
                ),
            )
            if scheme != EIP191_PERSONAL_SIGN:
                problems.append(
                    (
                        "invalid-cell-authority",
                        "cell_authority applies only to an EVM-signed offer; a "
                        "Bitcoin controller is already proven by its own signature",
                    )
                )
        if claim.get("acceptance_rule") not in ACCEPTANCE_RULES:
            problems.append(("invalid-acceptance-rule", "acceptance_rule is not recognised"))
        if claim.get("claim_policy") not in CLAIM_POLICIES:
            problems.append(("invalid-claim-policy", "claim_policy must be non-exclusive"))
        if claim.get("disclosure_level") not in DISCLOSURE_LEVELS:
            problems.append(("invalid-disclosure-level", "disclosure_level is not recognised"))
    elif schema == CLAIM_SCHEMA:
        _claim_scheme = signature_scheme_of(claim)
        check("invalid-signature-scheme", lambda: require_supported_scheme(claim))
        check("invalid-offer-hash", lambda: require_hash(claim.get("offer_sha256"), "offer_sha256"))
        check("invalid-agent-id", lambda: require_agent_id(claim.get("agent_id")))
        check(
            "invalid-agent-controller",
            lambda: require_signer_address(
                claim.get("agent_controller"), "agent_controller", _claim_scheme
            ),
        )
        check("invalid-intent", lambda: _require_text(claim.get("intent"), "intent"))
        if claim.get("claim_state") != "non-exclusive":
            problems.append(
                ("invalid-claim-state", "claim_state must be non-exclusive: a claim cannot reserve a task")
            )
    elif schema == SUBMISSION_SCHEMA:
        _sub_scheme = signature_scheme_of(claim)
        check("invalid-signature-scheme", lambda: require_supported_scheme(claim))
        check("invalid-offer-hash", lambda: require_hash(claim.get("offer_sha256"), "offer_sha256"))
        check("invalid-agent-id", lambda: require_agent_id(claim.get("agent_id")))
        check(
            "invalid-agent-controller",
            lambda: require_signer_address(
                claim.get("agent_controller"), "agent_controller", _sub_scheme
            ),
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

    # Every task document now binds its own scheme: the header is part of the signed
    # message, so an edited scheme makes the binding check fail before the signature is
    # even consulted. Absent means BIP-322, which keeps pre-existing documents verifying.
    scheme = signature_scheme_of(document)
    result["signature_scheme"] = scheme
    # What a reader may conclude about the requester's right to speak for the Cell. This is
    # the whole point of the delegation: without one the cell is a claim the signature
    # cannot back, and saying so is more useful than a boolean.
    if schema == OFFER_SCHEMA:
        authority = document.get("cell_authority")
        if isinstance(authority, Mapping):
            result["cell_authority_mode"] = DELEGATION_MODE
            result["cell_authority_status"] = "delegated-pending-delegation-verification"
            result["cell_authority_note"] = (
                "This offer points at a Cell account delegation. Verify it separately; a valid "
                "delegation makes this account's signatures attributable to the Cell. This "
                "response does not fetch or check the delegation."
            )
            result["delegation_sha256"] = authority.get("delegation_sha256")
            result["delegation_url"] = authority.get("delegation_url")
        elif document.get("requester_cell") is not None and scheme == EIP191_PERSONAL_SIGN:
            result["cell_authority_mode"] = CONTROLLER_MODE
            result["cell_authority_status"] = "declared-not-proven"
            result["cell_authority_note"] = (
                "The cell affiliation is declared only. The signature proves control of the "
                "requester account, not that the account acts for the Cell."
            )
        elif document.get("requester_cell") is not None:
            result["cell_authority_mode"] = CONTROLLER_MODE
            result["cell_authority_status"] = "controller-signed"
            result["cell_authority_note"] = (
                "Signed by the Cell controller's own Bitcoin key."
            )

    address = document.get(signer_field)
    result["signer_address"] = address

    if binding["bound"]:
        verification = verify_signature_over_message(
            address=address,
            message=binding["message"],
            signature=document.get("signature"),
            signature_verifier=signature_verifier,
            scheme=scheme,
        )
        result["signature_valid"] = verification.get("valid")
        if not verification.get("checked"):
            fail(
                verification["code"],
                verification.get("detail") or "signature could not be checked",
            )
        elif not verification.get("valid"):
            fail(
                "invalid-signature",
                verification.get("detail") or f"{scheme} signature invalid",
            )
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
