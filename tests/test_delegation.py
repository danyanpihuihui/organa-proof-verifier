"""Tests for Cell account delegation - binding an EVM account to a Cell.

The acceptance test is `test_a_cell_can_delegate_to_an_evm_account`: the Cell's Bitcoin
controller and the EVM account both sign the same message, and the result verifies with both
signatures checked.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from bitmap_memory_portal.delegation import (
    DELEGATION_SCHEMA,
    REVOCATION_SCHEMA,
    build_account_delegation,
    build_delegation_revocation,
    finalize_account_delegation,
    finalize_delegation_revocation,
    verify_account_delegation,
    verify_delegation_revocation,
)
from bitmap_memory_portal.task_flow import (
    build_task_offer,
    finalize_signed_document,
    verify_task_offer,
)
from bitmap_memory_portal.signed_claims import (
    EIP191_PERSONAL_SIGN,
    sha256_text,
)

CONTROLLER = "bc1p4wz46fk45hp5crm56k4emxelln9tpuc76frn2duumlyecr9ft35qjxmadq"
OTHER_CONTROLLER = "bc1pother0000000000000000000000000000000000000000"
ACCOUNT = "0xB12d25a800659D909D52Dd07EFcD9239175aec9c"
OTHER_ACCOUNT = "0x9999999999999999999999999999999999999999"
MANIFEST = "sha256:" + "e" * 64
ISSUED = datetime(2026, 9, 19, 12, 0, 0, tzinfo=timezone.utc)
DELEGATION_FILE_HASH = "sha256:" + "a" * 64


def _accept(_claim):
    return {"signature_valid": True, "signature_verification": "test-stub-accept"}


def _reject(_claim):
    return {"signature_valid": False, "signature_verification": "test-stub-reject"}


def _codes(result):
    return [item["code"] for item in result["errors"]]


def _delegation(**overrides):
    kwargs = dict(
        delegation_id="7187-base-payout-account",
        coordinate="7187.bitmap",
        cell_controller=CONTROLLER,
        delegated_account=ACCOUNT,
        scopes=["publish-tasks", "receive-payment"],
        cell_manifests_sha256=[MANIFEST],
        issued_at=ISSUED,
        expires_at=None,
    )
    kwargs.update(overrides)
    return build_account_delegation(**kwargs)


def _signed_delegation(**overrides):
    return finalize_account_delegation(
        _delegation(**overrides),
        controller_signature="stub-bip322",
        account_signature="stub-eip191",
    )


# --------------------------------------------------------------------------------------
# the acceptance test
# --------------------------------------------------------------------------------------


def test_a_cell_can_delegate_to_an_evm_account():
    """The Cell's controller and the account both attest, permanently."""
    delegation = _signed_delegation()
    assert delegation["schema_version"] == DELEGATION_SCHEMA
    assert delegation["expires_at_utc"] is None

    result = verify_account_delegation(delegation, signature_verifier=_accept)
    assert result["ok"] is True
    assert result["status"] == "delegation-valid"
    assert result["binding_ok"] is True
    assert result["controller_signature_valid"] is True
    assert result["account_signature_valid"] is True
    assert result["permanent"] is True
    assert result["expired"] is False


def test_both_parties_sign_the_same_message():
    """Dual-signature over one message, not two separate statements."""
    delegation = _signed_delegation()
    assert "Cell Controller:" in delegation["message"]
    assert "Delegated Account:" in delegation["message"]
    assert delegation["message_sha256"] == sha256_text(delegation["message"])
    # The message must not name which scheme signs which side: the same bytes are signed both
    # ways, so it cannot claim to be one party's text rather than a joint one.
    assert CONTROLLER in delegation["message"]
    assert ACCOUNT in delegation["message"]


def test_a_permanent_delegation_says_so_in_the_signed_text():
    """A reader of the raw message must be able to tell it does not lapse."""
    delegation = _signed_delegation(expires_at=None)
    assert "no expiry date" in delegation["message"]
    assert "until a revocation" in delegation["message"]


def test_a_dated_delegation_does_not_claim_to_be_permanent():
    delegation = _signed_delegation(expires_at=ISSUED + timedelta(days=30))
    assert "no expiry date" not in delegation["message"]
    assert delegation["expires_at_utc"] is not None


# --------------------------------------------------------------------------------------
# both signatures are mandatory
# --------------------------------------------------------------------------------------


def test_a_controller_statement_alone_is_not_a_delegation():
    """Without the account's signature nobody has shown the account consents."""
    delegation = _delegation()
    delegation["controller_signature"] = "stub-bip322"
    delegation["account_signature"] = ""
    result = verify_account_delegation(delegation, signature_verifier=_accept)
    assert result["ok"] is False
    assert "missing-signature" in _codes(result)


def test_finalizing_requires_both_signatures():
    base = _delegation()
    with pytest.raises(ValueError, match="controller_signature"):
        finalize_account_delegation(base, controller_signature="", account_signature="x")
    with pytest.raises(ValueError, match="account_signature"):
        finalize_account_delegation(base, controller_signature="x", account_signature="")


def test_a_valid_controller_signature_with_no_provider_is_not_enough():
    """If the controller verifies and the account does not, it is not a delegation."""

    def only_controller(claim):
        is_controller = claim.get("signing_scheme") == "bip322-simple"
        return {
            "signature_valid": is_controller,
            "signature_verification": "stub",
        }

    result = verify_account_delegation(_signed_delegation(), signature_verifier=only_controller)
    assert result["ok"] is False
    assert result["controller_signature_valid"] is True
    assert result["account_signature_valid"] is False
    assert "invalid-account-signature" in _codes(result)


def test_a_provider_signature_with_no_controller_is_not_a_delegation():
    def only_account(claim):
        is_account = claim.get("signing_scheme") == "eip191-personal-sign"
        return {"signature_valid": is_account, "signature_verification": "stub"}

    result = verify_account_delegation(_signed_delegation(), signature_verifier=only_account)
    assert result["ok"] is False
    assert "invalid-controller-signature" in _codes(result)


def test_each_signature_is_checked_in_its_own_scheme():
    """Swapping the schemes would let an EVM key impersonate a Cell controller."""
    seen = []

    def spy(claim):
        seen.append((claim.get("signing_scheme"), claim.get("signing_address")))
        return {"signature_valid": True, "signature_verification": "spy"}

    verify_account_delegation(_signed_delegation(), signature_verifier=spy)
    assert ("bip322-simple", CONTROLLER) in seen
    assert ("eip191-personal-sign", ACCOUNT) in seen


# --------------------------------------------------------------------------------------
# fields are bound
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(delegated_account=OTHER_ACCOUNT),
        lambda d: d.update(cell_controller=OTHER_CONTROLLER),
        lambda d: d.update(scopes=["publish-tasks"]),
        lambda d: d.update(cell_manifests_sha256=["sha256:" + "f" * 64]),
        lambda d: d.update(expires_at_utc="2030-01-01T00:00:00+00:00"),
        lambda d: d.update(delegation_id="something-else"),
    ],
)
def test_editing_any_bound_field_breaks_the_binding(mutate):
    signed = _signed_delegation()
    tampered = json.loads(json.dumps(signed))
    mutate(tampered)
    result = verify_account_delegation(tampered, signature_verifier=_accept)
    assert result["ok"] is False
    assert "message-mismatch" in _codes(result)


def test_the_scopes_are_visible_in_the_signed_text():
    delegation = _signed_delegation(scopes=["publish-tasks", "receive-payment"])
    assert '"publish-tasks"' in delegation["message"]
    assert '"receive-payment"' in delegation["message"]


# --------------------------------------------------------------------------------------
# build-time refusals
# --------------------------------------------------------------------------------------


def test_self_delegation_is_impossible_by_construction():
    """An account cannot delegate to itself, because the two fields cannot hold one address.

    `cell_controller` must be a Bitcoin address and `delegated_account` must be an EVM
    address, so the self-check in `_structural_problems` can never fire through the builder.
    It is kept as defence in depth for a hand-written document, and this test pins the
    property that actually matters: no single value satisfies both fields.
    """
    # An EVM address cannot fill cell_controller...
    with pytest.raises(ValueError, match="EVM address but the scheme is"):
        _delegation(delegated_account=ACCOUNT, cell_controller=ACCOUNT)

    # ...and a Bitcoin address cannot fill delegated_account.
    with pytest.raises(ValueError, match="EVM address"):
        _delegation(delegated_account=CONTROLLER, cell_controller=CONTROLLER)

    # The guard itself still refuses a hand-written document that somehow holds one value.
    from bitmap_memory_portal.delegation import verify_account_delegation
    from bitmap_memory_portal.signed_claims import sha256_text

    forgeable = {
        "schema_version": DELEGATION_SCHEMA,
        "delegation_id": "self",
        "coordinate": "7187.bitmap",
        "cell_controller": ACCOUNT,
        "delegated_account": ACCOUNT,
        "scopes": ["publish-tasks"],
        "cell_manifests_sha256": [MANIFEST],
        "issued_at_utc": ISSUED.isoformat(),
        "expires_at_utc": None,
    }
    from bitmap_memory_portal.delegation import build_delegation_message

    forgeable["message"] = build_delegation_message(forgeable)
    forgeable["message_sha256"] = sha256_text(forgeable["message"])
    result = verify_account_delegation(forgeable, signature_verifier=_accept)
    assert result["ok"] is False
    assert "delegation-to-self" in _codes(result)


def test_a_bitcoin_address_cannot_be_the_delegated_account():
    with pytest.raises(ValueError, match="EVM address"):
        _delegation(delegated_account=CONTROLLER)


def test_an_unknown_scope_is_refused():
    with pytest.raises(ValueError, match="scopes must be drawn from"):
        _delegation(scopes=["do-anything"])


def test_at_least_one_manifest_digest_is_required():
    with pytest.raises(ValueError, match="at least one manifest digest"):
        _delegation(cell_manifests_sha256=[])


def test_an_expiry_before_issue_is_refused():
    with pytest.raises(ValueError, match="must be after issued_at"):
        _delegation(issued_at=ISSUED, expires_at=ISSUED - timedelta(days=1))


def test_an_expired_dated_delegation_is_rejected():
    past = datetime.now(timezone.utc) - timedelta(days=60)
    delegation = _signed_delegation(issued_at=past, expires_at=past + timedelta(days=30))
    result = verify_account_delegation(delegation, signature_verifier=_accept)
    assert result["ok"] is False
    assert "delegation-expired" in _codes(result)


def test_a_permanent_delegation_never_expires():
    old = datetime.now(timezone.utc) - timedelta(days=3650)
    delegation = _signed_delegation(issued_at=old, expires_at=None)
    result = verify_account_delegation(delegation, signature_verifier=_accept)
    assert result["ok"] is True
    assert result["expired"] is False


def test_the_result_states_what_it_did_not_check():
    result = verify_account_delegation(_signed_delegation(), signature_verifier=_accept)
    boundary = result["boundary"]
    assert "cannot see revocations" in boundary
    assert "does not consult any registry" in boundary


# --------------------------------------------------------------------------------------
# revocation
# --------------------------------------------------------------------------------------


def test_a_controller_can_revoke_a_delegation():
    delegation = _signed_delegation()
    revocation = build_delegation_revocation(
        delegation=delegation, delegation_sha256=DELEGATION_FILE_HASH, issued_at=ISSUED
    )
    signed = finalize_delegation_revocation(revocation, signature="stub-bip322")
    assert signed["schema_version"] == REVOCATION_SCHEMA
    result = verify_delegation_revocation(signed, signature_verifier=_accept)
    assert result["ok"] is True
    assert result["status"] == "revocation-valid"
    assert result["revoked_account"] == ACCOUNT


def test_a_revocation_binds_the_exact_delegation_hash():
    delegation = _signed_delegation()
    revocation = finalize_delegation_revocation(
        build_delegation_revocation(
            delegation=delegation, delegation_sha256=DELEGATION_FILE_HASH, issued_at=ISSUED
        ),
        signature="stub-bip322",
    )
    tampered = json.loads(json.dumps(revocation))
    tampered["delegation_sha256"] = "sha256:" + "b" * 64
    result = verify_delegation_revocation(tampered, signature_verifier=_accept)
    assert result["ok"] is False
    assert "message-mismatch" in _codes(result)


def test_a_revocation_needs_the_controller_not_the_account():
    """The account cannot revoke itself out of an authorisation it did not grant."""

    def only_account(claim):
        return {
            "signature_valid": claim.get("signing_scheme") == "eip191-personal-sign",
            "signature_verification": "stub",
        }

    delegation = _signed_delegation()
    signed = finalize_delegation_revocation(
        build_delegation_revocation(
            delegation=delegation, delegation_sha256=DELEGATION_FILE_HASH, issued_at=ISSUED
        ),
        signature="stub",
    )
    result = verify_delegation_revocation(signed, signature_verifier=only_account)
    assert result["ok"] is False
    assert "invalid-signature" in _codes(result)


# --------------------------------------------------------------------------------------
# the endpoint
# --------------------------------------------------------------------------------------


def test_the_endpoint_dispatches_both_document_types():
    from bitmap_memory_portal.proof_verifier import verify_delegation

    delegation = _signed_delegation()
    revocation = finalize_delegation_revocation(
        build_delegation_revocation(
            delegation=delegation, delegation_sha256=DELEGATION_FILE_HASH, issued_at=ISSUED
        ),
        signature="stub",
    )
    a = verify_delegation(delegation, signature_verifier=_accept)
    b = verify_delegation(revocation, signature_verifier=_accept)
    assert a["status"] == "delegation-valid"
    assert b["status"] == "revocation-valid"
    assert a["delegation"]["permanent"] is True


def test_an_unknown_schema_is_refused_by_the_endpoint():
    from bitmap_memory_portal.proof_verifier import verify_delegation

    result = verify_delegation({"schema_version": "nonsense"}, signature_verifier=_accept)
    assert result["ok"] is False
    assert "unsupported-schema" in [e["code"] for e in result["errors"]]


# --------------------------------------------------------------------------------------
# offers can now point at a delegation
# --------------------------------------------------------------------------------------


def _offer(**overrides):
    kwargs = dict(
        task_id="bitmap-price-audit-2026-09",
        signature_scheme=EIP191_PERSONAL_SIGN,
        requester_controller=ACCOUNT,
        requester_cell="7187.bitmap",
        task_type="verification-task",
        title="Reproduce the published series",
        purpose="Independent reproduction of the published daily mainstream price.",
        deliverables=[{"name": "report.md", "description": "Method and results."}],
        acceptance_criteria=["States every data source"],
        reward={
            "amount": "0.0001",
            "asset": "ETH",
            "chain": "base",
            "address": ACCOUNT,
            "payment_on": "on-acceptance",
        },
        issued_at=ISSUED,
    )
    kwargs.update(overrides)
    return build_task_offer(**kwargs)


def _authority(**overrides):
    authority = {
        "mode": "cell-account-delegation",
        "delegation_sha256": DELEGATION_FILE_HASH,
        "delegation_url": "https://danyanpihuihui.github.io/organa-cell-7187/versions/0.4.0/delegations/7187-base-payout-account.json",
        "delegated_account": ACCOUNT,
    }
    authority.update(overrides)
    return authority


def test_an_offer_can_cite_a_delegation_instead_of_declaring_a_cell():
    offer = finalize_signed_document(_offer(cell_authority=_authority()), "stub")
    assert "Cell Authority: cell-account-delegation" in offer["message"]
    assert "Delegation SHA-256:" in offer["message"]
    assert "Verify that delegation" in offer["message"]
    assert "not proven by it" not in offer["message"]
    result = verify_task_offer(offer, signature_verifier=_accept)
    assert result["ok"] is True
    assert result["cell_authority_mode"] == "cell-account-delegation"
    assert result["cell_authority_status"] == "delegated-pending-delegation-verification"
    assert result["delegation_sha256"] == DELEGATION_FILE_HASH


def test_without_a_delegation_the_offer_still_admits_the_cell_is_declared():
    """The old honest behaviour must not change for offers that cite nothing."""
    offer = finalize_signed_document(_offer(), "stub")
    assert "not proven by it" in offer["message"]
    result = verify_task_offer(offer, signature_verifier=_accept)
    assert result["ok"] is True
    assert result["cell_authority_status"] == "declared-not-proven"


def test_a_delegation_pointer_cannot_be_swapped_after_signing():
    offer = finalize_signed_document(_offer(cell_authority=_authority()), "stub")
    tampered = json.loads(json.dumps(offer))
    tampered["cell_authority"]["delegation_sha256"] = "sha256:" + "c" * 64
    result = verify_task_offer(tampered, signature_verifier=_accept)
    assert result["ok"] is False
    assert "message-mismatch" in _codes(result)


def test_a_delegation_that_authorises_a_different_account_is_refused():
    """Otherwise an offer could cite a delegation that grants someone else the authority."""
    with pytest.raises(ValueError, match="must be the same account that signs"):
        _offer(cell_authority=_authority(delegated_account=OTHER_ACCOUNT))


def test_a_bitcoin_signed_offer_cannot_claim_a_delegation():
    """The controller's own signature is already the strongest statement available.

    A delegation names an EVM account as the delegated party, and a Bitcoin-signed offer's
    requester is a Bitcoin address, so the two cannot describe the same party. The builder
    refuses this whichever check it reaches first; what matters is that it cannot be built.
    """
    with pytest.raises(ValueError, match="delegated_account"):
        _offer(
            signature_scheme="bip322-simple",
            requester_controller=CONTROLLER,
            cell_authority=_authority(),
        )


def test_a_hand_written_bitcoin_offer_with_a_delegation_is_refused():
    """Defence in depth: the verifier, not only the builder, refuses this combination."""
    offer = finalize_signed_document(
        _offer(signature_scheme="bip322-simple", requester_controller=CONTROLLER), "stub"
    )
    offer["cell_authority"] = _authority()
    result = verify_task_offer(offer, signature_verifier=_accept)
    assert result["ok"] is False
    assert "invalid-cell-authority" in _codes(result)


def test_an_offer_without_a_cell_cannot_cite_a_delegation():
    with pytest.raises(ValueError, match="cell_authority requires requester_cell"):
        _offer(requester_cell=None, cell_authority=_authority())


def test_a_controller_signed_offer_reports_controller_authority():
    offer = finalize_signed_document(
        _offer(signature_scheme="bip322-simple", requester_controller=CONTROLLER), "stub"
    )
    result = verify_task_offer(offer, signature_verifier=_accept)
    assert result["ok"] is True
    assert result["cell_authority_status"] == "controller-signed"


# --------------------------------------------------------------------------------------
# end to end at the script level
# --------------------------------------------------------------------------------------


def test_offer_and_delegation_agree_on_the_account():
    """The two documents must name the same account or the chain of authority is broken."""
    delegation = _signed_delegation()
    offer = finalize_signed_document(_offer(cell_authority=_authority()), "stub")
    assert delegation["delegated_account"].lower() == offer["requester_controller"].lower()
    assert delegation["coordinate"] == offer["requester_cell"]
