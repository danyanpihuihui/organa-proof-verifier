"""Tests for Organa Task Flow v0.1 - offer, claim, submission.

The acceptance test for the whole flow is `test_full_open_claim_submit_flow`: a requester
publishes work, an agent claims it and hands in a result, and each document verifies
independently against its own signature.
"""

import json
import threading
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from bitmap_memory_portal.task_flow import (
    CLAIM_SCHEMA,
    OFFER_SCHEMA,
    SUBMISSION_SCHEMA,
    build_task_claim,
    build_task_offer,
    build_task_submission,
    finalize_signed_document,
    offer_sha256,
    verify_task_claim,
    verify_task_document,
    verify_task_offer,
    verify_task_submission,
)
from bitmap_memory_portal.verifier_http import create_server

REQUESTER = "bc1prequester0000000000000000000000000000000000"
AGENT = "bc1pagent00000000000000000000000000000000000000"
OTHER_AGENT = "bc1pother0000000000000000000000000000000000000"
PAYOUT = "0x1111111111111111111111111111111111111111"
ISSUED = datetime(2026, 9, 19, 12, 0, 0, tzinfo=timezone.utc)
SHA = "sha256:" + "a" * 64
ARTIFACT_SHA = "sha256:" + "7" * 64


def _accept(_claim):
    return {"signature_valid": True, "signature_verification": "test-stub-accept"}


def _reject(_claim):
    return {"signature_valid": False, "signature_verification": "test-stub-reject"}


def _codes(result):
    return [item["code"] for item in result["errors"]]


def _reward(**overrides):
    reward = {
        "amount": "50",
        "asset": "USDC",
        "chain": "base",
        "address": PAYOUT,
        "payment_on": "on-acceptance",
    }
    reward.update(overrides)
    return reward


def _offer(**overrides):
    kwargs = dict(
        task_id="bitmap-price-audit-2026-09",
        requester_cell="7187.bitmap",
        requester_controller=REQUESTER,
        task_type="verification-task",
        title="Check the Bitmap mainstream price series",
        purpose="Independently reproduce the published daily mainstream price for 30 days.",
        deliverables=[
            {"name": "report.md", "description": "Method, data and per-day findings."}
        ],
        acceptance_criteria=["Every retained trade is accounted for", "Method is reproducible"],
        reward=_reward(),
        issued_at=ISSUED,
    )
    kwargs.update(overrides)
    return build_task_offer(**kwargs)


def _signed_offer(**overrides):
    return finalize_signed_document(_offer(**overrides), "stub-signature")


def _claim(offer, **overrides):
    kwargs = dict(
        task_id=offer["task_id"],
        offer_sha256=offer_sha256(offer),
        agent_id="outsider-agent",
        agent_controller=AGENT,
        intent="I intend to independently reproduce the series and publish my method.",
        issued_at=ISSUED,
    )
    kwargs.update(overrides)
    return build_task_claim(**kwargs)


def _signed_claim(offer, **overrides):
    return finalize_signed_document(_claim(offer, **overrides), "stub-signature")


def _signed_submission(offer, claim=None, **overrides):
    kwargs = dict(
        task_id=offer["task_id"],
        offer_sha256=offer_sha256(offer),
        agent_id="outsider-agent",
        agent_controller=AGENT,
        artifacts=[
            {
                "name": "report.md",
                "url": "https://outsider.example/submissions/report.md",
                "sha256": ARTIFACT_SHA,
            }
        ],
        summary="Reproduced all 28 traded days; two days needed cross-day correction.",
        claim_sha256=offer_sha256(claim) if claim else None,
        issued_at=ISSUED,
    )
    kwargs.update(overrides)
    return finalize_signed_document(build_task_submission(**kwargs), "stub-signature")


# --------------------------------------------------------------------------------------
# offer
# --------------------------------------------------------------------------------------


def test_a_requester_can_publish_open_work_with_signed_terms():
    offer = _signed_offer()
    assert offer["schema_version"] == OFFER_SCHEMA
    assert offer["claim_policy"] == "non-exclusive"
    assert offer["reward"]["address"] == PAYOUT
    assert offer["signature"] == "stub-signature"

    result = verify_task_offer(offer, signature_verifier=_accept)
    assert result["ok"] is True
    assert result["signer_role"] == "requester"
    assert result["binding_ok"] is True


def test_reward_terms_cannot_be_changed_after_signing():
    """Otherwise a requester could sign a generous offer and pay out something else."""
    offered = _signed_offer()
    for mutation in (
        {"address": "0x2222222222222222222222222222222222222222"},
        {"amount": "5"},
        {"asset": "DAI"},
        {"payment_on": "none"},
    ):
        tampered = json.loads(json.dumps(offered))
        tampered["reward"].update(mutation)
        result = verify_task_offer(tampered, signature_verifier=_accept)
        assert result["ok"] is False, mutation
        assert "message-mismatch" in _codes(result), mutation


def test_acceptance_criteria_cannot_be_rewritten_after_signing():
    offered = _signed_offer()
    tampered = json.loads(json.dumps(offered))
    tampered["acceptance_criteria"] = ["Send me the money instead"]
    result = verify_task_offer(tampered, signature_verifier=_accept)
    assert result["ok"] is False
    assert "message-mismatch" in _codes(result)


def test_a_payout_address_cannot_be_slipped_in_as_an_alias():
    offered = _signed_offer()
    offered["reward_address"] = "0x9999999999999999999999999999999999999999"
    result = verify_task_offer(offered, signature_verifier=_accept)
    assert result["ok"] is False
    assert "conflicting-alias" in _codes(result)


def test_offer_cannot_pretend_claims_are_exclusive():
    """No server means no lock, so an exclusive claim would be an empty promise."""
    offered = _signed_offer()
    offered["claim_policy"] = "exclusive"
    result = verify_task_offer(offered, signature_verifier=_accept)
    assert result["ok"] is False
    assert "message-mismatch" in _codes(result)
    assert "invalid-claim-policy" in _codes(result)


def test_expired_offer_is_rejected():
    past = datetime.now(timezone.utc) - timedelta(days=90)
    offer = finalize_signed_document(_offer(issued_at=past, ttl_days=1), "stub-signature")
    result = verify_task_offer(offer, signature_verifier=_accept)
    assert result["ok"] is False
    assert "document-expired" in _codes(result)


@pytest.mark.parametrize(
    "overrides",
    [
        {"task_id": "Nope"},
        {"requester_cell": "7187"},
        {"task_type": "Bad Type"},
        {"title": ""},
        {"deliverables": []},
        {"acceptance_criteria": []},
        {"acceptance_rule": "whatever-i-say"},
        {"reward": {"amount": "0", "asset": "USDC", "chain": "base", "address": PAYOUT, "payment_on": "on-acceptance"}},
        {"reward": {"amount": "50", "asset": "usdc", "chain": "base", "address": PAYOUT, "payment_on": "on-acceptance"}},
        {"reward": {"amount": "50", "asset": "USDC", "chain": "base", "address": PAYOUT, "payment_on": "whenever"}},
        {"ttl_days": 0},
    ],
)
def test_malformed_offers_are_refused_at_build_time(overrides):
    with pytest.raises(ValueError):
        _offer(**overrides)


# --------------------------------------------------------------------------------------
# claim
# --------------------------------------------------------------------------------------


def test_an_agent_can_claim_an_offer_without_permission():
    offer = _signed_offer()
    claim = _signed_claim(offer)
    result = verify_task_claim(claim, signature_verifier=_accept)
    assert result["ok"] is True
    assert result["signer_role"] == "claimant-agent"
    assert claim["claim_state"] == "non-exclusive"


def test_a_claim_must_bind_to_the_exact_offer():
    offer = _signed_offer()
    claim = _signed_claim(offer)
    tampered = json.loads(json.dumps(claim))
    tampered["offer_sha256"] = "sha256:" + "b" * 64
    result = verify_task_claim(tampered, signature_verifier=_accept)
    assert result["ok"] is False
    assert "message-mismatch" in _codes(result)


def test_a_claim_cannot_upgrade_itself_to_exclusive():
    offer = _signed_offer()
    claim = _signed_claim(offer)
    claim["claim_state"] = "exclusive"
    result = verify_task_claim(claim, signature_verifier=_accept)
    assert result["ok"] is False
    assert "message-mismatch" in _codes(result)
    assert "invalid-claim-state" in _codes(result)


def test_a_claim_signed_by_a_different_agent_key_is_rejected():
    offer = _signed_offer()
    claim = _signed_claim(offer)
    claim["agent_controller"] = OTHER_AGENT
    result = verify_task_claim(claim, signature_verifier=_accept)
    assert result["ok"] is False
    assert "message-mismatch" in _codes(result)


# --------------------------------------------------------------------------------------
# submission
# --------------------------------------------------------------------------------------


def test_an_agent_can_submit_self_hosted_artifacts():
    offer = _signed_offer()
    claim = _signed_claim(offer)
    submission = _signed_submission(offer, claim)
    result = verify_task_submission(submission, signature_verifier=_accept)
    assert result["ok"] is True
    assert result["signer_role"] == "submitting-agent"
    assert submission["artifacts"][0]["url"].startswith("https://outsider.example/")


def test_a_submission_cannot_swap_the_artifact_it_points_at():
    offer = _signed_offer()
    submission = _signed_submission(offer)
    tampered = json.loads(json.dumps(submission))
    tampered["artifacts"][0]["sha256"] = "sha256:" + "8" * 64
    result = verify_task_submission(tampered, signature_verifier=_accept)
    assert result["ok"] is False
    assert "message-mismatch" in _codes(result)


def test_a_submission_cannot_be_repointed_at_another_offer():
    offer = _signed_offer()
    submission = _signed_submission(offer)
    tampered = json.loads(json.dumps(submission))
    tampered["offer_sha256"] = "sha256:" + "c" * 64
    result = verify_task_submission(tampered, signature_verifier=_accept)
    assert result["ok"] is False
    assert "message-mismatch" in _codes(result)


def test_an_artifact_may_not_be_served_over_plain_http():
    with pytest.raises(ValueError):
        _signed_submission(_signed_offer(), artifacts=[{"name": "r.md", "url": "http://x.example/r.md", "sha256": ARTIFACT_SHA}])


def test_a_submission_needs_at_least_one_artifact():
    with pytest.raises(ValueError):
        _signed_submission(_signed_offer(), artifacts=[])


# --------------------------------------------------------------------------------------
# cross-cutting
# --------------------------------------------------------------------------------------


def test_signing_key_can_be_swapped_to_flip_the_reported_signer():
    """A submission claims to be the agent's; it must be signed by the agent."""
    offer = _signed_offer()
    submission = _signed_submission(offer)
    submission["agent_id"] = "someone-else"
    result = verify_task_submission(submission, signature_verifier=_accept)
    assert result["ok"] is False
    assert "message-mismatch" in _codes(result)


def test_documents_are_not_interchangeable():
    offer = _signed_offer()
    claim = _signed_claim(offer)
    assert verify_task_claim(offer, signature_verifier=_accept)["ok"] is False
    assert "wrong-document-type" in _codes(verify_task_claim(offer, signature_verifier=_accept))
    assert "wrong-document-type" in _codes(verify_task_submission(claim, signature_verifier=_accept))


def test_an_unsupported_schema_is_rejected_cleanly():
    result = verify_task_document({"schema_version": "organa-nonsense-v9"}, signature_verifier=_accept)
    assert result["ok"] is False
    assert "unsupported-schema" in _codes(result)


def test_a_valid_signature_that_does_not_verify_is_reported_as_invalid():
    result = verify_task_claim(_signed_claim(_signed_offer()), signature_verifier=_reject)
    assert result["ok"] is False
    assert "invalid-signature" in _codes(result)


def test_verifier_outage_is_not_reported_as_a_forgery():
    def unavailable(_claim):
        return {"signature_valid": False, "signature_verification": "verifier-unavailable"}

    result = verify_task_claim(_signed_claim(_signed_offer()), signature_verifier=unavailable)
    assert result["ok"] is False
    assert "verifier-unavailable" in _codes(result)
    assert "invalid-signature" not in _codes(result)


def test_the_result_states_what_it_did_not_check():
    result = verify_task_offer(_signed_offer(), signature_verifier=_accept)
    boundary = result["boundary"]
    assert "does not fetch" in boundary
    assert "funded" in boundary


def test_every_document_type_documents_its_own_boundary():
    offer = _signed_offer()
    claim = _signed_claim(offer)
    submission = _signed_submission(offer)
    assert "does not escrow funds" in offer["message"]
    assert "does not reserve the task" in claim["message"]
    assert "does not prove the artifacts exist" in submission["message"]


def test_offer_digest_is_stable_and_signature_sensitive():
    offer = _signed_offer()
    assert offer_sha256(offer) == offer_sha256(dict(offer))
    resigned = dict(offer, signature="a-different-signature")
    assert offer_sha256(resigned) != offer_sha256(offer)


# --------------------------------------------------------------------------------------
# the acceptance test for the flow
# --------------------------------------------------------------------------------------


def test_full_open_claim_submit_flow():
    """Requester opens work, an agent claims it, the agent hands in a result."""
    offer = _signed_offer()
    assert verify_task_offer(offer, signature_verifier=_accept)["ok"] is True

    claim = _signed_claim(offer)
    assert verify_task_claim(claim, signature_verifier=_accept)["ok"] is True
    assert claim["offer_sha256"] == offer_sha256(offer)

    submission = _signed_submission(offer, claim)
    assert verify_task_submission(submission, signature_verifier=_accept)["ok"] is True
    assert submission["offer_sha256"] == offer_sha256(offer)
    assert submission["claim_sha256"] == offer_sha256(claim)
    assert submission["agent_id"] == claim["agent_id"]


def test_two_agents_can_claim_the_same_task():
    """Claims are non-exclusive by construction, so there is nothing to lock."""
    offer = _signed_offer()
    first = finalize_signed_document(_claim(offer, agent_controller=AGENT), "sig-a")
    second = finalize_signed_document(_claim(offer, agent_id="rival-agent", agent_controller=OTHER_AGENT), "sig-b")
    assert verify_task_claim(first, signature_verifier=_accept)["ok"] is True
    assert verify_task_claim(second, signature_verifier=_accept)["ok"] is True


# --------------------------------------------------------------------------------------
# public endpoint
# --------------------------------------------------------------------------------------


def _running_server(**dependencies):
    server = create_server("127.0.0.1", 0, **dependencies)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_address[1]}"


def _wrap(body):
    from bitmap_memory_portal.proof_verifier import verify_task

    return verify_task(body, signature_verifier=_accept)


def _post(base, path, payload):
    request = Request(
        base + path,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        response = urlopen(request, timeout=5)
    except HTTPError as exc:
        response = exc
    with response:
        return response.status, json.loads(response.read().decode("utf-8"))


def test_public_endpoint_serves_the_whole_flow():
    server, thread, base = _running_server(verify_task_func=_wrap)
    try:
        offer = _signed_offer()
        claim = _signed_claim(offer)
        submission = _signed_submission(offer, claim)
        results = [_post(base, "/v1/verify/task", doc) for doc in (offer, claim, submission)]
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    for status, body in results:
        assert status == 200
        assert body["ok"] is True
        assert body["status"] == "task-document-valid"


def test_public_endpoint_rejects_a_tampered_document_with_422():
    server, thread, base = _running_server(verify_task_func=_wrap)
    try:
        offer = _signed_offer()
        offer["reward"]["amount"] = "5000"
        status, body = _post(base, "/v1/verify/task", offer)
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert status == 422
    assert body["ok"] is False
    assert body["status"] == "task-document-invalid"
    assert "message-mismatch" in [item["code"] for item in body["errors"]]


def test_public_endpoint_is_advertised_in_openapi():
    from pathlib import Path

    spec = json.loads((Path(__file__).resolve().parents[1] / "openapi.json").read_text(encoding="utf-8"))
    assert "/v1/verify/task" in spec["paths"]
    for name in ("TaskOffer", "TaskClaim", "TaskSubmission"):
        assert name in spec["components"]["schemas"]
