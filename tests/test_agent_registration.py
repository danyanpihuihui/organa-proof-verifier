"""Tests for Organa Agent Registration Claim v0.1.

Core security property: a signature is only meaningful for the exact field values it was
made over. Verification re-derives the message from the claim's own fields, so a valid
signature cannot be replayed against different content.
"""

import json
import threading
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from bitmap_memory_portal.agent_registration import (
    build_agent_registration_claim,
    build_registration_message,
    finalize_agent_registration_claim,
    registration_claim_to_registry_entry,
    verify_agent_registration_claim,
)
from bitmap_memory_portal.verifier_http import create_server

ADDRESS = "bc1pagentcontrollerxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
HOME = "7187.bitmap"
BASE = "https://probe.example/agents/probe-agent"
ISSUED = datetime(2026, 9, 19, 12, 0, 0, tzinfo=timezone.utc)
SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
SHA_F = "sha256:" + "f" * 64


def _accept(claim):
    return {"signature_valid": True, "signature_verification": "test-stub-accept"}


def _reject(claim):
    return {"signature_valid": False, "signature_verification": "test-stub-reject"}


def _build(**overrides):
    """Build with a fixed issued_at so the claim is byte-deterministic."""
    kwargs = dict(
        agent_id="probe-agent",
        display_name="Probe Agent",
        home_cell=HOME,
        role="research-executor",
        controller_address=ADDRESS,
        identity_url=f"{BASE}/agent-identity.json",
        identity_sha256=SHA_A,
        checkpoint_url=f"{BASE}/continuity-checkpoint.json",
        checkpoint_sha256=SHA_B,
        discovery_url=f"{BASE}/.well-known/organa-agent.json",
        discovery_sha256=SHA_C,
        issued_at=ISSUED,
    )
    kwargs.update(overrides)
    return build_agent_registration_claim(**kwargs)


def _signed(**overrides):
    return finalize_agent_registration_claim(_build(**overrides), "stub-signature")


def _codes(result):
    return [item["code"] for item in result["errors"]]


def test_an_agent_can_self_register_without_asking_permission():
    """The whole point: build, sign, submit. No human gate in the format."""
    claim = _signed()
    assert claim["schema_version"] == "organa-agent-registration-claim-v0.1"
    assert claim["signature"] == "stub-signature"
    assert claim["subjective_continuity_claimed"] is False
    assert claim["message_sha256"].startswith("sha256:")

    result = verify_agent_registration_claim(claim, signature_verifier=_accept)
    assert result["ok"] is True
    assert result["errors"] == []
    assert result["binding_ok"] is True
    assert result["signature_valid"] is True


def test_claim_without_a_signature_is_rejected():
    result = verify_agent_registration_claim(_build(), signature_verifier=_accept)
    assert result["ok"] is False
    assert "missing-signature" in _codes(result)


def test_signature_cannot_be_replayed_against_a_different_identity_hash():
    """Rebind attack: valid signature, then point the claim at another package."""
    signed = _signed()
    rebound = json.loads(json.dumps(signed))
    rebound["identity"]["sha256"] = SHA_F

    result = verify_agent_registration_claim(rebound, signature_verifier=_accept)
    assert result["ok"] is False
    assert "message-mismatch" in _codes(result)
    assert result["binding_ok"] is False


def test_signature_cannot_be_replayed_against_a_different_discovery_url():
    signed = _signed()
    rebound = json.loads(json.dumps(signed))
    rebound["discovery"]["url"] = "https://attacker.example/.well-known/organa-agent.json"

    result = verify_agent_registration_claim(rebound, signature_verifier=_accept)
    assert result["ok"] is False
    assert "message-mismatch" in _codes(result)


def test_signature_cannot_be_replayed_against_a_different_home_cell():
    signed = _signed()
    rebound = json.loads(json.dumps(signed))
    rebound["home_cell"] = "999999.bitmap"

    result = verify_agent_registration_claim(rebound, signature_verifier=_accept)
    assert result["ok"] is False
    assert "message-mismatch" in _codes(result)


def test_a_hand_edited_message_is_rejected():
    signed = _signed()
    signed["message"] = signed["message"].replace("Home Cell: 7187.bitmap", "Home Cell: 999999.bitmap")
    result = verify_agent_registration_claim(signed, signature_verifier=_accept)
    assert result["ok"] is False
    assert "message-mismatch" in _codes(result)


def test_a_claim_cannot_carry_a_stray_twin_of_a_bound_field():
    """The signature covers the bound fields only, so a differing twin must be fatal."""
    signed = _signed()
    signed["identity_sha256"] = SHA_F

    result = verify_agent_registration_claim(signed, signature_verifier=_accept)
    assert result["ok"] is False
    assert "conflicting-alias" in _codes(result)


def test_a_matching_twin_is_harmless():
    signed = _signed()
    signed["identity_sha256"] = signed["identity"]["sha256"]
    result = verify_agent_registration_claim(signed, signature_verifier=_accept)
    assert result["ok"] is True


def test_subjective_continuity_must_stay_unclaimed():
    signed = _signed()
    signed["subjective_continuity_claimed"] = True
    result = verify_agent_registration_claim(signed, signature_verifier=_accept)
    assert result["ok"] is False
    assert "subjective-continuity-claimed" in _codes(result)


def test_expired_claim_is_rejected():
    past = datetime.now(timezone.utc) - timedelta(days=30)
    claim = finalize_agent_registration_claim(_build(issued_at=past, ttl_days=1), "stub-signature")
    result = verify_agent_registration_claim(claim, signature_verifier=_accept)
    assert result["ok"] is False
    assert "claim-expired" in _codes(result)
    assert result["expired"] is True


def test_lineage_cannot_be_swapped_after_signing():
    """A fork must not be able to present itself as genesis."""
    forked = _signed(lineage_status="fork")
    assert "Lineage Status: fork" in forked["message"]
    swapped = json.loads(json.dumps(forked))
    swapped["lineage_status"] = "original"
    result = verify_agent_registration_claim(swapped, signature_verifier=_accept)
    assert result["ok"] is False
    assert "message-mismatch" in _codes(result)


def test_non_original_lineage_is_flagged_as_unsubstantiated():
    forked = _signed(lineage_status="fork")
    result = verify_agent_registration_claim(forked, signature_verifier=_accept)
    assert result["ok"] is True
    assert any("not substantiated" in warning for warning in result["warnings"])


@pytest.mark.parametrize(
    "overrides",
    [
        {"agent_id": "Bad Agent"},
        {"agent_id": "x"},
        {"home_cell": "7187"},
        {"home_cell": "abc.bitmap"},
        {"identity_sha256": "sha256:xyz"},
        {"identity_url": "http://probe.example/a.json"},
        {"discovery_url": "https://user:pw@probe.example/a.json"},
        {"role": "Research Executor"},
        {"ttl_days": 0},
    ],
)
def test_malformed_claims_are_refused_at_build_time(overrides):
    """Fail closed where the agent can still see the problem, not only at the verifier."""
    with pytest.raises(ValueError):
        _build(**overrides)


def test_invalid_signature_is_rejected_and_names_the_failure():
    result = verify_agent_registration_claim(_signed(), signature_verifier=_reject)
    assert result["ok"] is False
    assert "invalid-signature" in _codes(result)
    assert result["signature_valid"] is False


def test_verifier_outage_is_not_reported_as_an_invalid_signature():
    def _unavailable(claim):
        return {"signature_valid": False, "signature_verification": "verifier-unavailable"}

    result = verify_agent_registration_claim(_signed(), signature_verifier=_unavailable)
    assert result["ok"] is False
    assert "verifier-unavailable" in _codes(result)
    assert "invalid-signature" not in _codes(result)


def test_signature_is_not_even_attempted_when_the_message_is_unbound():
    """Checking a signature over unbound content would prove nothing useful."""
    signed = _signed()
    signed["identity"]["sha256"] = SHA_F
    result = verify_agent_registration_claim(signed, signature_verifier=_accept)
    assert "unverified-signature" in _codes(result)


def test_verified_claim_projects_to_a_pending_registry_entry():
    """A claim binds the controller to declared hashes; it does not prove the URLs resolve."""
    claim = _signed()
    entry = registration_claim_to_registry_entry(claim)
    assert entry["id"] == "probe-agent"
    assert entry["lifecycle_status"] == "pending"
    assert entry["identity"]["sha256"] == claim["identity"]["sha256"]
    assert entry["continuity_checkpoint"]["sha256"] == claim["continuity_checkpoint"]["sha256"]
    assert entry["discovery"]["sha256"] == claim["discovery"]["sha256"]
    assert entry["lineage_status"] == "original"
    assert entry["subjective_continuity_claimed"] is False
    assert entry["registration"]["controller_address"] == ADDRESS
    assert "signature" not in entry


def test_registry_entry_can_be_promoted_only_by_an_explicit_caller():
    entry = registration_claim_to_registry_entry(_signed(), lifecycle_status="live")
    assert entry["lifecycle_status"] == "live"


def test_message_is_deterministic_for_identical_fields():
    """Builder and verifier must agree byte-for-byte, or nothing can be checked."""
    assert build_registration_message(_build()) == build_registration_message(_build())


def test_message_changes_when_any_bound_field_changes():
    baseline = build_registration_message(_build())
    assert build_registration_message(_build(agent_id="other-agent")) != baseline
    assert build_registration_message(_build(role="other-role")) != baseline
    assert build_registration_message(_build(controller_address="bc1potherxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")) != baseline


def _wrap(body):
    from bitmap_memory_portal.proof_verifier import verify_agent_registration

    return verify_agent_registration(body, signature_verifier=_accept)


def _running_server(**dependencies):
    server = create_server("127.0.0.1", 0, **dependencies)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_address[1]}"


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


def test_public_endpoint_accepts_a_valid_claim():
    server, thread, base = _running_server(verify_registration_func=_wrap)
    try:
        status, body = _post(base, "/v1/verify/agent-registration", _signed())
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert status == 200
    assert body["ok"] is True
    assert body["status"] == "registration-valid"
    assert body["registration"]["binding_ok"] is True


def test_public_endpoint_rejects_a_rebound_claim_with_422():
    server, thread, base = _running_server(verify_registration_func=_wrap)
    try:
        rebound = json.loads(json.dumps(_signed()))
        rebound["identity"]["sha256"] = SHA_F
        status, body = _post(base, "/v1/verify/agent-registration", rebound)
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert status == 422
    assert body["ok"] is False
    assert body["status"] == "registration-invalid"
    codes = [item["code"] for item in body["errors"]]
    assert codes[0] == "message-mismatch"
    assert "unverified-signature" in codes


def test_public_endpoint_is_advertised_in_openapi():
    from pathlib import Path

    spec = json.loads((Path(__file__).resolve().parents[1] / "openapi.json").read_text(encoding="utf-8"))
    assert "/v1/verify/agent-registration" in spec["paths"]
    assert "AgentRegistrationClaim" in spec["components"]["schemas"]
