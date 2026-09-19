"""Tests for EVM-signed task offers.

An offer that commits ETH on Base should be signable by the account holding that ETH.
Before this, every document required BIP-322, which meant a Base-native requester needed a
Bitcoin key it may not have - and the promise was made by a key that never proved control
of the payout address.

These tests cover both the build-time rules and the fact that the scheme is inside the
signed bytes, so it cannot be swapped after the fact.
"""

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from bitmap_memory_portal.task_flow import (
    build_task_offer,
    finalize_signed_document,
    verify_task_offer,
)
from bitmap_memory_portal.signed_claims import (
    EIP191_PERSONAL_SIGN,
    SIGNATURE_SCHEMES,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
REQUIRED_SIGNER = "0xB12d25a800659D909D52Dd07EFcD9239175aec9c"
BTC_CONTROLLER = "bc1p4wz46fk45hp5crm56k4emxelln9tpuc76frn2duumlyecr9ft35qjxmadq"
ISSUED = datetime(2026, 9, 19, 12, 0, 0, tzinfo=timezone.utc)


def _accept(_claim):
    return {"signature_valid": True, "signature_verification": "test-stub-accept"}


def _codes(result):
    return [item["code"] for item in result["errors"]]


def _evm_offer(**overrides):
    kwargs = dict(
        task_id="bitmap-price-audit-2026-09",
        requester_cell=None,
        requester_controller=REQUIRED_SIGNER,
        task_type="verification-task",
        title="Reproduce the published series",
        purpose="Independent reproduction of the published daily mainstream price.",
        deliverables=[{"name": "report.md", "description": "Method and per-day results."}],
        acceptance_criteria=["States every data source", "Reports every traded day"],
        reward={
            "amount": "0.0001",
            "asset": "ETH",
            "chain": "base",
            "address": REQUIRED_SIGNER,
            "payment_on": "on-acceptance",
        },
        signature_scheme=EIP191_PERSONAL_SIGN,
        issued_at=ISSUED,
    )
    kwargs.update(overrides)
    return build_task_offer(**kwargs)


def _btc_offer(**overrides):
    kwargs = dict(
        task_id="bitmap-price-audit-2026-09",
        requester_cell="7187.bitmap",
        requester_controller=BTC_CONTROLLER,
        task_type="verification-task",
        title="Reproduce the published series",
        purpose="Independent reproduction of the published daily mainstream price.",
        deliverables=[{"name": "report.md", "description": "Method and per-day results."}],
        acceptance_criteria=["States every data source"],
        reward={
            "amount": "0.0001",
            "asset": "ETH",
            "chain": "base",
            "address": REQUIRED_SIGNER,
            "payment_on": "on-acceptance",
        },
        issued_at=ISSUED,
    )
    kwargs.update(overrides)
    return build_task_offer(**kwargs)


# --------------------------------------------------------------------------------------
# the message says who signed and how
# --------------------------------------------------------------------------------------


def test_evm_offer_message_names_the_account_not_a_controller():
    message = _evm_offer()["message"]
    assert "Signature scheme: eip191-personal-sign" in message
    assert "EVM chain: base" in message
    assert f"Requester Account: {REQUIRED_SIGNER}" in message
    assert "Requester Controller:" not in message
    assert "Bitcoin network: mainnet" not in message


def test_bitcoin_offer_message_is_unchanged_in_shape():
    message = _btc_offer()["message"]
    assert "Signature scheme: bip322-simple" in message
    assert "Bitcoin network: mainnet" in message
    assert f"Requester Controller: {BTC_CONTROLLER}" in message
    assert "Requester Account:" not in message


def test_evm_offer_needs_no_cell():
    offer = _evm_offer(requester_cell=None)
    assert "requester_cell" not in offer
    assert "Requester Cell" not in offer["message"]


def test_a_declared_cell_is_labelled_as_unproven():
    """The signature proves the account, not that the account speaks for the Cell."""
    offer = _evm_offer(requester_cell="7187.bitmap")
    assert "Requester Cell (declared): 7187.bitmap" in offer["message"]
    assert "not proven by it" in offer["message"]
    assert "separate delegation" in offer["message"]


def test_bitcoin_offer_still_asserts_its_cell_plainly():
    offer = _btc_offer()
    assert "Requester Cell: 7187.bitmap" in offer["message"]
    assert "(declared)" not in offer["message"]


# --------------------------------------------------------------------------------------
# the scheme is inside the signed bytes
# --------------------------------------------------------------------------------------


def test_flipping_the_scheme_after_signing_breaks_the_binding():
    """Otherwise an EVM signature could be re-presented as a Bitcoin-authorised offer."""
    signed = finalize_signed_document(_evm_offer(), "stub-signature")
    original = json.loads(json.dumps(signed))
    assert verify_task_offer(original, signature_verifier=_accept)["ok"] is True

    tampered = json.loads(json.dumps(signed))
    tampered["signature_scheme"] = "bip322-simple"
    tampered["requester_controller"] = BTC_CONTROLLER
    result = verify_task_offer(tampered, signature_verifier=_accept)
    assert result["ok"] is False
    assert "message-mismatch" in _codes(result)


def test_removing_the_scheme_field_also_breaks_the_binding():
    signed = finalize_signed_document(_evm_offer(), "stub-signature")
    tampered = json.loads(json.dumps(signed))
    del tampered["signature_scheme"]
    result = verify_task_offer(tampered, signature_verifier=_accept)
    assert result["ok"] is False
    assert "message-mismatch" in _codes(result)


def test_verification_reports_which_scheme_it_used():
    offer = finalize_signed_document(_evm_offer(), "stub-signature")
    result = verify_task_offer(offer, signature_verifier=_accept)
    assert result["signature_scheme"] == EIP191_PERSONAL_SIGN
    assert result["signer_role"] == "requester"


def test_the_scheme_reaches_the_signature_verifier():
    """A verifier that is not told the scheme cannot pick the right recovery."""
    seen = {}

    def spy(payload):
        seen.update(payload)
        return {"signature_valid": True, "signature_verification": "spy"}

    offer = finalize_signed_document(_evm_offer(), "stub-signature")
    verify_task_offer(offer, signature_verifier=spy)
    assert seen.get("signing_scheme") == EIP191_PERSONAL_SIGN
    assert seen.get("signing_address") == REQUIRED_SIGNER


# --------------------------------------------------------------------------------------
# build-time refusals
# --------------------------------------------------------------------------------------


def test_a_bitcoin_address_cannot_be_used_with_the_evm_scheme():
    with pytest.raises(ValueError, match="EVM address"):
        _evm_offer(requester_controller=BTC_CONTROLLER)


def test_an_evm_address_cannot_be_used_without_declaring_the_scheme():
    """Caught at build time rather than published as a document that can never verify."""
    with pytest.raises(ValueError, match="EVM address but the scheme is"):
        _btc_offer(requester_controller=REQUIRED_SIGNER)


def test_a_cell_is_required_on_the_bitcoin_path():
    with pytest.raises(ValueError, match="requester_cell is required"):
        _btc_offer(requester_cell=None)


def test_an_unknown_scheme_is_refused():
    with pytest.raises(ValueError, match="signature_scheme must be one of"):
        _evm_offer(signature_scheme="eip712-typed-data")


def test_an_unknown_scheme_is_reported_not_silently_defaulted():
    offer = finalize_signed_document(_evm_offer(), "stub-signature")
    offer["signature_scheme"] = "eip712-typed-data"
    result = verify_task_offer(offer, signature_verifier=_accept)
    assert result["ok"] is False
    assert "invalid-signature-scheme" in _codes(result)


@pytest.mark.parametrize("scheme", sorted(SIGNATURE_SCHEMES))
def test_every_declared_scheme_is_accepted_by_the_builder(scheme):
    signer = REQUIRED_SIGNER if scheme == EIP191_PERSONAL_SIGN else BTC_CONTROLLER
    cell = None if scheme == EIP191_PERSONAL_SIGN else "7187.bitmap"
    offer = _btc_offer(
        requester_controller=signer, requester_cell=cell, signature_scheme=scheme
    )
    assert offer["signature_scheme"] == scheme


# --------------------------------------------------------------------------------------
# every task document binds its own scheme
# --------------------------------------------------------------------------------------


def test_a_claim_can_be_signed_with_an_evm_account():
    """An agent's own key signs a claim, and that key may be an EVM account.

    This was the gap that blocked outsider agents: an EVM account could publish an offer
    but could not claim one, because only the offer accepted EIP-191.
    """
    from bitmap_memory_portal.task_flow import build_task_claim, verify_task_claim

    claim = build_task_claim(
        task_id="bitmap-mainstream-price-audit-2026-09",
        offer_sha256="sha256:" + "a" * 64,
        agent_id="outsider-agent",
        agent_controller=REQUIRED_SIGNER,
        intent="I will reproduce the series.",
        signature_scheme=EIP191_PERSONAL_SIGN,
        issued_at=ISSUED,
    )
    assert claim["signature_scheme"] == EIP191_PERSONAL_SIGN
    assert "Signature scheme: eip191-personal-sign" in claim["message"]
    assert f"Agent Controller: {REQUIRED_SIGNER}" in claim["message"]

    result = verify_task_claim(finalize_signed_document(claim, "stub"), signature_verifier=_accept)
    assert result["ok"] is True, result.get("errors")
    assert result["signature_scheme"] == EIP191_PERSONAL_SIGN


def test_a_submission_can_be_signed_with_an_evm_account():
    from bitmap_memory_portal.task_flow import build_task_submission, verify_task_submission

    submission = build_task_submission(
        task_id="bitmap-mainstream-price-audit-2026-09",
        offer_sha256="sha256:" + "a" * 64,
        agent_id="outsider-agent",
        agent_controller=REQUIRED_SIGNER,
        artifacts=[{"name": "report.md", "url": "https://x.example/r.md", "sha256": "sha256:" + "b" * 64}],
        summary="Reproduced the series.",
        signature_scheme=EIP191_PERSONAL_SIGN,
        issued_at=ISSUED,
    )
    result = verify_task_submission(finalize_signed_document(submission, "stub"), signature_verifier=_accept)
    assert result["ok"] is True, result.get("errors")
    assert result["signature_scheme"] == EIP191_PERSONAL_SIGN


def test_editing_a_claims_scheme_after_signing_breaks_the_binding():
    """The scheme is in the signed header, so a stray edit is caught by the binding check.

    This is the property that replaced 'only the offer may choose a scheme': the field is
    now bound rather than ignored, which is strictly stronger - an editor cannot move the
    document onto a different verification path, and cannot hide the change either.
    """
    from bitmap_memory_portal.task_flow import build_task_claim, verify_task_claim

    claim = build_task_claim(
        task_id="bitmap-mainstream-price-audit-2026-09",
        offer_sha256="sha256:" + "a" * 64,
        agent_id="outsider-agent",
        agent_controller=BTC_CONTROLLER,
        intent="I will reproduce the series.",
        issued_at=ISSUED,
    )
    signed = finalize_signed_document(claim, "stub-signature")
    signed["signature_scheme"] = EIP191_PERSONAL_SIGN

    result = verify_task_claim(signed, signature_verifier=_accept)
    assert result["ok"] is False
    codes = [e["code"] for e in result["errors"]]
    assert "message-mismatch" in codes
    assert "unverified-signature" in codes


def test_an_evm_address_cannot_sneak_into_a_bitcoin_signed_claim():
    """A mismatched pair would produce a document that can never verify."""
    from bitmap_memory_portal.task_flow import build_task_claim

    with pytest.raises(ValueError, match="EVM address but the scheme is"):
        build_task_claim(
            task_id="bitmap-mainstream-price-audit-2026-09",
            offer_sha256="sha256:" + "a" * 64,
            agent_id="outsider-agent",
            agent_controller=REQUIRED_SIGNER,
            intent="I will reproduce the series.",
            issued_at=ISSUED,
        )


# --------------------------------------------------------------------------------------
# the actual EVM recovery path
# --------------------------------------------------------------------------------------


def _node_available() -> bool:
    if not shutil.which("node"):
        return False
    return (REPO_ROOT / "node_modules" / "@noble" / "curves").is_dir()


@pytest.mark.skipif(not _node_available(), reason="node and @noble/curves are required")
def test_eip191_recovery_accepts_a_real_signature_and_rejects_a_tampered_one():
    """Sign with a throwaway EVM key, verify it, then tamper the message."""
    signer = REPO_ROOT / "scripts" / "verify_evm_message.js"
    assert signer.exists()

    helper = REPO_ROOT / "tests" / "_evm_recovery_probe.js"
    helper.write_text(
        """
const { secp256k1 } = require('@noble/curves/secp256k1');
const { keccak_256 } = require('@noble/hashes/sha3');
const { hexToBytes } = require('@noble/hashes/utils');

const message = process.argv[2];
function personalHash(m) {
  const b = Buffer.from(m, 'utf8');
  return keccak_256(Buffer.concat([Buffer.from('\\x19Ethereum Signed Message:\\n' + b.length, 'utf8'), b]));
}
function addr(pub65) { return '0x' + Buffer.from(keccak_256(pub65.slice(1)).slice(12)).toString('hex'); }

// Throwaway key. No funds, no relation to any real account.
const priv = hexToBytes('59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d');
const address = addr(secp256k1.getPublicKey(priv, false));
const s = secp256k1.sign(personalHash(message), priv, { prehash: false });
const sig = '0x' + s.r.toString(16).padStart(64, '0') + s.s.toString(16).padStart(64, '0')
          + (s.recovery + 27).toString(16).padStart(2, '0');
process.stdout.write(JSON.stringify({ address, signature: sig }));
""",
        encoding="utf-8",
    )
    try:
        made = json.loads(
            subprocess.run(
                ["node", str(helper), "hello organa"],
                text=True,
                capture_output=True,
                check=True,
                timeout=60,
            ).stdout
        )

        def run(message, signer_address):
            proc = subprocess.run(
                ["node", str(signer)],
                input=json.dumps(
                    {
                        # The spelling claims.py uses. Passing `address` here would test a
                        # contract the service does not actually send.
                        "signing_address": signer_address,
                        "message": message,
                        "signature": made["signature"],
                    }
                ),
                text=True,
                capture_output=True,
                timeout=60,
            )
            return proc.returncode, json.loads(proc.stdout or "{}")

        code, ok = run("hello organa", made["address"])
        assert code == 0 and ok["ok"] is True, ok
        assert ok["recovered"].lower() == made["address"].lower()

        code, bad = run("hello organa ", made["address"])
        assert code == 1 and bad["ok"] is False

        code, wrong = run("hello organa", "0x" + "11" * 20)
        assert code == 1 and wrong["ok"] is False
    finally:
        helper.unlink(missing_ok=True)


@pytest.mark.skipif(not _node_available(), reason="node and @noble/curves are required")
def test_claims_layer_dispatches_an_evm_claim_to_the_evm_script():
    """Drive the real service entry point, not the script directly.

    Calling verify_evm_message.js straight would pass even if claims.py sent it the wrong
    field names - which is exactly what happened: the script read `address` while the
    service sends `signing_address`, so every EVM signature failed in production with
    "address, message and signature must all be strings".
    """
    from bitmap_memory_portal.claims import verify_claim_signature

    helper = REPO_ROOT / "tests" / "_evm_dispatch_probe.js"
    helper.write_text(
        """
const { secp256k1 } = require('@noble/curves/secp256k1');
const { keccak_256 } = require('@noble/hashes/sha3');
const { hexToBytes } = require('@noble/hashes/utils');

const message = process.argv[2];
function personalHash(m) {
  const b = Buffer.from(m, 'utf8');
  return keccak_256(Buffer.concat([Buffer.from('\\x19Ethereum Signed Message:\\n' + b.length, 'utf8'), b]));
}
function addr(pub65) { return '0x' + Buffer.from(keccak_256(pub65.slice(1)).slice(12)).toString('hex'); }

const priv = hexToBytes('7f2b1c9d4e6a8f0b3d5c7e9a1b2d4f6081c3e5a7b9d0f2a4c6e8b1d3f5a7c9e0');
const address = addr(secp256k1.getPublicKey(priv, false));
const s = secp256k1.sign(personalHash(message), priv, { prehash: false });
const sig = '0x' + s.r.toString(16).padStart(64, '0') + s.s.toString(16).padStart(64, '0')
          + (s.recovery + 27).toString(16).padStart(2, '0');
process.stdout.write(JSON.stringify({ address, signature: sig }));
""",
        encoding="utf-8",
    )
    try:
        made = json.loads(
            subprocess.run(
                ["node", str(helper), "organa evm dispatch"],
                text=True,
                capture_output=True,
                check=True,
                timeout=60,
            ).stdout
        )
        # Exactly the dict shape verify_signature_over_message builds.
        verified = verify_claim_signature(
            {
                "signing_address": made["address"],
                "message": "organa evm dispatch",
                "signature": made["signature"],
                "signing_scheme": "eip191-personal-sign",
            }
        )
        assert verified["signature_valid"] is True, verified.get("verification_error")
        assert verified["signature_verification"] == "locally-verified-eip191-noble"
        assert verified["recovered_address"].lower() == made["address"].lower()

        # Wrong message, same signature.
        mismatched = verify_claim_signature(
            {
                "signing_address": made["address"],
                "message": "organa evm dispatch ",
                "signature": made["signature"],
                "signing_scheme": "eip191-personal-sign",
            }
        )
        assert mismatched["signature_valid"] is False

        # An unknown scheme must be reported, never silently verified as BIP-322.
        unknown = verify_claim_signature(
            {
                "signing_address": made["address"],
                "message": "organa evm dispatch",
                "signature": made["signature"],
                "signing_scheme": "eip712-typed-data",
            }
        )
        assert unknown["signature_valid"] is False
        assert unknown["signature_verification"] == "unsupported-signature-scheme"
    finally:
        helper.unlink(missing_ok=True)
