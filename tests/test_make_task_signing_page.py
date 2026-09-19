"""Guard tests for the task signing page generator.

The failure these exist for: the page decides which wallet to ask by looking up the
document's own signature_scheme, but only for schema versions listed in SCHEME_AWARE.
A schema left out of that set does not error - it silently falls back to bip322-simple and
asks UniSat for a signature, which is exactly what a MetaMask-only agent cannot give.

That happened twice: once for the verifier, once here. The rule is a single set, and every
document type that carries a signature_scheme belongs in it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "make_task_signing_page.py"

sys.path.insert(0, str(REPO_ROOT / "scripts"))

import make_task_signing_page as page_gen  # noqa: E402

EVM = "0xc897755B1C0836E67247865bF48bAeBc7Ca040Ea"


def _doc(schema: str, scheme: str, signer: str) -> dict:
    return {
        "schema_version": schema,
        "signature_scheme": scheme,
        "agent_controller": signer,
        "requester_controller": signer,
        "message": "Organa document body",
    }


def test_every_scheme_aware_document_type_is_listed():
    """Every task document that binds a scheme must be in SCHEME_AWARE.

    Reading the set from the generator is not enough - it could simply be short. This
    asserts the four task document types that carry signature_scheme are all present.
    """
    assert {
        "organa-task-offer-v0.1",
        "organa-task-claim-v0.1",
        "organa-task-submission-v0.1",
        "organa-task-commit-v0.1",
    } <= page_gen.SCHEME_AWARE


@pytest.mark.parametrize(
    "schema",
    [
        "organa-task-offer-v0.1",
        "organa-task-claim-v0.1",
        "organa-task-submission-v0.1",
        "organa-task-commit-v0.1",
    ],
)
def test_an_evm_document_uses_the_evm_wallet(tmp_path: Path, schema: str):
    """The regression: an eip191 document must never be routed to UniSat."""
    doc = tmp_path / "doc.json"
    doc.write_text(json.dumps(_doc(schema, "eip191-personal-sign", EVM)))

    out = subprocess.run(
        [sys.executable, str(SCRIPT), "--document", str(doc), "--out-dir", str(tmp_path)],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0, out.stderr

    page = (tmp_path / "sign.html").read_text()
    assert 'const WALLET = "metamask"' in page
    assert 'const WALLET = "unisat"' not in page
    assert EVM in page


@pytest.mark.parametrize(
    "schema",
    ["organa-task-offer-v0.1", "organa-task-claim-v0.1", "organa-task-submission-v0.1"],
)
def test_a_bitcoin_document_still_uses_unisat(tmp_path: Path, schema: str):
    doc = tmp_path / "doc.json"
    doc.write_text(json.dumps(_doc(schema, "bip322-simple", "bc1p4wz46fk45hp5crm56k4emxelln9tpuc76frn2duumlyecr9ft35qjxmadq")))

    out = subprocess.run(
        [sys.executable, str(SCRIPT), "--document", str(doc), "--out-dir", str(tmp_path)],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0, out.stderr
    assert 'const WALLET = "unisat"' in (tmp_path / "sign.html").read_text()


def test_the_page_never_requests_a_transaction(tmp_path: Path):
    """A signing page that could move funds would be a different tool entirely."""
    doc = tmp_path / "doc.json"
    doc.write_text(json.dumps(_doc("organa-task-claim-v0.1", "eip191-personal-sign", EVM)))
    subprocess.run(
        [sys.executable, str(SCRIPT), "--document", str(doc), "--out-dir", str(tmp_path)],
        capture_output=True, text=True,
    )
    page = (tmp_path / "sign.html").read_text()
    for forbidden in ("eth_sendTransaction", "personal_sign_transaction", "signTransaction", "eth_signTransaction"):
        assert forbidden not in page, f"page must never be able to call {forbidden}"
