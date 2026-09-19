#!/usr/bin/env python3
"""Generate a self-contained page for signing one Organa task document.

Why this exists
---------------
The published message-signing.html is hardcoded for the v0.1.0 controller claim, so it
cannot sign a task offer, claim or submission. This emits a page that embeds exactly one
document, shows its message, and asks the right wallet for a signature over that message.

Two schemes, chosen by the document's own signature_scheme:

  bip322-simple         UniSat, window.unisat.signMessage(msg, 'bip322-simple')
  eip191-personal-sign  MetaMask, window.ethereum.request personal_sign

Safety properties the page enforces:
  * the message is embedded and shown read-only, so what is displayed is what is signed;
  * the wallet account is compared against the required signer before signing, so the
    wrong wallet is caught rather than silently producing a useless signature;
  * it requests a message signature only - no transaction, PSBT, fee or transfer.

Usage:
    python3 scripts/make_task_signing_page.py --document offer.json --out-dir ./session
"""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path

# Which field must carry the signing address, per document type.
SIGNER_FIELD = {
    "organa-task-offer-v0.1": "requester_controller",
    "organa-task-claim-v0.1": "agent_controller",
    "organa-task-submission-v0.1": "agent_controller",
    "organa-task-commit-v0.1": "agent_controller",
    "organa-agent-registration-claim-v0.1": "controller_address",
}

SIGNER_LABEL = {
    "organa-task-offer-v0.1": "requester",
    "organa-task-claim-v0.1": "agent",
    "organa-task-submission-v0.1": "agent",
    "organa-task-commit-v0.1": "agent",
    "organa-agent-registration-claim-v0.1": "agent",
}

# Documents whose own signature_scheme field decides the wallet. Every task document binds
# the scheme in its signed header, so all four belong here: leaving claims, commits and submissions
# out silently forced a MetaMask signer onto UniSat and asked it for a BIP-322 signature it
# could never produce.
SCHEME_AWARE = {
    "organa-task-offer-v0.1",
    "organa-task-claim-v0.1",
    "organa-task-submission-v0.1",
    "organa-task-commit-v0.1",
}

WALLET_BY_SCHEME = {
    "bip322-simple": "unisat",
    "eip191-personal-sign": "metamask",
}

WALLET_TITLE = {
    "unisat": "UniSat (Bitcoin, BIP-322)",
    "metamask": "MetaMask (EVM, personal_sign)",
}

WALLET_NOTE = {
    "unisat": "Connect the Bitcoin wallet holding the controller key.",
    "metamask": "Connect the EVM account named as the requester.",
}

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign Organa document - __SCHEMA__</title>
<style>
body{margin:0;background:#090b10;color:#edf4ff;font:15px/1.6 system-ui;max-width:940px;padding:40px 24px;margin:auto}
h1{font-size:22px;margin:0 0 4px}
.card{background:#111722;border:1px solid #273247;border-radius:14px;padding:20px;margin:18px 0}
pre{background:#0b1020;border:1px solid #1e2a3d;border-radius:10px;padding:14px;overflow:auto;white-space:pre-wrap;word-break:break-word;font:12.5px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;max-height:340px}
button{background:#ff9b4a;color:#101010;border:0;border-radius:10px;padding:12px 18px;font:600 15px system-ui;cursor:pointer;margin:0 8px 8px 0}
button.ghost{background:#243044;color:#dce7f7}
.k{color:#8fa3bf}.v{color:#71e6ae;word-break:break-all}
.warn{background:#2a1a12;border:1px solid #6b3a1c;border-radius:10px;padding:12px;color:#ffd0a8}
.ok{background:#12251c;border:1px solid #285b48;border-radius:10px;padding:12px;color:#a8f0c8}
label{display:block;margin:10px 0 4px;color:#8fa3bf;font-size:13px}
</style></head><body>
<h1>Sign Organa document</h1>
<p><span class="k">type</span> <span class="v">__SCHEMA__</span> &nbsp;
   <span class="k">wallet</span> <span class="v">__WALLET_TITLE__</span></p>

<div class="card">
  <p><span class="k">Required signer (__SIGNER_LABEL__):</span><br><span class="v">__SIGNER_ADDRESS__</span></p>
  <p>__WALLET_NOTE__</p>
  <label>Message to be signed (exactly this, UTF-8)</label>
  <pre id="message">__MESSAGE__</pre>
  <p><button id="sign">Connect &amp; sign</button></p>
  <div id="status"></div>
</div>

<div class="card" id="outcard" style="display:none">
  <h2 style="font-size:16px;margin:0 0 8px">Signed document</h2>
  <p>Send this back. It is the whole document plus the signature; nothing else changed.</p>
  <p><button id="copy">Copy signed JSON</button>
     <button id="download" class="ghost">Download</button>
     <button id="check" class="ghost">Verify against the public verifier</button></p>
  <div id="checkout"></div>
  <pre id="result"></pre>
</div>

<div class="card">
  <p class="warn"><strong>What this requests:</strong> a <em>message</em> signature only, via
  __WALLET_TITLE__. It does not create a transaction, PSBT, miner fee, inscription transfer
  or spending authorization. Your wallet will show the message; check that it matches the
  text above before approving.</p>
</div>

<script>
const DOC = __DOCUMENT__;
const SIGNER_FIELD = __SIGNER_FIELD_JSON__;
const WALLET = __WALLET_JSON__;
const API = __API_JSON__;

const statusEl = document.getElementById('status');
const say = (cls, text) => { statusEl.innerHTML = '<div class="' + cls + '">' + text + '</div>'; };
const esc = (s) => String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));

function showSigned(signature, method) {
  const signed = Object.assign({}, DOC, { signature: signature, signature_method: method });
  document.getElementById('result').textContent = JSON.stringify(signed, null, 2);
  document.getElementById('outcard').style.display = 'block';
}

document.getElementById('sign').onclick = async () => {
  const required = DOC[SIGNER_FIELD];
  try {
    if (WALLET === 'unisat') {
      if (!window.unisat) throw new Error('UniSat provider not detected. Install or enable the UniSat extension, then reload.');
      const accounts = await window.unisat.requestAccounts();
      const account = accounts && accounts[0];
      if (!account) throw new Error('no account returned by the wallet');
      if (account !== required) {
        say('warn', 'Wrong wallet. Connected <b>' + esc(account) + '</b> but this document must be signed by <b>' + esc(required) + '</b>. Switch the active account in UniSat and try again.');
        return;
      }
      say('ok', 'Correct wallet connected. Approve the message signature in UniSat.');
      const sig = await window.unisat.signMessage(DOC.message, 'bip322-simple');
      showSigned(sig, 'BIP-322-simple-message-signature');
      say('ok', 'Signature returned. Copy the signed document below and send it back.');
    } else {
      if (!window.ethereum) throw new Error('No EVM provider detected. Install or enable MetaMask, then reload.');
      const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
      const account = accounts && accounts[0];
      if (!account) throw new Error('no account returned by the wallet');
      if (account.toLowerCase() !== String(required).toLowerCase()) {
        say('warn', 'Wrong wallet. Connected <b>' + esc(account) + '</b> but this document must be signed by <b>' + esc(required) + '</b>. Switch the active account in MetaMask and try again.');
        return;
      }
      say('ok', 'Correct account connected. Approve the signature request in MetaMask.');
      // The message has no 0x prefix, so personal_sign treats it as UTF-8 text and signs
      // its bytes - exactly what the verifier re-derives and hashes.
      const sig = await window.ethereum.request({
        method: 'personal_sign',
        params: [DOC.message, account],
      });
      showSigned(sig, 'EIP-191-personal_sign');
      say('ok', 'Signature returned. Copy the signed document below and send it back.');
    }
  } catch (e) {
    say('warn', 'Stopped: ' + esc(e && e.message ? e.message : String(e)));
  }
};

document.getElementById('copy').onclick = () => {
  navigator.clipboard.writeText(document.getElementById('result').textContent)
    .then(() => say('ok', 'Signed document copied to the clipboard.'))
    .catch(() => say('warn', 'Clipboard blocked by the browser. Select the text and copy manually.'));
};

document.getElementById('download').onclick = () => {
  const blob = new Blob([document.getElementById('result').textContent], {type: 'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = '__FILENAME__';
  a.click();
};

document.getElementById('check').onclick = async () => {
  const out = document.getElementById('checkout');
  out.innerHTML = '<div class="ok">Checking...</div>';
  try {
    const body = JSON.parse(document.getElementById('result').textContent);
    const res = await fetch(API, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body),
    });
    const data = await res.json();
    const codes = (data.errors || []).map(e => e.code).join(', ') || 'none';
    out.innerHTML = '<div class="' + (data.ok ? 'ok' : 'warn') + '">HTTP ' + res.status
      + ' - <b>' + esc(data.status) + '</b><br>errors: ' + esc(codes) + '</div>';
  } catch (e) {
    out.innerHTML = '<div class="warn">Could not reach the verifier from this page (usually a'
      + ' browser restriction on local files). The signature is still fine - send the JSON back'
      + ' and it can be checked server-side.</div>';
  }
};
</script>
</body></html>
"""


def build_page(document: dict, *, api: str) -> str:
    schema = document.get("schema_version")
    if schema not in SIGNER_FIELD:
        raise SystemExit(f"unsupported schema_version for signing: {schema!r}")
    message = document.get("message")
    if not isinstance(message, str) or not message:
        raise SystemExit("document has no 'message' to sign")
    signer_field = SIGNER_FIELD[schema]
    signer = document.get(signer_field)
    if not isinstance(signer, str) or not signer:
        raise SystemExit(f"document has no {signer_field!r} to sign with")

    scheme = (
        document.get("signature_scheme", "bip322-simple")
        if schema in SCHEME_AWARE
        else "bip322-simple"
    )
    if scheme not in WALLET_BY_SCHEME:
        raise SystemExit(f"unsupported signature_scheme for signing: {scheme!r}")
    wallet = WALLET_BY_SCHEME[scheme]

    return (
        PAGE.replace("__SCHEMA__", html.escape(schema))
        .replace("__WALLET_TITLE__", html.escape(WALLET_TITLE[wallet]))
        .replace("__WALLET_NOTE__", html.escape(WALLET_NOTE[wallet]))
        .replace("__SIGNER_LABEL__", html.escape(SIGNER_LABEL[schema]))
        .replace("__SIGNER_ADDRESS__", html.escape(signer))
        .replace("__MESSAGE__", html.escape(message))
        .replace("__DOCUMENT__", json.dumps(document, ensure_ascii=False))
        .replace("__SIGNER_FIELD_JSON__", json.dumps(signer_field))
        .replace("__WALLET_JSON__", json.dumps(wallet))
        .replace("__API_JSON__", json.dumps(api))
        .replace("__FILENAME__", f"{document.get('task_id') or 'document'}.signed.json")
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--document", required=True, help="path to the unsigned document JSON")
    ap.add_argument("--out-dir", required=True, help="directory for the signing page")
    ap.add_argument(
        "--api",
        default="https://organa-proof-verifier.onrender.com/v1/verify/task",
        help="verifier endpoint the page uses for its optional self-check",
    )
    args = ap.parse_args()

    document = json.loads(Path(args.document).expanduser().read_text(encoding="utf-8"))
    out_dir = Path(args.out_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)

    page_path = out_dir / "sign.html"
    page_path.write_text(build_page(document, api=args.api), encoding="utf-8")
    print(
        json.dumps(
            {
                "page": str(page_path),
                "schema": document.get("schema_version"),
                "signature_scheme": document.get("signature_scheme", "bip322-simple"),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
