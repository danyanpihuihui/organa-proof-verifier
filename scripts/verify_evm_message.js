#!/usr/bin/env node
// Verify an EIP-191 personal_sign signature and recover the signing account.
//
// Why this exists alongside verify_claim.js: an Organa document can be signed either by a
// Bitcoin key (BIP-322, a Cell controller) or by an EVM account (EIP-191, the party holding
// the funds on an L2). A document that commits ETH on Base should be signable by the account
// that actually holds that ETH, otherwise the promise is made by a key that never proves it
// controls the payout address.
//
// Uses @noble/curves and @noble/hashes, which are already present as transitive dependencies
// of bip322-js - so this adds no new dependency to the service.
//
// stdin : { address, message, signature }   signature = 0x + 65 bytes (r || s || v)
// stdout: { ok, recovered } or { ok: false, error }

const { secp256k1 } = require('@noble/curves/secp256k1');
const { keccak_256 } = require('@noble/hashes/sha3');

function personalHash(message) {
  const body = Buffer.from(message, 'utf8');
  const prefix = Buffer.from('\x19Ethereum Signed Message:\n' + body.length, 'utf8');
  return keccak_256(Buffer.concat([prefix, body]));
}

function toChecksumInsensitive(address) {
  // Compare lowercased: EIP-55 casing is a display convention, not part of the identity.
  return String(address).trim().toLowerCase();
}

function addressFromPublicKey(uncompressed65) {
  const hash = keccak_256(uncompressed65.slice(1));
  return '0x' + Buffer.from(hash.slice(12)).toString('hex');
}

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', () => {
  try {
    const req = JSON.parse(input);
    const { address, message, signature } = req;
    if (typeof address !== 'string' || typeof message !== 'string' || typeof signature !== 'string') {
      throw new Error('address, message and signature must all be strings');
    }

    let raw = signature.trim();
    if (raw.startsWith('0x') || raw.startsWith('0X')) raw = raw.slice(2);
    if (!/^[0-9a-fA-F]+$/.test(raw)) throw new Error('signature is not hex');
    if (raw.length !== 130) throw new Error('signature must be 65 bytes (r || s || v), got ' + raw.length / 2);

    const bytes = Buffer.from(raw, 'hex');
    const r = BigInt('0x' + bytes.subarray(0, 32).toString('hex'));
    const s = BigInt('0x' + bytes.subarray(32, 64).toString('hex'));
    let v = bytes[64];
    if (v === 0 || v === 1) v += 27;      // some wallets emit the raw recovery id
    if (v !== 27 && v !== 28) throw new Error('unsupported recovery byte ' + bytes[64] + ' (expected 0/1 or 27/28)');

    const digest = personalHash(message);
    const sig = new secp256k1.Signature(r, s).addRecoveryBit(v - 27);
    const recovered = addressFromPublicKey(sig.recoverPublicKey(digest).toRawBytes(false));

    const ok = toChecksumInsensitive(recovered) === toChecksumInsensitive(address);
    process.stdout.write(JSON.stringify({ ok, recovered: recovered }));
    if (!ok) process.exitCode = 1;
  } catch (err) {
    process.stdout.write(JSON.stringify({ ok: false, error: String(err && err.message ? err.message : err) }));
    process.exitCode = 1;
  }
});
