#!/usr/bin/env node
const { Verifier } = require('bip322-js');

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { input += chunk; });
process.stdin.on('end', () => {
  try {
    const claim = JSON.parse(input);
    const ok = Verifier.verifySignature(
      claim.signing_address,
      claim.message,
      claim.signature
    );
    process.stdout.write(JSON.stringify({ ok: !!ok }));
  } catch (err) {
    process.stdout.write(JSON.stringify({ ok: false, error: String(err && err.message ? err.message : err) }));
    process.exitCode = 1;
  }
});
