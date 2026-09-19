const https = require('https');
const { secp256k1 } = require('@noble/curves/secp256k1');
const { keccak_256 } = require('@noble/hashes/sha3');

const BASE_RPC = 'https://mainnet.base.org';
const CHAIN_ID = 8453;

// Minimal RLP encoder
function encodeLength(len, offset) {
  if (len < 56) return Buffer.from([len + offset]);
  const hex = len.toString(16);
  const l = hex.length % 2 === 0 ? hex : '0' + hex;
  const buf = Buffer.from(l, 'hex');
  return Buffer.concat([Buffer.from([offset + 55 + buf.length]), buf]);
}

function rlpEncode(item) {
  if (Buffer.isBuffer(item)) {
    if (item.length === 1 && item[0] < 0x80) return item;
    return Buffer.concat([encodeLength(item.length, 0x80), item]);
  } else if (Array.isArray(item)) {
    const encoded = Buffer.concat(item.map(rlpEncode));
    return Buffer.concat([encodeLength(encoded.length, 0xc0), encoded]);
  }
  throw new Error('Invalid RLP item');
}

function toBytes(val) {
  if (typeof val === 'number' || typeof val === 'bigint') {
    if (val === 0 || val === 0n) return Buffer.alloc(0);
    let hex = val.toString(16);
    if (hex.length % 2 !== 0) hex = '0' + hex;
    return Buffer.from(hex, 'hex');
  }
  if (typeof val === 'string') {
    let hex = val.startsWith('0x') ? val.slice(2) : val;
    if (hex.length % 2 !== 0) hex = '0' + hex;
    return Buffer.from(hex, 'hex');
  }
  return Buffer.alloc(0);
}

function rpcCall(method, params = []) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({ jsonrpc: '2.0', method, params, id: Math.floor(Math.random() * 100000) });
    const req = https.request(BASE_RPC, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': data.length }
    }, (res) => {
      let b = '';
      res.on('data', c => b += c);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(b);
          if (parsed.error) reject(new Error(parsed.error.message || JSON.stringify(parsed.error)));
          else resolve(parsed.result);
        } catch (e) {
          reject(e);
        }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function privKeyToAddress(privHex) {
  const pub = secp256k1.getPublicKey(Buffer.from(privHex, 'hex'), false);
  return '0x' + Buffer.from(keccak_256(pub.slice(1))).slice(-20).toString('hex');
}

function signTransaction(tx, privKeyHex) {
  const chainId = tx.chainId || CHAIN_ID;
  const raw = [
    toBytes(tx.nonce),
    toBytes(tx.gasPrice),
    toBytes(tx.gasLimit),
    toBytes(tx.to),
    toBytes(tx.value),
    toBytes(tx.data),
    toBytes(chainId),
    Buffer.alloc(0),
    Buffer.alloc(0)
  ];
  const encoded = rlpEncode(raw);
  const hash = keccak_256(encoded);

  const sig = secp256k1.sign(hash, Buffer.from(privKeyHex, 'hex'));
  const v = sig.recovery + (chainId * 2 + 35);
  const r = toBytes(sig.r);
  const s = toBytes(sig.s);

  const signedRaw = [
    toBytes(tx.nonce),
    toBytes(tx.gasPrice),
    toBytes(tx.gasLimit),
    toBytes(tx.to),
    toBytes(tx.value),
    toBytes(tx.data),
    toBytes(v),
    r,
    s
  ];
  return '0x' + rlpEncode(signedRaw).toString('hex');
}

async function sendRawTransaction(tx, privKeyHex) {
  const sender = privKeyToAddress(privKeyHex);
  if (tx.nonce === undefined) {
    const n = await rpcCall('eth_getTransactionCount', [sender, 'latest']);
    tx.nonce = BigInt(n);
  }
  if (!tx.gasPrice) {
    const gp = await rpcCall('eth_gasPrice', []);
    tx.gasPrice = BigInt(gp);
  }
  if (!tx.gasLimit) {
    tx.gasLimit = 250000n;
  }
  const signed = signTransaction(tx, privKeyHex);
  const txHash = await rpcCall('eth_sendRawTransaction', [signed]);
  return txHash;
}

async function waitForReceipt(txHash, timeoutMs = 60000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const r = await rpcCall('eth_getTransactionReceipt', [txHash]);
    if (r && r.blockNumber) return r;
    await new Promise(r => setTimeout(r, 2000));
  }
  throw new Error(`Timeout waiting for tx ${txHash}`);
}

module.exports = {
  rpcCall,
  privKeyToAddress,
  signTransaction,
  sendRawTransaction,
  waitForReceipt,
  CHAIN_ID
};
