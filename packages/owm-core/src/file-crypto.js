// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OWMF v1 — client-side authenticated file encryption. See WM-8.
//
// 100% Web Crypto (HKDF-SHA256 + AES-256-GCM), zero deps. `signMessage` is
// INJECTED — an async (message) => signatureHex — so the same code drives a
// wallet (wagmi `signMessageAsync`) in the browser and a raw key in tests.
//
// Tamper-proof: the header (scheme/salt/nonce) is AEAD associated data, so a
// single flipped byte anywhere fails the GCM tag. Crypto-agile: the `scheme`
// byte is in the file and auto-detected on decrypt — new (incl. post-quantum)
// schemes drop in without breaking old files.

const MAGIC = [0x4f, 0x57, 0x4d, 0x46]; // "OWMF"
const VERSION = 0x01;
const HEADER_LEN = 52; // magic4 ver1 scheme1 mode1 flags1 salt32 nonce12

export const SCHEMES = {
  0x01: { name: 'AES-256-GCM', kind: 'symmetric', pq: true },
};
export const SCHEME_BY_NAME = { 'AES-256-GCM': 0x01 };
export const MODE = { SYMMETRIC: 0x01, RECIPIENT: 0x02 };
export const FLAG = { WALLET_SIGNED: 0x01, PASSWORD: 0x02 };

const enc = new TextEncoder();
const dec = new TextDecoder();

function subtle() {
  const c = globalThis.crypto;
  if (!c || !c.subtle) throw new Error('Web Crypto (crypto.subtle) is unavailable here');
  return c.subtle;
}
function rand(n) { return globalThis.crypto.getRandomValues(new Uint8Array(n)); }

function hexToBytes(hex) {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function b64(bytes) { let s = ''; bytes.forEach((b) => { s += String.fromCharCode(b); }); return btoa(s); }
function concat(...arrs) {
  const total = arrs.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
function writeUvarint(nIn) {
  let n = nIn; const bytes = [];
  while (n > 0x7f) { bytes.push((n & 0x7f) | 0x80); n = Math.floor(n / 128); }
  bytes.push(n & 0x7f);
  return new Uint8Array(bytes);
}
function readUvarint(bytes, offIn) {
  let n = 0; let shift = 0; let i = offIn;
  for (;;) { const byte = bytes[i]; i += 1; n += (byte & 0x7f) * (2 ** shift); if ((byte & 0x80) === 0) break; shift += 7; }
  return [n, i];
}

// Optional password → PBKDF2 (slow) so it resists offline brute-force even if
// an attacker has seized the wallet and can produce the signature.
const PBKDF2_ITERS = 210000;
async function pbkdf2(password, salt) {
  const pk = await subtle().importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await subtle().deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERS }, pk, 256));
}

// Key = HKDF-SHA256(ikm), where ikm = signature bytes [ ‖ PBKDF2(password) ].
async function deriveKeyFromIkm(ikm, salt, schemeName) {
  const hk = await subtle().importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
  return subtle().deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(`owmf|${schemeName}`) },
    hk,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

function buildHeader(scheme, mode, flags, salt, nonce) {
  return concat(new Uint8Array([...MAGIC, VERSION, scheme, mode, flags]), salt, nonce);
}

// Read the header without decrypting — this is the "auto-detect the scheme" step.
export function inspect(blob) {
  if (blob.length < HEADER_LEN || MAGIC.some((m, i) => blob[i] !== m)) {
    return { ok: false, error: 'not an OWMF file' };
  }
  const scheme = blob[5];
  const flags = blob[7];
  return {
    ok: true, version: blob[4], scheme, mode: blob[6], flags,
    schemeName: (SCHEMES[scheme] || {}).name || `unknown(0x${scheme.toString(16)})`,
    supported: !!SCHEMES[scheme],
    passwordProtected: (flags & FLAG.PASSWORD) === FLAG.PASSWORD,
  };
}

export async function encryptFile({
  data, name = 'file', type = 'application/octet-stream', signMessage, scheme = 'AES-256-GCM', password = '',
}) {
  const schemeId = SCHEME_BY_NAME[scheme];
  if (!schemeId) throw new Error(`unknown scheme: ${scheme}`);
  const salt = rand(32);
  const nonce = rand(12);
  const flags = password ? FLAG.PASSWORD : 0x00;
  const header = buildHeader(schemeId, MODE.SYMMETRIC, flags, salt, nonce);
  const sig = await signMessage(`owm-file-key-v1\n${b64(salt)}`);
  let ikm = hexToBytes(sig);
  if (password) ikm = concat(ikm, await pbkdf2(password, salt));
  const key = await deriveKeyFromIkm(ikm, salt, scheme);
  const meta = enc.encode(JSON.stringify({ n: name, t: type, s: data.length }));
  const plaintext = concat(writeUvarint(meta.length), meta, data);
  const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv: nonce, additionalData: header }, key, plaintext));
  return concat(header, ct);
}

export async function decryptFile({ blob, signMessage, password = '' }) {
  const info = inspect(blob);
  if (!info.ok) throw new Error(info.error);
  if (!info.supported) throw new Error(`unsupported scheme 0x${info.scheme.toString(16)}`);
  if (info.mode !== MODE.SYMMETRIC) throw new Error('recipient-encrypted files are not supported by this function yet');
  if (info.passwordProtected && !password) throw new Error('password required');
  const header = blob.slice(0, HEADER_LEN);
  const salt = blob.slice(8, 40);
  const nonce = blob.slice(40, 52);
  const ct = blob.slice(HEADER_LEN);
  const sig = await signMessage(`owm-file-key-v1\n${b64(salt)}`);
  let ikm = hexToBytes(sig);
  if (info.passwordProtected) ikm = concat(ikm, await pbkdf2(password, salt));
  const key = await deriveKeyFromIkm(ikm, salt, info.schemeName);
  let pt;
  try {
    pt = new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv: nonce, additionalData: header }, key, ct));
  } catch {
    throw new Error('decryption failed — wrong wallet, a tampered file, or a non-deterministic signature');
  }
  const [mlen, off] = readUvarint(pt, 0);
  const meta = JSON.parse(dec.decode(pt.slice(off, off + mlen)));
  return { data: pt.slice(off + mlen), name: meta.n, type: meta.t, scheme: info.schemeName };
}
