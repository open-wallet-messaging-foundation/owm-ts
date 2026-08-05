// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OWM recipient encryption + messaging over insecure channels.
//
// The key idea: **sign-to-derive an x25519 identity keypair** from the wallet.
// You reveal your OWM *public* key once (a short string); anyone can then seal a
// message/file to it, and you decrypt by signing again to re-derive your secret.
// This works with ANY deterministic-signing wallet — no wallet ECDH/decrypt
// primitive is needed (which is why "encrypt to a raw address" can't round-trip
// with real wallets, but this can). See WM-8 §6/§7.

import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hexToBytes, bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

export const IDENTITY_MSG = 'owm-identity-key-v1';
const enc = new TextEncoder();
const dec = new TextDecoder();

function subtle() {
  const c = globalThis.crypto;
  if (!c || !c.subtle) throw new Error('Web Crypto (crypto.subtle) is unavailable here');
  return c.subtle;
}
function rand(n) { return globalThis.crypto.getRandomValues(new Uint8Array(n)); }
function concat(...arrs) {
  const total = arrs.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
function randSecret() {
  return x25519.utils.randomSecretKey ? x25519.utils.randomSecretKey() : x25519.utils.randomPrivateKey();
}
async function aesKeyFromShared(shared, ephPub) {
  const k = hkdf(sha256, shared, ephPub, utf8ToBytes('owm-seal-v1'), 32);
  return subtle().importKey('raw', k, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

// Deterministically derive the OWM x25519 identity keypair from a wallet signature.
export async function deriveOwmKeypair(signMessage) {
  const sig = await signMessage(IDENTITY_MSG);
  const secretKey = hkdf(sha256, hexToBytes(sig.replace(/^0x/, '')), undefined, utf8ToBytes('owm-x25519-identity'), 32);
  const publicKey = x25519.getPublicKey(secretKey);
  return { secretKey, publicKey, publicKeyHex: bytesToHex(publicKey) };
}

// Seal bytes TO a recipient's OWM public key (hex or bytes). ECIES:
// ephemeral x25519 → ECDH → HKDF → AES-256-GCM. Output = ephPub‖nonce‖ct+tag,
// tamper-proof (ephPub is AEAD associated data).
export async function sealTo({ recipientPublicKey, data }) {
  const recip = typeof recipientPublicKey === 'string' ? hexToBytes(recipientPublicKey.replace(/^0x/, '')) : recipientPublicKey;
  if (recip.length !== 32) throw new Error('recipient OWM public key must be 32 bytes');
  const ephSecret = randSecret();
  const ephPub = x25519.getPublicKey(ephSecret);
  const shared = x25519.getSharedSecret(ephSecret, recip);
  const key = await aesKeyFromShared(shared, ephPub);
  const nonce = rand(12);
  const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv: nonce, additionalData: ephPub }, key, data));
  return concat(ephPub, nonce, ct);
}

// Open a sealed blob addressed to YOU (re-derives your key by signing).
export async function openSealed({ sealed, signMessage }) {
  if (sealed.length < 44 + 16) throw new Error('sealed blob too short');
  const { secretKey } = await deriveOwmKeypair(signMessage);
  const ephPub = sealed.slice(0, 32);
  const nonce = sealed.slice(32, 44);
  const ct = sealed.slice(44);
  const shared = x25519.getSharedSecret(secretKey, ephPub);
  const key = await aesKeyFromShared(shared, ephPub);
  try {
    return new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv: nonce, additionalData: ephPub }, key, ct));
  } catch {
    throw new Error('decryption failed — not addressed to this wallet, or tampered');
  }
}

// Seal a FILE (with its name/type) to a recipient — download + share the result.
export async function sealFileTo({ recipientPublicKey, data, name = 'file', type = 'application/octet-stream' }) {
  const meta = enc.encode(JSON.stringify({ n: name, t: type }));
  const len = new Uint8Array([meta.length & 0xff, (meta.length >> 8) & 0xff]);
  return sealTo({ recipientPublicKey, data: concat(len, meta, data) });
}
export async function openSealedFile({ sealed, signMessage }) {
  const payload = await openSealed({ sealed, signMessage });
  const mlen = payload[0] | (payload[1] << 8);
  const meta = JSON.parse(dec.decode(payload.slice(2, 2 + mlen)));
  return { data: payload.slice(2 + mlen), name: meta.n, type: meta.t };
}

// ── Messaging over insecure channels: a base64 blob you paste into anything ───
function b64encode(bytes) { let s = ''; bytes.forEach((b) => { s += String.fromCharCode(b); }); return btoa(s); }
function b64decode(str) { const bin = atob(str); const o = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i += 1) o[i] = bin.charCodeAt(i); return o; }

export async function encryptMessageTo({ recipientPublicKey, text }) {
  const sealed = await sealTo({ recipientPublicKey, data: enc.encode(text) });
  return `owm1:${b64encode(sealed)}`;
}
export async function decryptMessage({ blob, signMessage }) {
  const sealed = b64decode(blob.trim().replace(/^owm1:/, ''));
  return dec.decode(await openSealed({ sealed, signMessage }));
}
