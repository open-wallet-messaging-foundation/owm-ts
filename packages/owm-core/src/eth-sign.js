// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// Shared EIP-191 personal-message signing/recovery over canonical strings.
// One implementation for every OWM signature: SCX contact cards (WM-3),
// OWM-AUTH responses and OWM-GRANT grants/revokes (WM-7). The EIP-191
// prefix guarantees none of these signatures can ever be a valid Ethereum
// transaction; each caller adds its own domain-separation tag on top so the
// signature domains are mutually disjoint too.

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';

export function normalizePrivateKey(privateKey) {
  if (privateKey instanceof Uint8Array) return privateKey;
  if (typeof privateKey === 'string' && /^(0x)?[0-9a-fA-F]{64}$/.test(privateKey)) {
    return hexToBytes(privateKey.replace(/^0x/, '').toLowerCase());
  }
  throw new Error('privateKey must be 32 bytes (hex or Uint8Array)');
}

export function addressFromPrivateKey(privateKey) {
  const pub = secp256k1.getPublicKey(normalizePrivateKey(privateKey), false);
  return `0x${bytesToHex(keccak_256(pub.slice(1)).slice(12))}`;
}

// EIP-191 personal-message digest: keccak256("\x19Ethereum Signed
// Message:\n" || len(payload) || payload), lengths in bytes.
export function eip191Digest(payload) {
  const msg = utf8ToBytes(payload);
  const prefix = utf8ToBytes(`\x19Ethereum Signed Message:\n${msg.length}`);
  return keccak_256(concatBytes(prefix, msg));
}

// Sign a canonical string; returns the Ethereum wire format r||s||v as
// 130 lowercase hex chars, v = 27 + recovery. noble's 'recovered' layout
// is recovery||r||s.
export function signPersonalMessage(payload, privateKey) {
  const priv = normalizePrivateKey(privateKey);
  const rec = secp256k1.sign(eip191Digest(payload), priv, { prehash: false, format: 'recovered' });
  return bytesToHex(concatBytes(rec.slice(1), Uint8Array.of(27 + rec[0])));
}

// Recover the lowercase 0x address that signed `payload`, or null if the
// signature is malformed / unrecoverable. Callers compare the result to an
// expected address (case-insensitive) — never trust a self-asserted signer.
export function recoverPersonalMessage(payload, sigHex) {
  if (typeof sigHex !== 'string') return null;
  const hex = (sigHex.startsWith('0x') ? sigHex.slice(2) : sigHex).toLowerCase();
  if (!/^[0-9a-f]{130}$/.test(hex)) return null;
  const sig = hexToBytes(hex);
  const v = sig[64];
  if (v !== 27 && v !== 28) return null;
  try {
    const parsed = secp256k1.Signature.fromBytes(
      concatBytes(Uint8Array.of(v - 27), sig.slice(0, 64)), 'recovered',
    );
    const pub = parsed.recoverPublicKey(eip191Digest(payload)).toBytes(false);
    return `0x${bytesToHex(keccak_256(pub.slice(1)).slice(12))}`;
  } catch {
    return null;
  }
}

// EIP-55 mixed-case checksum encoding (display / interop, e.g. EIP-4361
// messages). Input may be any case; output is the canonical checksum form.
export function toChecksumAddress(address) {
  if (typeof address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error('address must be 0x + 40 hex chars');
  }
  const addr = address.slice(2).toLowerCase();
  const hash = bytesToHex(keccak_256(utf8ToBytes(addr)));
  let out = '0x';
  for (let i = 0; i < 40; i++) {
    out += parseInt(hash[i], 16) >= 8 ? addr[i].toUpperCase() : addr[i];
  }
  return out;
}
