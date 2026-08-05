// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// SPAKE2 (RFC 9382) over P-256 with SHA-256, HKDF, and HMAC — the
// SPAKE2-P256-SHA256-HKDF-HMAC ciphersuite — built on @noble primitives.
// This is the PAKE under SCX: it turns a short spoken pairing code into a
// full-strength session key, and a wrong guess visibly breaks the
// handshake instead of silently succeeding.
//
// Verified against the four test vectors in RFC 9382 Appendix B.

import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';

const Point = p256.Point;
const ORDER = Point.Fn.ORDER; // group order n (prime, cofactor h = 1)

// Fixed points from RFC 9382 §6 ("Table of points", P-256, compressed SEC1).
export const SPAKE2_M_HEX = '02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f';
export const SPAKE2_N_HEX = '03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49';

const M = Point.fromHex(SPAKE2_M_HEX);
const N = Point.fromHex(SPAKE2_N_HEX);

const SHARE_BYTES = 65; // uncompressed SEC1, 0x04 prefix (RFC 9382 §6)
const FIELD_BYTES = 32; // w is encoded big-endian padded to len(p) (§3.3)

function bytesToBig(bytes) {
  return BigInt(`0x${bytesToHex(bytes)}`);
}

function bigTo32(x) {
  return hexToBytes(x.toString(16).padStart(FIELD_BYTES * 2, '0'));
}

// len(S) per RFC 9382 §3.2: eight-byte little-endian byte count.
function lenLE8(byteLength) {
  const out = new Uint8Array(8);
  let v = byteLength;
  for (let i = 0; i < 8; i++) {
    out[i] = v & 0xff;
    v = Math.floor(v / 256);
  }
  return out;
}

function lp(bytes) {
  return concatBytes(lenLE8(bytes.length), bytes);
}

// w derivation (v0, documented in WM-3): w = int(SHA-256(password || context))
// mod n. RFC 9382 recommends an MHF; SCX accepts plain SHA-256 for v0 because
// the online-guess bound — not offline hashing cost — is what protects the
// short code. In the astronomically unlikely case w = 0, re-hash.
export function deriveW(password, context = 'owm-scx-v1') {
  if (typeof password !== 'string' || password === '') throw new Error('password required');
  if (typeof context !== 'string') throw new Error('context must be a string');
  let digest = sha256(concatBytes(utf8ToBytes(password), utf8ToBytes(context)));
  let w = bytesToBig(digest) % ORDER;
  while (w === 0n) {
    digest = sha256(digest);
    w = bytesToBig(digest) % ORDER;
  }
  return w;
}

// Uniform scalar in [1, n) via rejection sampling (RFC 9382 §7 RECOMMENDS
// rejection sampling; no modulo bias).
function randomScalar() {
  const buf = new Uint8Array(FIELD_BYTES);
  for (;;) {
    globalThis.crypto.getRandomValues(buf);
    const v = bytesToBig(buf);
    if (v >= 1n && v < ORDER) return v;
  }
}

// Start a SPAKE2 run. Role 'a' computes pA = w*M + x*P; role 'b' computes
// pB = w*N + y*P (§3.3). `scalar` is injectable for test vectors ONLY.
// Returns opaque state carrying the secrets — never serialise it.
export function spake2Start({ role, w, scalar = randomScalar() }) {
  if (role !== 'a' && role !== 'b') throw new Error(`bad role: ${role}`);
  if (typeof w !== 'bigint' || w <= 0n || w >= ORDER) throw new Error('w must be a bigint in [1, n)');
  if (typeof scalar !== 'bigint' || scalar <= 0n || scalar >= ORDER) throw new Error('scalar out of range');
  const blind = role === 'a' ? M : N;
  const point = Point.BASE.multiply(scalar).add(blind.multiply(w));
  if (point.is0()) throw new Error('degenerate share'); // unreachable in practice
  return { role, w, scalar, share: point.toBytes(false) };
}

function decodeShare(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== SHARE_BYTES || bytes[0] !== 0x04) {
    return null; // wrong encoding — includes the SEC1 identity encoding (0x00)
  }
  let point;
  try {
    point = Point.fromBytes(bytes); // throws off-curve / malformed
  } catch {
    return null;
  }
  if (point.is0()) return null; // reject the identity element
  return point;
}

// Finish: validate the peer share, compute the shared element K, build the
// transcript TT exactly per §3.3, and run the §4 key schedule:
//   Ke || Ka  = SHA-256(TT)                       (16 bytes each)
//   KcA || KcB = HKDF-SHA256(Ka, nil, "ConfirmationKeys" || AAD, 32)
//   cA = HMAC-SHA256(KcA, TT), cB = HMAC-SHA256(KcB, TT)
// Returns { ok:false, error } on any invalid peer input — never throws for
// wire data.
export function spake2Finish({ state, peerShare, idA = '', idB = '', aad = '' }) {
  const peer = decodeShare(peerShare);
  if (!peer) return { ok: false, error: 'invalid peer share' };
  const { role, w, scalar, share } = state;
  // A computes K = h*x*(pB - w*N); B computes K = h*y*(pA - w*M). h = 1.
  const unblind = role === 'a' ? N : M;
  const stripped = peer.subtract(unblind.multiply(w));
  if (stripped.is0()) return { ok: false, error: 'degenerate shared element' };
  const K = stripped.multiply(scalar).toBytes(false);
  const pA = role === 'a' ? share : peerShare;
  const pB = role === 'a' ? peerShare : share;
  const transcript = concatBytes(
    lp(utf8ToBytes(idA)),
    lp(utf8ToBytes(idB)),
    lp(pA),
    lp(pB),
    lp(K),
    lp(bigTo32(w)),
  );
  const hash = sha256(transcript);
  const ke = hash.slice(0, 16);
  const ka = hash.slice(16);
  const info = concatBytes(utf8ToBytes('ConfirmationKeys'), utf8ToBytes(aad));
  const kc = hkdf(sha256, ka, undefined, info, 32);
  const kcA = kc.slice(0, 16);
  const kcB = kc.slice(16);
  const cA = hmac(sha256, kcA, transcript);
  const cB = hmac(sha256, kcB, transcript);
  return {
    ok: true,
    ke,
    ka,
    kcA,
    kcB,
    cA,
    cB,
    confirm: role === 'a' ? cA : cB, // the MAC we send
    expectedPeerConfirm: role === 'a' ? cB : cA, // the MAC we must receive
    transcript,
  };
}

// Constant-time byte comparison — MAC verification MUST NOT short-circuit.
// (Length is not secret; unequal lengths return false immediately.)
export function constantTimeEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
