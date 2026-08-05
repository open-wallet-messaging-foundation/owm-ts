// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OWM-AUTH / OWM-GRANT pure protocol logic (WM-7, kinds 530-534):
// canonical signing strings, challenge build, response/grant/revoke
// sign + verify. Signature scheme is identical to the SCX contact card
// (EIP-191 personal_sign, secp256k1 recovery, case-insensitive address
// compare) with three mutually disjoint domain-separation tags — an auth
// signature can never verify as a grant, a revoke, an SCX card, or an
// Ethereum transaction.
//
// Time convention: iat/exp/ts in these kinds are unix SECONDS (JWT
// convention). APIs that take a wall clock take `now` in unix MS, matching
// the rest of the codebase, and convert internally.

import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';
import {
  signPersonalMessage, recoverPersonalMessage, addressFromPrivateKey,
} from './eth-sign.js';
import {
  buildWmAuthChallenge, buildWmAuthResponse, buildWmGrant, buildWmGrantRevoke,
  parseMessage, randomNonce,
} from './envelope.js';

export const AUTH_DOMAIN = 'owm-auth-v1';
export const GRANT_DOMAIN = 'owm-grant-v1';
export const GRANT_REVOKE_DOMAIN = 'owm-grant-revoke-v1';

// A challenge lives at most 120 s (WM-7 §3): exp MUST be <= iat + 120.
export const AUTH_MAX_TTL_S = 120;

const requireStr = (name, x, { allowEmpty = false } = {}) => {
  if (typeof x !== 'string' || /[\r\n]/.test(x) || (!allowEmpty && x.length === 0)) {
    throw new Error(`${name} must be a non-empty string without newlines`);
  }
  return x;
};
const requireUnixS = (name, x) => {
  if (!Number.isInteger(x) || x <= 0) throw new Error(`${name} must be a positive integer (unix s)`);
  return x;
};

// Canonical auth string (normative, WM-7 §3.3):
//   "owm-auth-v1" \n rp \n action \n challenge \n match \n (binding | "-") \n exp
// An absent binding is encoded as "-"; consequently the literal binding
// value "-" is reserved and MUST NOT be issued.
export function canonicalAuthPayload({ rp, action, challenge, match, binding, exp }) {
  requireStr('rp', rp);
  requireStr('action', action);
  if (typeof challenge !== 'string' || !/^[0-9a-f]{64}$/.test(challenge)) {
    throw new Error('challenge must be 64 lowercase hex chars');
  }
  if (typeof match !== 'string' || !/^[0-9]{1,8}$/.test(match)) {
    throw new Error('match must be a 1-8 digit string');
  }
  if (binding !== undefined) requireStr('binding', binding);
  requireUnixS('exp', exp);
  return [AUTH_DOMAIN, rp, action, challenge, match, binding ?? '-', String(exp)].join('\n');
}

// Canonical grant string (normative, WM-7 §4.2):
//   "owm-grant-v1" \n rp \n client \n scope \n aud \n nonce \n iat \n exp
export function canonicalGrantPayload({ rp, client, scope, aud, nonce, iat, exp }) {
  requireStr('rp', rp);
  requireStr('client', client);
  requireStr('scope', scope);
  requireStr('aud', aud);
  if (typeof nonce !== 'string' || !/^[0-9a-f]{64}$/.test(nonce)) {
    throw new Error('nonce must be 64 lowercase hex chars');
  }
  requireUnixS('iat', iat);
  requireUnixS('exp', exp);
  return [GRANT_DOMAIN, rp, client, scope, aud, nonce, String(iat), String(exp)].join('\n');
}

// Canonical revoke string (normative, WM-7 §4.4):
//   "owm-grant-revoke-v1" \n grantId \n ts
export function canonicalGrantRevokePayload({ grantId, ts }) {
  if (typeof grantId !== 'string' || !/^[0-9a-f]{64}$/.test(grantId)) {
    throw new Error('grantId must be 64 lowercase hex chars');
  }
  requireUnixS('ts', ts);
  return [GRANT_REVOKE_DOMAIN, grantId, String(ts)].join('\n');
}

// grantId = SHA-256 hex of the canonical grant string. Deterministic:
// anyone holding the grant fields can compute it; nobody can forge a
// second grant with the same id short of a SHA-256 collision.
export function computeGrantId({ rp, client, scope, aud, nonce, iat, exp }) {
  return bytesToHex(sha256(utf8ToBytes(canonicalGrantPayload({ rp, client, scope, aud, nonce, iat, exp }))));
}

// --- OWM-AUTH ---------------------------------------------------------------

// Server side: mint a wm-auth-challenge (530). `now` is unix ms. The match
// code is NOT part of the envelope — the server displays it on the
// initiating screen and remembers it (see @open-wallet-messaging/auth OwmAuthServer).
export function buildAuthChallenge({ rp, action, binding, now, ttlS = AUTH_MAX_TTL_S, challenge = randomNonce(32) }) {
  if (typeof now !== 'number') throw new Error('now (unix ms) required');
  if (!Number.isInteger(ttlS) || ttlS < 1 || ttlS > AUTH_MAX_TTL_S) {
    throw new Error(`ttlS must be 1..${AUTH_MAX_TTL_S} seconds`);
  }
  const iat = Math.floor(now / 1000);
  return buildWmAuthChallenge({ rp, action, challenge, binding, iat, exp: iat + ttlS });
}

function requireKind(envelope, kind) {
  const parsed = parseMessage(JSON.stringify(envelope));
  if (!parsed.ok || parsed.kind !== kind) {
    throw new Error(`expected a strictly valid ${kind} envelope${parsed.error ? `: ${parsed.error}` : ''}`);
  }
  return parsed.body;
}

// Wallet side: sign a challenge envelope with the enrolled auth key plus
// the USER-ENTERED match code -> wm-auth-response (531). Refuses malformed
// or over-TTL challenges (a wallet must never blind-sign). `binding`
// defaults to the challenge's own binding; strict-mode wallets may supply
// one obtained out-of-band (e.g. scanned from the genuine page).
export function signAuthResponse({ privateKey, challenge, match, binding }) {
  const env = requireKind(challenge, 'wm-auth-challenge');
  if (env.exp - env.iat > AUTH_MAX_TTL_S) {
    throw new Error(`challenge TTL exceeds ${AUTH_MAX_TTL_S}s — refusing to sign`);
  }
  const payload = canonicalAuthPayload({
    rp: env.rp,
    action: env.action,
    challenge: env.challenge,
    match,
    binding: binding ?? env.binding,
    exp: env.exp,
  });
  return buildWmAuthResponse({
    challenge: env.challenge,
    match,
    addr: addressFromPrivateKey(privateKey),
    sig: signPersonalMessage(payload, privateKey),
  });
}

// Server side: verify a wm-auth-response against what THIS server issued
// and displayed. Every expected value comes from server state, never from
// the envelope. Distinct failure reasons (in check order):
//   'challenge-mismatch'  response is for a different nonce
//   'expired'             past exp (now: unix ms)
//   'match-mismatch'      user typed a different code than displayed
//   'bad-signature'       sig malformed / does not recover the claimed addr
//   'wrong-address'       valid sig, but not by the enrolled auth address
export function verifyAuthResponse(envelope, expected) {
  let env;
  try {
    env = requireKind(envelope, 'wm-auth-response');
  } catch {
    return { ok: false, reason: 'bad-signature' };
  }
  const { rp, action, challenge, match, binding, exp, enrolledAddress, now } = expected;
  if (typeof now !== 'number') throw new Error('expected.now (unix ms) required');
  if (env.challenge !== challenge) return { ok: false, reason: 'challenge-mismatch' };
  if (Math.floor(now / 1000) > exp) return { ok: false, reason: 'expired' };
  if (env.match !== match) return { ok: false, reason: 'match-mismatch' };
  const payload = canonicalAuthPayload({ rp, action, challenge, match, binding, exp });
  const signer = recoverPersonalMessage(payload, env.sig);
  if (signer === null || signer !== env.addr.toLowerCase()) {
    return { ok: false, reason: 'bad-signature' };
  }
  if (enrolledAddress !== undefined && signer !== enrolledAddress.toLowerCase()) {
    return { ok: false, reason: 'wrong-address' };
  }
  return { ok: true, address: signer };
}

// --- OWM-GRANT --------------------------------------------------------------

// Wallet side: sign a capability grant -> wm-grant (533). Fields normally
// echo a wm-grant-request (532) the user just approved (WYSIWYS).
export function signGrant({ privateKey, rp, client, scope, aud, nonce, iat, exp }) {
  const payload = canonicalGrantPayload({ rp, client, scope, aud, nonce, iat, exp });
  return buildWmGrant({
    rp, client, scope, aud, nonce, iat, exp,
    addr: addressFromPrivateKey(privateKey),
    sig: signPersonalMessage(payload, privateKey),
  });
}

// Resource-server side, OFFLINE: verify the signature chain of a wm-grant.
// Checks (in order): strict envelope + signature recovers env.addr
// ('bad-signature'); signer is the expected per-RP identity
// ('wrong-address', only when expectedAddress given); not past exp
// ('expired', only when now [unix ms] given). Policy checks — aud match,
// revocation, long-exp registry rule — live one layer up (@open-wallet-messaging/auth
// GrantServer / WM-7 §4.3).
export function verifyGrant(envelope, { now, expectedAddress } = {}) {
  let env;
  try {
    env = requireKind(envelope, 'wm-grant');
  } catch {
    return { ok: false, reason: 'bad-signature' };
  }
  const { rp, client, scope, aud, nonce, iat, exp } = env;
  const payload = canonicalGrantPayload({ rp, client, scope, aud, nonce, iat, exp });
  const signer = recoverPersonalMessage(payload, env.sig);
  if (signer === null || signer !== env.addr.toLowerCase()) {
    return { ok: false, reason: 'bad-signature' };
  }
  if (expectedAddress !== undefined && signer !== expectedAddress.toLowerCase()) {
    return { ok: false, reason: 'wrong-address' };
  }
  if (now !== undefined && Math.floor(now / 1000) > exp) {
    return { ok: false, reason: 'expired' };
  }
  return {
    ok: true,
    address: signer,
    grantId: computeGrantId({ rp, client, scope, aud, nonce, iat, exp }),
  };
}

// Wallet side: revoke a grant by id -> wm-grant-revoke (534). ts unix s.
export function signGrantRevoke({ privateKey, grantId, ts }) {
  const payload = canonicalGrantRevokePayload({ grantId, ts });
  return buildWmGrantRevoke({ grantId, ts, sig: signPersonalMessage(payload, privateKey) });
}

// Registry side: a revoke is valid only if signed by the same key that
// signed the grant (expectedAddress = the grant's addr).
export function verifyGrantRevoke(envelope, { expectedAddress } = {}) {
  let env;
  try {
    env = requireKind(envelope, 'wm-grant-revoke');
  } catch {
    return { ok: false, reason: 'bad-signature' };
  }
  const payload = canonicalGrantRevokePayload({ grantId: env.grantId, ts: env.ts });
  const signer = recoverPersonalMessage(payload, env.sig);
  if (signer === null) return { ok: false, reason: 'bad-signature' };
  if (expectedAddress !== undefined && signer !== expectedAddress.toLowerCase()) {
    return { ok: false, reason: 'wrong-address' };
  }
  return { ok: true, address: signer };
}

// --- Per-RP sub-identity derivation ------------------------------------------

const SECP256K1_N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');

// PLACEHOLDER derivation (WM-7 §5): scalar = keccak256(seed || utf8(rp))
// reduced into [1, n-1]. Deterministic, one address per RP, primary address
// never appears — but NOT hardened HD derivation: production wallets will
// replace this with BIP-32 hardened paths (WM-1 sub-identity ladder) before
// v0 freeze. Seed >= 16 bytes (hex string or Uint8Array).
export function deriveRpSubKey(seed, rp) {
  let seedBytes;
  if (seed instanceof Uint8Array) seedBytes = seed;
  else if (typeof seed === 'string' && /^(0x)?[0-9a-fA-F]{32,}$/.test(seed) && seed.replace(/^0x/, '').length % 2 === 0) {
    seedBytes = hexToBytes(seed.replace(/^0x/, '').toLowerCase());
  } else throw new Error('seed must be >=16 bytes (hex or Uint8Array)');
  if (seedBytes.length < 16) throw new Error('seed must be >=16 bytes');
  if (typeof rp !== 'string' || rp.length === 0) throw new Error('rp required');
  const digest = keccak_256(concatBytes(seedBytes, utf8ToBytes(rp)));
  const scalar = (BigInt(`0x${bytesToHex(digest)}`) % (SECP256K1_N - 1n)) + 1n;
  return scalar.toString(16).padStart(64, '0');
}
