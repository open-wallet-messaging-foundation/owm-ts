// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// WM-14 OWM-PRESENT — a holder proves (or discloses) a signed object to an
// audience, bound to context and a freshness challenge, non-repudiably. This is
// WM-10 §10b REVEAL generalised out of KV: it presents ANY signed object (an
// attestation, a binding, a KV record, a ticket). EIP-191, disjoint domain.

import {
  signPersonalMessage, recoverPersonalMessage, addressFromPrivateKey, toChecksumAddress,
} from './eth-sign.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { canonicalJson } from './attestation.js';

export const PRESENTATION_DOMAIN = 'owm-presentation-v1';
function nowS() { return Math.floor(Date.now() / 1000); }
function lc(x) { return String(x).toLowerCase(); }
function h(s) { return bytesToHex(sha256(utf8ToBytes(s))); }
function normFields(fields) { return (!fields || fields === '*') ? '*' : [...new Set(fields)].sort().join(','); }

// The version pin: hash of the presented object (or pass its id string directly).
export function objectHash(obj) { return typeof obj === 'string' ? obj : h(canonicalJson(obj)); }

export function canonicalPresentation({ holder, objectKind, objectHash: oh, audience, challenge, fields, iat, exp }) {
  return [PRESENTATION_DOMAIN, lc(holder), objectKind, oh, lc(audience), String(challenge), normFields(fields), String(iat), String(exp)].join('\n');
}
export function computePresentationId(f) { return h(canonicalPresentation(f)); }

export function signPresentation({ privateKey, objectKind, object, objectHash: oh, audience, challenge, fields = '*', ttlS = 300, now = nowS() }) {
  const holder = addressFromPrivateKey(privateKey).toLowerCase();
  const f = {
    holder, objectKind, objectHash: oh ?? objectHash(object), audience: lc(audience),
    challenge: String(challenge), fields: normFields(fields), iat: now, exp: now + ttlS,
  };
  const sig = signPersonalMessage(canonicalPresentation(f), privateKey);
  return { v: 1, kind: 'owm-presentation', ...f, sig, presentationId: computePresentationId(f) };
}

// Verify: sig recovers to `holder`, unexpired, and — for anything that GATES access
// — `challenge` MUST equal the nonce the verifier issued (defeats replay) and, if
// given, `audience` MUST match. The verifier MUST separately verify the presented
// object's own signature/attestation (presentation proves possession + context).
export function verifyPresentation(p, { now = nowS(), expectedChallenge, expectedAudience } = {}) {
  if (!p || p.kind !== 'owm-presentation') return { ok: false, error: 'not an owm-presentation' };
  if (p.exp != null && now > p.exp) return { ok: false, error: 'expired' };
  if (expectedChallenge != null && String(p.challenge) !== String(expectedChallenge)) return { ok: false, error: 'stale or replayed (challenge mismatch)' };
  if (expectedAudience && lc(p.audience) !== lc(expectedAudience)) return { ok: false, error: 'wrong audience' };
  if (p.presentationId && p.presentationId !== computePresentationId(p)) return { ok: false, error: 'presentationId mismatch (tampered)' };
  const rec = recoverPersonalMessage(canonicalPresentation(p), p.sig);
  if (!rec) return { ok: false, error: 'bad signature' };
  if (lc(rec) !== lc(p.holder)) return { ok: false, error: 'signature is not from the holder' };
  return { ok: true, holder: toChecksumAddress(rec), objectKind: p.objectKind, objectHash: p.objectHash };
}
