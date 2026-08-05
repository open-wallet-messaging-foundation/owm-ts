// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// WM-13 OWM-ATTEST — an issuer signs a typed claim about a subject. OWM-native
// Verifiable Credentials. Self-attestation (issuer == subject) is a WM-9 binding;
// the general case is a third party vouching (a bank → KYC tier, a CA → SSH
// principal, a venue → paid access). EIP-191, domain disjoint from every other
// OWM signing domain.

import {
  signPersonalMessage, recoverPersonalMessage, addressFromPrivateKey, toChecksumAddress,
} from './eth-sign.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

export const ATTESTATION_DOMAIN = 'owm-attestation-v1';
function nowS() { return Math.floor(Date.now() / 1000); }
function lc(x) { return String(x).toLowerCase(); }
function h(s) { return bytesToHex(sha256(utf8ToBytes(s))); }

// Deterministic canonical JSON (sorted keys) so a claim body hashes stably across
// implementations. Shared by presentation.js / transfer.js (imported, not re-exported).
export function canonicalJson(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(',')}}`;
}
export function claimHash(claim) { return h(canonicalJson(claim ?? {})); }

// The exact bytes signed. `subject` may be an address or a WM-9 subjectRef hash;
// `anchor` is the domain the issuer key is trust-anchored to (WM-9 §7) or "".
export function canonicalAttestation({ issuer, subject, claimType, claim, anchor, iat, exp }) {
  return [ATTESTATION_DOMAIN, lc(issuer), lc(subject), claimType, claimHash(claim), anchor ? lc(anchor) : '', String(iat), String(exp)].join('\n');
}
export function computeAttestationId(fields) { return h(canonicalAttestation(fields)); }

export function signAttestation({ privateKey, subject, claimType, claim = {}, anchor = '', ttlS = 31536000, now = nowS() }) {
  const issuer = addressFromPrivateKey(privateKey).toLowerCase();
  const fields = { issuer, subject: lc(subject), claimType, claim, anchor, iat: now, exp: now + ttlS };
  const sig = signPersonalMessage(canonicalAttestation(fields), privateKey);
  return { v: 1, kind: 'owm-attestation', ...fields, sig, attestationId: computeAttestationId(fields) };
}

// Verify: sig recovers to `issuer`, unexpired, id-integrity, optional expected
// issuer/subject. The verifier MUST separately validate `anchor` against the WM-9
// §7 trust anchors (a network fetch, out of scope for this pure verify).
export function verifyAttestation(att, { now = nowS(), expectedIssuer, expectedSubject } = {}) {
  if (!att || att.kind !== 'owm-attestation') return { ok: false, error: 'not an owm-attestation' };
  if (att.exp != null && now > att.exp) return { ok: false, error: 'expired' };
  if (att.attestationId && att.attestationId !== computeAttestationId(att)) return { ok: false, error: 'attestationId mismatch (tampered)' };
  const rec = recoverPersonalMessage(canonicalAttestation(att), att.sig);
  if (!rec) return { ok: false, error: 'bad signature' };
  if (lc(rec) !== lc(att.issuer)) return { ok: false, error: 'signature is not from the issuer' };
  if (expectedIssuer && lc(rec) !== lc(expectedIssuer)) return { ok: false, error: 'not the expected issuer' };
  if (expectedSubject && lc(att.subject) !== lc(expectedSubject)) return { ok: false, error: 'not the expected subject' };
  return { ok: true, issuer: toChecksumAddress(rec), subject: att.subject, claimType: att.claimType };
}
