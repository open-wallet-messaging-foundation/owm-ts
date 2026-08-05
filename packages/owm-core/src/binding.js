// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// WM-9 OWM-BIND (general) — a signed association between a wallet address and a
// typed subject (SMS, email, bank account, card, another wallet, …), carrying a
// capability set and an accept posture. Grant-shaped, EIP-191 signed (shared
// with WM-3/WM-7). A `mutual` binding adds a counterparty attestation (kind 528),
// whose signing key is trust-anchored to a domain via Web PKI / DNS (WM-9 §7).

import {
  signPersonalMessage, recoverPersonalMessage, addressFromPrivateKey, toChecksumAddress,
} from './eth-sign.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

export const BINDING_DOMAIN = 'owm-binding-v1';
export const ATTEST_DOMAIN = 'owm-binding-attest-v1';
export const DIRECTIONS = ['sink', 'source'];
export const ACCEPT_POSTURES = ['everything', 'secure', 'verified'];

function nowS() { return Math.floor(Date.now() / 1000); }

// Subject values (phone, email, PAN, account ref) are never carried in the clear
// in the signed payload — only this stable reference hash is.
export function subjectRef(type, value) {
  return bytesToHex(sha256(utf8ToBytes(`${type}:${String(value).trim().toLowerCase()}`)));
}
function normCaps(caps) { return [...new Set(caps)].sort().join(','); }

// The exact bytes signed. Domain tag first, capabilities sorted+comma-joined so
// the canonical is order-independent, subject bound by its reference hash.
export function canonicalBindingPayload({ address, subjectType, subjectRef: ref, direction, capabilities, accept, iat, exp }) {
  return [BINDING_DOMAIN, String(address).toLowerCase(), subjectType, ref, direction, normCaps(capabilities), accept, String(iat), String(exp)].join('\n');
}
export function computeBindingId(fields) {
  return bytesToHex(sha256(utf8ToBytes(canonicalBindingPayload(fields))));
}

export function signBinding({
  privateKey, subjectType, subjectValue, direction, capabilities, accept = 'secure', ttlS = 31536000, now = nowS(),
}) {
  if (!DIRECTIONS.includes(direction)) throw new Error(`direction must be one of ${DIRECTIONS.join('|')}`);
  if (!ACCEPT_POSTURES.includes(accept)) throw new Error(`accept must be one of ${ACCEPT_POSTURES.join('|')}`);
  const address = addressFromPrivateKey(privateKey).toLowerCase();
  const fields = {
    address, subjectType, subjectRef: subjectRef(subjectType, subjectValue),
    direction, capabilities: [...new Set(capabilities)].sort(), accept, iat: now, exp: now + ttlS,
  };
  const sig = signPersonalMessage(canonicalBindingPayload(fields), privateKey);
  return { v: 1, kind: 'owm-binding', ...fields, sig, bindingId: computeBindingId(fields) };
}

// Verify a binding: the signature must recover to the binding's own address
// (self-asserted), unexpired, and (optionally) equal an expected owner.
export function verifyBinding(binding, { now = nowS(), expectedAddress } = {}) {
  if (!binding || binding.kind !== 'owm-binding') return { ok: false, error: 'not an owm-binding' };
  if (binding.exp && now > binding.exp) return { ok: false, error: 'expired' };
  const recovered = recoverPersonalMessage(canonicalBindingPayload(binding), binding.sig);
  if (!recovered) return { ok: false, error: 'bad signature' };
  if (recovered.toLowerCase() !== String(binding.address).toLowerCase()) return { ok: false, error: 'signature is not from the binding address' };
  if (expectedAddress && recovered.toLowerCase() !== String(expectedAddress).toLowerCase()) return { ok: false, error: 'not the expected owner' };
  return { ok: true, address: toChecksumAddress(recovered) };
}

// ── Mutual attestation (kind owm-binding-attest, 528) ─────────────────────────
// The counterparty (e.g. a bank) signs over the bindingId + the domain their key
// is trust-anchored to (WM-9 §7: proven via .well-known over TLS / DNSSEC).
export function canonicalAttestPayload({ bindingId, domain, ts }) {
  return [ATTEST_DOMAIN, bindingId, String(domain).toLowerCase(), String(ts)].join('\n');
}
export function signBindingAttest({ privateKey, bindingId, domain, now = nowS() }) {
  const fields = { bindingId, domain: String(domain).toLowerCase(), ts: now };
  const sig = signPersonalMessage(canonicalAttestPayload(fields), privateKey);
  return { v: 1, kind: 'owm-binding-attest', ...fields, sig };
}
// Recovers the attester's address. The caller MUST additionally verify that this
// address controls `attest.domain` via the WM-9 trust anchor (Web PKI/DNS) — that
// check is a network fetch, out of scope for this pure function.
export function verifyBindingAttest(attest) {
  if (!attest || attest.kind !== 'owm-binding-attest') return { ok: false, error: 'not an owm-binding-attest' };
  const recovered = recoverPersonalMessage(canonicalAttestPayload(attest), attest.sig);
  if (!recovered) return { ok: false, error: 'bad signature' };
  return { ok: true, attester: toChecksumAddress(recovered), domain: attest.domain, bindingId: attest.bindingId };
}
