// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// WM-15 OWM-XFER — hand a bound object (an attestation, a binding, a WM-11
// entitlement) to a new holder under the issuer's policy. State advances by the
// same append-only fold + hash-chain used across OWM: the current holder = the
// `to` of the latest chain-valid transfer; a double-transfer / fork is rejected by
// CAS. EIP-191, disjoint domain. Issuer-policy enforcement (soulbound / mediated /
// cap / royalty) is applied by the caller holding the object's issuer attestation.

import {
  signPersonalMessage, recoverPersonalMessage, addressFromPrivateKey, toChecksumAddress,
} from './eth-sign.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { canonicalJson } from './attestation.js';

export const TRANSFER_DOMAIN = 'owm-transfer-v1';
function nowS() { return Math.floor(Date.now() / 1000); }
function lc(x) { return String(x).toLowerCase(); }
function h(s) { return bytesToHex(sha256(utf8ToBytes(s))); }

export function canonicalTransfer({ objectId, objectKind, from, to, terms, prevId, iat, exp }) {
  return [TRANSFER_DOMAIN, objectId, objectKind, lc(from), lc(to), terms ? h(canonicalJson(terms)) : '', prevId || '', String(iat), String(exp)].join('\n');
}
export function computeTransferId(f) { return h(canonicalTransfer(f)); }

export function signTransfer({ privateKey, objectId, objectKind, to, terms = null, prevId = '', ttlS = 3600, now = nowS() }) {
  const from = addressFromPrivateKey(privateKey).toLowerCase();
  const f = { objectId, objectKind, from, to: lc(to), terms, prevId, iat: now, exp: now + ttlS };
  const sig = signPersonalMessage(canonicalTransfer(f), privateKey);
  return { v: 1, kind: 'owm-transfer', ...f, sig, transferId: computeTransferId(f) };
}

// Verify: sig recovers to `from` (the current holder authorises the hand-off),
// unexpired, id-integrity. Issuer counter-signature (mediated policy) is checked by
// the caller against the object's issuer attestation.
export function verifyTransfer(t, { now = nowS() } = {}) {
  if (!t || t.kind !== 'owm-transfer') return { ok: false, error: 'not an owm-transfer' };
  if (t.exp != null && now > t.exp) return { ok: false, error: 'expired' };
  if (t.transferId && t.transferId !== computeTransferId(t)) return { ok: false, error: 'transferId mismatch (tampered)' };
  const rec = recoverPersonalMessage(canonicalTransfer(t), t.sig);
  if (!rec) return { ok: false, error: 'bad signature' };
  if (lc(rec) !== lc(t.from)) return { ok: false, error: 'signature is not from the current holder' };
  return { ok: true, from: toChecksumAddress(rec), to: t.to };
}

// Fold a transfer chain for one object → current holder + the chain-of-custody.
// Each transfer's `from` MUST equal the running holder and `prevId` MUST chain to
// the prior accepted transfer's id ("" for the first). Everything else is rejected.
// NOTE (v0): transfers on one object MUST have strictly increasing iat.
export function foldTransfers(transfers, { objectId, originalHolder }) {
  let holder = lc(originalHolder);
  let headId = '';
  const chain = [];
  const rejected = [];
  const sorted = [...transfers]
    .filter((t) => t.objectId === objectId)
    .sort((a, b) => (a.iat - b.iat) || (a.transferId < b.transferId ? -1 : a.transferId > b.transferId ? 1 : 0));
  for (const t of sorted) {
    const vr = verifyTransfer(t, { now: t.iat }); // a transfer is validated as of its own issue time
    if (!vr.ok) { rejected.push({ t, reason: vr.error }); continue; }
    if (lc(t.from) !== holder) { rejected.push({ t, reason: 'not signed by the current holder' }); continue; }
    if ((t.prevId || '') !== headId) { rejected.push({ t, reason: 'prevId mismatch (stale / forked)' }); continue; }
    holder = lc(t.to); headId = t.transferId; chain.push(t.transferId);
  }
  return { holder: toChecksumAddress(holder), headId, chain, rejected };
}
