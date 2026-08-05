// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OWM-APPROVAL (WM-7 §9, kinds 535-537): M-of-N approvals over messaging.
// The MLS room is the committee; these are the wire shapes + the OFFLINE
// quorum verifier — anyone holding the request (and its policy) can verify
// a 537 aggregate with no server, same property as WM-7 §4 grants.
//
// Canonical (WM-7 §9, normative):
//   "owm-approval-v1" \n rp \n approvalId \n sha256(action) \n signer \n exp
// The ACTION is hashed into the canonical, so approvals are WYSIWYS-bound:
// a signature over "release wire #114 for $250k" cannot be replayed onto a
// different action, approval, rp, or window. Signing the hash (not the
// text) keeps multiline WYSIWYS actions out of the newline-delimited
// canonical.
//
// Safe interop: when the approved action IS an on-chain Safe transaction, the
// action text embeds the safeTxHash; the Phase 4 execution adapter has each
// signer ALSO produce the EIP-712 SafeTx owner signature in the same
// ceremony. The 536 is the room-side approval; the adapter's sig is the
// chain-side one — two signatures, disjoint domains, one screen.

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { addressFromPrivateKey, signPersonalMessage, recoverPersonalMessage } from './eth-sign.js';
import { buildWmApprovalRequest, buildWmApprovalSig, buildWmApprovalResult, randomNonce } from './envelope.js';

export const APPROVAL_DOMAIN = 'owm-approval-v1';

export function actionHash(action) {
  return bytesToHex(sha256(utf8ToBytes(action)));
}

export function canonicalApprovalPayload({ rp, approvalId, actionHash: ah, signer, exp }) {
  return [APPROVAL_DOMAIN, rp, approvalId, ah, signer.toLowerCase(), String(exp)].join('\n');
}

export function buildApprovalRequest({ rp, action, policy, now, ttlS = 3600, approvalId = randomNonce(32) }) {
  if (!Number.isInteger(now)) throw new Error('now (unix seconds) required');
  return buildWmApprovalRequest({ rp, action, policy, approvalId, iat: now, exp: now + ttlS });
}

// One approver signs the request as displayed on THEIR device.
export function signApproval({ privateKey, request }) {
  const signer = addressFromPrivateKey(privateKey);
  const ah = actionHash(request.action);
  const sig = signPersonalMessage(
    canonicalApprovalPayload({ rp: request.rp, approvalId: request.approvalId, actionHash: ah, signer, exp: request.exp }),
    privateKey,
  );
  return buildWmApprovalSig({ approvalId: request.approvalId, signer, actionHash: ah, sig });
}

// Verify ONE 536 against its request. `now` (unix s) enforces the signing
// window; omit it for historical audit of an already-accepted approval.
export function verifyApprovalSig(env, request, { now } = {}) {
  if (typeof env !== 'object' || env === null) return { ok: false, error: 'not an approval sig' };
  if (env.approvalId !== request.approvalId) return { ok: false, error: 'wrong approval' };
  const ah = actionHash(request.action);
  if (env.actionHash !== ah) return { ok: false, error: 'action mismatch' };
  if (typeof now === 'number' && now >= request.exp) return { ok: false, error: 'expired' };
  const signer = recoverPersonalMessage(
    canonicalApprovalPayload({ rp: request.rp, approvalId: request.approvalId, actionHash: ah, signer: env.signer, exp: request.exp }),
    env.sig,
  );
  if (!signer) return { ok: false, error: 'bad signature' };
  if (signer !== env.signer.toLowerCase()) return { ok: false, error: 'signer is not the declared signer' };
  const rostered = request.policy.signers.some((s) => s.toLowerCase() === signer);
  if (!rostered) return { ok: false, error: 'signer not in policy' };
  return { ok: true, signer };
}

// Aggregate ≥m valid, distinct signatures into a 537. Throws below quorum —
// a partial aggregate must never look like a result.
export function aggregateApprovalResult({ request, sigs, ts, now }) {
  const seen = new Set();
  const kept = [];
  for (const env of sigs) {
    const v = verifyApprovalSig(env, request, { now });
    if (!v.ok || seen.has(v.signer)) continue;
    seen.add(v.signer);
    kept.push({ signer: env.signer, sig: env.sig });
  }
  if (kept.length < request.policy.m) {
    throw new Error(`quorum not met: ${kept.length}/${request.policy.m}`);
  }
  return buildWmApprovalResult({
    approvalId: request.approvalId, actionHash: actionHash(request.action), sigs: kept, ts,
  });
}

// The offline quorum verifier: anyone holding the request verifies a 537.
// Every listed signature must recover, match the roster, and be distinct;
// the quorum must clear policy.m. Returns the distinct signers on success.
export function verifyApprovalResult(env, request, { now } = {}) {
  if (typeof env !== 'object' || env === null) return { ok: false, error: 'not an approval result' };
  if (env.approvalId !== request.approvalId) return { ok: false, error: 'wrong approval' };
  if (env.actionHash !== actionHash(request.action)) return { ok: false, error: 'action mismatch' };
  const seen = new Set();
  for (const entry of env.sigs) {
    const v = verifyApprovalSig(
      { approvalId: env.approvalId, actionHash: env.actionHash, signer: entry.signer, sig: entry.sig },
      request,
      { now },
    );
    if (!v.ok) return { ok: false, error: v.error };
    if (seen.has(v.signer)) return { ok: false, error: `duplicate signer: ${v.signer}` };
    seen.add(v.signer);
  }
  if (seen.size < request.policy.m) {
    return { ok: false, error: `quorum not met: ${seen.size}/${request.policy.m}` };
  }
  return { ok: true, signers: [...seen] };
}
