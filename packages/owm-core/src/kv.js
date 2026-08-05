// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// WM-10 OWM-KV (v0) — the wallet-native personal record store. The address's own
// self-conversation is the store; a record's current value is the FOLD of an
// append-only, signed, hash-chained op log. Five verbs (set/get/delete/list/
// reveal) each carry an independent capability; writes are authorised at fold
// time, so an unauthorised or tampered op is simply not folded into state — no
// trusted server required. EIP-191 signing (shared with WM-3/7/8/9); domains are
// disjoint from every other OWM signing domain, so a KV op can never be replayed
// as an auth, grant, approval, binding, or contact card.
//
// Scope of this module: it SIGNS and AUTHORISES ops and FOLDS the log. It does
// not re-implement value sealing — a value is a WM-8 blob (recipient-crypto.js)
// and the op signs its `valueHash`, binding the signature to the exact bytes.

import {
  signPersonalMessage, recoverPersonalMessage, addressFromPrivateKey, toChecksumAddress,
} from './eth-sign.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

export const KV_VERBS = ['set', 'get', 'delete', 'list', 'reveal'];
export const KV_WRITE_VERBS = ['set', 'delete'];
export const KV_DOMAINS = Object.freeze({
  set: 'owm-kv-set-v1',
  get: 'owm-kv-get-v1',
  delete: 'owm-kv-del-v1',
  list: 'owm-kv-list-v1',
  reveal: 'owm-kv-reveal-v1',
  grant: 'owm-kv-grant-v1',
});
const KV_KIND = Object.freeze({
  set: 'owm-kv-set', get: 'owm-kv-get', delete: 'owm-kv-delete',
  list: 'owm-kv-list', reveal: 'owm-kv-reveal', grant: 'owm-kv-grant',
});

function nowS() { return Math.floor(Date.now() / 1000); }
function lc(x) { return String(x).toLowerCase(); }
function h(s) { return bytesToHex(sha256(utf8ToBytes(s))); }

// valueHash binds an op to exact ciphertext bytes; helper for callers holding the
// sealed value as a string or bytes.
export function valueHash(bytesOrString) {
  return bytesToHex(sha256(typeof bytesOrString === 'string' ? utf8ToBytes(bytesOrString) : bytesOrString));
}

// recordId names the logical slot: owner + namespace + key. Low-entropy keys are
// confirmable-by-hash (WM-10 §2 / WM-9 §5) — at-rest leak resistance, not anonymity.
export function recordId(owner, namespace, key) {
  return h(`owm-kv-v1:${lc(owner)}:${namespace}:${key}`);
}
// opId = hash of the canonical signing payload — also the hash-chain link (prevId).
export function computeOpId(canonical) { return h(canonical); }

// The exact bytes signed for each verb. Writes carry valueHash + prevId (the
// chain); reads carry a nonce (single-use); reveal binds the disclosure to a
// group + audience + optional freshness challenge (WM-10 §10b).
export function canonicalKvOp(op) {
  const o = lc(op.owner);
  switch (op.verb) {
    case 'set':
      return [KV_DOMAINS.set, o, op.namespace, op.key, op.valueHash || '', op.prevId || '', String(op.iat), String(op.exp ?? '')].join('\n');
    case 'delete':
      return [KV_DOMAINS.delete, o, op.namespace, op.key, op.prevId || '', String(op.iat)].join('\n');
    case 'get':
      return [KV_DOMAINS.get, o, op.namespace, op.key, op.nonce, String(op.iat)].join('\n');
    case 'list':
      return [KV_DOMAINS.list, o, op.namespace, op.nonce, String(op.iat)].join('\n');
    case 'reveal':
      // versionId = the opId of the SET being disclosed (WM-10 §10b "opId").
      return [KV_DOMAINS.reveal, o, op.namespace, op.key, op.valueHash || '', op.versionId || '', op.groupId, op.audienceHash || '', op.challenge || '', String(op.iat)].join('\n');
    default:
      throw new Error(`unknown kv verb: ${op.verb}`);
  }
}

// Sign an op. `owner` is the store owner (whose namespace); the AUTHOR is whoever
// holds privateKey (owner or a delegate) and is recovered from the signature at
// verify/fold time. Defaults owner to the signer for the common self-op case.
export function signKvOp({ privateKey, verb, now = nowS(), ...rest }) {
  if (!KV_VERBS.includes(verb)) throw new Error(`verb must be one of ${KV_VERBS.join('|')}`);
  const owner = rest.owner ? lc(rest.owner) : addressFromPrivateKey(privateKey).toLowerCase();
  const op = { verb, ...rest, owner, iat: rest.iat ?? now };
  const canonical = canonicalKvOp(op);
  const sig = signPersonalMessage(canonical, privateKey);
  return { v: 1, kind: KV_KIND[verb], ...op, sig, opId: computeOpId(canonical) };
}

// Verify signature + opId integrity and recover the author. Does NOT check
// authorisation — that is the fold's job, against the grant set.
export function verifyKvOp(op) {
  if (!op || !KV_VERBS.includes(op.verb)) return { ok: false, error: 'not a kv op' };
  let canonical;
  try { canonical = canonicalKvOp(op); } catch (e) { return { ok: false, error: e.message }; }
  const id = computeOpId(canonical);
  if (op.opId && op.opId !== id) return { ok: false, error: 'opId does not match payload (tampered)' };
  const author = recoverPersonalMessage(canonical, op.sig);
  if (!author) return { ok: false, error: 'bad signature' };
  return { ok: true, author: toChecksumAddress(author), owner: op.owner, opId: id };
}

// ── Per-verb capability grants (owner authorises a grantee) ───────────────────
// A WM-7 grant (kind 533) specialised to KV: verbs × namespace, time-boxed.
function normVerbs(verbs) { return [...new Set(verbs)].filter((v) => KV_VERBS.includes(v)).sort(); }

export function canonicalKvGrant({ owner, grantee, namespace, verbs, iat, exp }) {
  return [KV_DOMAINS.grant, lc(owner), lc(grantee), namespace, normVerbs(verbs).join(','), String(iat), String(exp)].join('\n');
}
export function signKvGrant({ privateKey, grantee, namespace, verbs, ttlS = 31536000, now = nowS() }) {
  const fields = {
    owner: addressFromPrivateKey(privateKey).toLowerCase(), grantee: lc(grantee),
    namespace, verbs: normVerbs(verbs), iat: now, exp: now + ttlS,
  };
  const sig = signPersonalMessage(canonicalKvGrant(fields), privateKey);
  return { v: 1, kind: KV_KIND.grant, ...fields, sig, grantId: h(canonicalKvGrant(fields)) };
}
export function verifyKvGrant(grant, { now = nowS() } = {}) {
  if (!grant || grant.kind !== 'owm-kv-grant') return { ok: false, error: 'not a kv grant' };
  if (grant.exp != null && now > grant.exp) return { ok: false, error: 'expired' };
  const signer = recoverPersonalMessage(canonicalKvGrant(grant), grant.sig);
  if (!signer) return { ok: false, error: 'bad signature' };
  if (lc(signer) !== lc(grant.owner)) return { ok: false, error: 'grant not signed by its owner' };
  return { ok: true, owner: toChecksumAddress(signer) };
}

// Is `author` allowed to `verb` on (owner, namespace) at time `iat`? The owner may
// do anything on their own store; otherwise a valid, unexpired, owner-signed grant
// covering (grantee, namespace, verb) at that time must exist.
export function isAuthorised({ author, owner, verb, namespace, iat, grants = [] }) {
  if (lc(author) === lc(owner)) return true;
  return grants.some((g) => (
    lc(g.owner) === lc(owner)
    && lc(g.grantee) === lc(author)
    && g.namespace === namespace
    && Array.isArray(g.verbs) && g.verbs.includes(verb)
    && (g.iat == null || iat >= g.iat)
    && (g.exp == null || iat <= g.exp)
    && verifyKvGrant(g, { now: iat }).ok
  ));
}

// Fold an append-only op log into current state. Accepts a SET/DELETE only if:
//   (1) its signature verifies (author recovered),
//   (2) the author is authorised for that verb+namespace at the op's iat, and
//   (3) prevId chains to the record's current head (CAS: '' for the first write).
// Everything else is collected in `rejected` with a reason. A DELETE is a
// tombstone — the record drops from current state but the signed event remains.
// NOTE (v0): ops within a record MUST have strictly increasing iat; the owner
// assigns them in write order, so iat-order == chain-order.
export function foldKv(ops, { grants = [] } = {}) {
  const heads = {};        // recordId -> accepted op
  const rejected = [];
  const sorted = [...ops].sort((a, b) => (a.iat - b.iat) || (a.opId < b.opId ? -1 : a.opId > b.opId ? 1 : 0));
  for (const op of sorted) {
    if (!KV_WRITE_VERBS.includes(op.verb)) { rejected.push({ op, reason: 'not a write op' }); continue; }
    const vr = verifyKvOp(op);
    if (!vr.ok) { rejected.push({ op, reason: vr.error }); continue; }
    if (!isAuthorised({ author: vr.author, owner: op.owner, verb: op.verb, namespace: op.namespace, iat: op.iat, grants })) {
      rejected.push({ op, reason: 'unauthorised author' }); continue;
    }
    const rid = recordId(op.owner, op.namespace, op.key);
    const expectedPrev = heads[rid] ? heads[rid].opId : '';
    if ((op.prevId || '') !== expectedPrev) { rejected.push({ op, reason: 'prevId mismatch (stale write / broken chain)' }); continue; }
    heads[rid] = op;
  }
  const records = {};
  for (const rid of Object.keys(heads)) {
    const op = heads[rid];
    if (op.verb === 'delete') continue; // tombstone
    records[`${op.namespace}/${op.key}`] = {
      namespace: op.namespace, key: op.key, valueHash: op.valueHash,
      iat: op.iat, author: verifyKvOp(op).author, opId: op.opId, recordId: rid,
    };
  }
  return { records, rejected };
}
