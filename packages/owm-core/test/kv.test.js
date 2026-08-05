// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  signKvOp, verifyKvOp, canonicalKvOp, computeOpId, valueHash,
  signKvGrant, verifyKvGrant, canonicalKvGrant, isAuthorised, foldKv,
} from '../src/index.js';

const ID = JSON.parse(readFileSync(new URL('../../../api/test-identities.json', import.meta.url))).identities;
const alice = ID.alice; const bob = ID.bob; const accountant = ID.accountant;
const vh = (s) => valueHash(s);

// A chain of owner SETs on one record; each prevId links to the prior opId.
function chain(priv, owner, namespace, key, values, startIat = 1000) {
  const ops = []; let prevId = '';
  values.forEach((val, i) => {
    const op = signKvOp({ privateKey: priv, verb: 'set', owner, namespace, key, valueHash: vh(val), prevId, iat: startIat + i });
    ops.push(op); prevId = op.opId;
  });
  return ops;
}

test('WM-10 vector: signKvOp + signKvGrant reproduce canonical, id, and signature', () => {
  const V = JSON.parse(readFileSync(new URL('../../../api/vectors/kv.json', import.meta.url)));
  const op = signKvOp({ privateKey: V.set.privateKey, verb: 'set', ...V.set.input });
  assert.equal(canonicalKvOp(op), V.set.expected.canonicalPayload);
  assert.equal(op.opId, V.set.expected.opId);
  assert.equal(op.sig, V.set.expected.sig);
  assert.equal(verifyKvOp(op).author, V.set.expected.author);

  const g = signKvGrant({ privateKey: V.grant.privateKey, grantee: V.grant.input.grantee, namespace: V.grant.input.namespace, verbs: V.grant.input.verbs, ttlS: V.grant.input.ttlS, now: V.grant.input.iat });
  assert.equal(canonicalKvGrant(g), V.grant.expected.canonicalPayload);
  assert.equal(g.grantId, V.grant.expected.grantId);
  assert.equal(g.sig, V.grant.expected.sig);
  assert.deepEqual(g.verbs, V.grant.expected.verbs);
});

test('signKvOp → verifyKvOp round-trips and recovers the author', () => {
  const op = signKvOp({ privateKey: alice.privateKey, verb: 'set', namespace: 'profile', key: 'firstName', valueHash: vh('saxon'), prevId: '', iat: 1000 });
  const r = verifyKvOp(op);
  assert.equal(r.ok, true);
  assert.equal(r.author, alice.address);
  assert.equal(r.opId, computeOpId(canonicalKvOp(op)));
});

test('non-tamper: mutating the value hash breaks opId/signature verification', () => {
  const op = signKvOp({ privateKey: alice.privateKey, verb: 'set', namespace: 'profile', key: 'firstName', valueHash: vh('saxon'), prevId: '', iat: 1000 });
  const tampered = { ...op, valueHash: vh('mallory') };
  assert.equal(verifyKvOp(tampered).ok, false);            // opId no longer matches the payload
  const { records, rejected } = foldKv([tampered]);        // and the fold refuses it
  assert.equal(Object.keys(records).length, 0);
  assert.equal(rejected.length, 1);
});

test('fold: latest write in the chain wins', () => {
  const ops = chain(alice.privateKey, alice.address, 'profile', 'firstName', ['sax', 'saxon', 'saxon-n']);
  const { records } = foldKv(ops);
  assert.equal(records['profile/firstName'].opId, ops[2].opId);
  assert.equal(records['profile/firstName'].author, alice.address);
});

test('CAS: a fork (two writes off the same head) rejects the stale one', () => {
  const [a] = chain(alice.privateKey, alice.address, 'profile', 'x', ['one']);
  const fork = signKvOp({ privateKey: alice.privateKey, verb: 'set', owner: alice.address, namespace: 'profile', key: 'x', valueHash: vh('two'), prevId: '', iat: 1001 });
  const { records, rejected } = foldKv([a, fork]);
  assert.equal(records['profile/x'].opId, a.opId);
  assert.ok(rejected.some((r) => r.reason.startsWith('prevId mismatch')));
});

test('DELETE is a tombstone: the record drops from current state', () => {
  const [set] = chain(alice.privateKey, alice.address, 'profile', 'gone', ['here']);
  const del = signKvOp({ privateKey: alice.privateKey, verb: 'delete', owner: alice.address, namespace: 'profile', key: 'gone', prevId: set.opId, iat: 1001 });
  const { records } = foldKv([set, del]);
  assert.equal(records['profile/gone'], undefined);
});

test('per-verb caps: a delegate SET is rejected without a matching grant, accepted with one', () => {
  // Bob writes into Alice's `shared` namespace.
  const bobSet = signKvOp({ privateKey: bob.privateKey, verb: 'set', owner: alice.address, namespace: 'shared', key: 'note', valueHash: vh('hi'), prevId: '', iat: 1000 });
  assert.equal(verifyKvOp(bobSet).author, bob.address);

  // No grant → unauthorised, not folded.
  const noGrant = foldKv([bobSet]);
  assert.equal(noGrant.records['shared/note'], undefined);
  assert.ok(noGrant.rejected.some((r) => r.reason === 'unauthorised author'));

  // A read-only grant does NOT authorise a write.
  const readGrant = signKvGrant({ privateKey: alice.privateKey, grantee: bob.address, namespace: 'shared', verbs: ['get', 'list'], now: 900 });
  assert.equal(foldKv([bobSet], { grants: [readGrant] }).records['shared/note'], undefined);

  // A `set` grant does.
  const writeGrant = signKvGrant({ privateKey: alice.privateKey, grantee: bob.address, namespace: 'shared', verbs: ['set'], now: 900 });
  assert.equal(foldKv([bobSet], { grants: [writeGrant] }).records['shared/note'].author, bob.address);
});

test('per-verb caps: isAuthorised honours owner, verb, namespace, and grant expiry', () => {
  const g = signKvGrant({ privateKey: alice.privateKey, grantee: accountant.address, namespace: 'financial', verbs: ['get', 'list'], ttlS: 100, now: 1000 });
  assert.equal(verifyKvGrant(g, { now: 1050 }).ok, true);
  // owner may do anything on their own store
  assert.equal(isAuthorised({ author: alice.address, owner: alice.address, verb: 'delete', namespace: 'anything', iat: 1, grants: [] }), true);
  // grantee: allowed verb in-window
  assert.equal(isAuthorised({ author: accountant.address, owner: alice.address, verb: 'get', namespace: 'financial', iat: 1050, grants: [g] }), true);
  // wrong verb
  assert.equal(isAuthorised({ author: accountant.address, owner: alice.address, verb: 'set', namespace: 'financial', iat: 1050, grants: [g] }), false);
  // wrong namespace
  assert.equal(isAuthorised({ author: accountant.address, owner: alice.address, verb: 'get', namespace: 'personal', iat: 1050, grants: [g] }), false);
  // after expiry
  assert.equal(isAuthorised({ author: accountant.address, owner: alice.address, verb: 'get', namespace: 'financial', iat: 2000, grants: [g] }), false);
});

test('grant signature must come from the owner; a forged owner is rejected', () => {
  const g = signKvGrant({ privateKey: bob.privateKey, grantee: accountant.address, namespace: 'financial', verbs: ['get'], now: 1000 });
  const forged = { ...g, owner: alice.address }; // claim Alice's store without her signature
  assert.equal(verifyKvGrant(forged, { now: 1001 }).ok, false);
});

test('invalid verb is rejected at signing', () => {
  assert.throws(() => signKvOp({ privateKey: alice.privateKey, verb: 'nope', namespace: 'x', key: 'y', iat: 1 }), /verb must be one of/);
});
