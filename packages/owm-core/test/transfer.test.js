// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  signTransfer, verifyTransfer, canonicalTransfer, foldTransfers,
} from '../src/index.js';

const ID = JSON.parse(readFileSync(new URL('../../../api/test-identities.json', import.meta.url))).identities;
const alice = ID.alice; const bob = ID.bob; const carol = ID.carol;

test('WM-15 vector: signTransfer reproduces canonical/id/sig and folds to bob', () => {
  const V = JSON.parse(readFileSync(new URL('../../../api/vectors/transfer.json', import.meta.url)));
  const t = signTransfer({ privateKey: V.privateKey, ...V.input });
  assert.equal(canonicalTransfer(t), V.expected.canonicalPayload);
  assert.equal(t.transferId, V.expected.transferId);
  assert.equal(t.sig, V.expected.sig);
  assert.equal(foldTransfers([t], { objectId: V.input.objectId, originalHolder: V.expected.from }).holder, V.expected.foldedHolder);
});

test('fold: an alice→bob→carol chain resolves to carol', () => {
  const t1 = signTransfer({ privateKey: alice.privateKey, objectId: 'o1', objectKind: 'owm-binding', to: bob.address, prevId: '', now: 1000 });
  const t2 = signTransfer({ privateKey: bob.privateKey, objectId: 'o1', objectKind: 'owm-binding', to: carol.address, prevId: t1.transferId, now: 1001 });
  const f = foldTransfers([t2, t1], { objectId: 'o1', originalHolder: alice.address }); // out of order on purpose
  assert.equal(f.holder, carol.address);
  assert.deepEqual(f.chain, [t1.transferId, t2.transferId]);
});

test('CAS: a stale transfer (wrong prevId) from the current holder is rejected', () => {
  const t1 = signTransfer({ privateKey: alice.privateKey, objectId: 'o2', objectKind: 'owm-binding', to: bob.address, prevId: '', now: 1000 });
  // bob IS the current holder, but chains off '' (stale) instead of t1.transferId
  const stale = signTransfer({ privateKey: bob.privateKey, objectId: 'o2', objectKind: 'owm-binding', to: carol.address, prevId: '', now: 1001 });
  const f = foldTransfers([t1, stale], { objectId: 'o2', originalHolder: alice.address });
  assert.equal(f.holder, bob.address);
  assert.ok(f.rejected.some((r) => r.reason.startsWith('prevId mismatch')));
});

test('a transfer not signed by the current holder is rejected', () => {
  const bogus = signTransfer({ privateKey: bob.privateKey, objectId: 'o3', objectKind: 'owm-binding', to: carol.address, prevId: '', now: 1000 });
  const f = foldTransfers([bogus], { objectId: 'o3', originalHolder: alice.address });
  assert.equal(f.holder, alice.address);
  assert.ok(f.rejected.some((r) => r.reason === 'not signed by the current holder'));
});

test('signTransfer → verifyTransfer recovers the sender; non-tamper on `to`', () => {
  const t = signTransfer({ privateKey: alice.privateKey, objectId: 'o4', objectKind: 'owm-binding', to: bob.address, now: 1000 });
  assert.equal(verifyTransfer(t, { now: 1000 }).from, alice.address);
  assert.equal(verifyTransfer({ ...t, to: carol.address.toLowerCase() }, { now: 1000 }).ok, false);
});
