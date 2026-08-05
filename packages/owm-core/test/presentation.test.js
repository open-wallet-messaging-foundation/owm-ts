// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  signPresentation, verifyPresentation, canonicalPresentation,
} from '../src/index.js';

const ID = JSON.parse(readFileSync(new URL('../../../api/test-identities.json', import.meta.url))).identities;
const alice = ID.alice; const bob = ID.bob; const carol = ID.carol;

test('WM-14 vector: signPresentation reproduces canonical, id, and signature', () => {
  const V = JSON.parse(readFileSync(new URL('../../../api/vectors/presentation.json', import.meta.url)));
  const p = signPresentation({ privateKey: V.privateKey, ...V.input });
  assert.equal(canonicalPresentation(p), V.expected.canonicalPayload);
  assert.equal(p.presentationId, V.expected.presentationId);
  assert.equal(p.sig, V.expected.sig);
  assert.equal(verifyPresentation(p, { now: V.input.now + 1, expectedChallenge: V.input.challenge }).holder, V.expected.holder);
});

test('round-trips with the matching challenge and audience', () => {
  const p = signPresentation({ privateKey: alice.privateKey, objectKind: 'owm-attestation', objectHash: 'abc123', audience: bob.address, challenge: 'n1', now: 1000 });
  assert.equal(verifyPresentation(p, { now: 1000, expectedChallenge: 'n1', expectedAudience: bob.address }).holder, alice.address);
});

test('anti-replay: a stale/replayed challenge is rejected', () => {
  const p = signPresentation({ privateKey: alice.privateKey, objectKind: 'owm-attestation', objectHash: 'abc123', audience: bob.address, challenge: 'n1', now: 1000 });
  assert.equal(verifyPresentation(p, { now: 1000, expectedChallenge: 'n2' }).ok, false);
});

test('wrong audience is rejected', () => {
  const p = signPresentation({ privateKey: alice.privateKey, objectKind: 'owm-attestation', objectHash: 'abc123', audience: bob.address, challenge: 'n1', now: 1000 });
  assert.equal(verifyPresentation(p, { now: 1000, expectedChallenge: 'n1', expectedAudience: carol.address }).ok, false);
});

test('expired presentation is refused', () => {
  const p = signPresentation({ privateKey: alice.privateKey, objectKind: 'owm-attestation', objectHash: 'abc123', audience: bob.address, challenge: 'n1', ttlS: 60, now: 1000 });
  assert.equal(verifyPresentation(p, { now: 1200, expectedChallenge: 'n1' }).ok, false);
});

test('non-tamper: mutating the presented objectHash breaks verification', () => {
  const p = signPresentation({ privateKey: alice.privateKey, objectKind: 'owm-attestation', objectHash: 'abc123', audience: bob.address, challenge: 'n1', now: 1000 });
  assert.equal(verifyPresentation({ ...p, objectHash: 'deadbeef' }, { now: 1000, expectedChallenge: 'n1' }).ok, false);
});
