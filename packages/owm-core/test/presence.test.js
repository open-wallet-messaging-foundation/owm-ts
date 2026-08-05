// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OWM-PRESENCE (WM-4, 547): attestation signing, mutual sets, tamper arms.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  participantsHash, createCallAttestation, verifyCallAttestation, verifyAttestationSet,
} from '../src/presence.js';
import { buildWmCallAttestation, parseMessage, randomNonce } from '../src/envelope.js';
import { addressFromPrivateKey } from '../src/eth-sign.js';

const TS = 1770000000000;
const KEYS = ['55'.repeat(32), '66'.repeat(32), '77'.repeat(32)];
const INBOXES = ['inbox-charlie', 'inbox-alice', 'inbox-bob'];

const callFields = () => ({
  roomId: 'room-1',
  callId: randomNonce(),
  fingerprint: '🐙 🌵 4821',
  participantsHash: participantsHash(INBOXES),
  fromTs: TS,
  toTs: TS + 1800_000,
});

test('participantsHash is order-independent and input-strict', () => {
  assert.equal(participantsHash(INBOXES), participantsHash([...INBOXES].reverse()));
  assert.notEqual(participantsHash(INBOXES), participantsHash(INBOXES.slice(1)));
  assert.throws(() => participantsHash([]));
});

test('an attestation builds a strictly valid envelope and verifies', () => {
  const env = createCallAttestation({ privateKey: KEYS[0], ...callFields() });
  assert.ok(parseMessage(JSON.stringify(env)).ok);
  const v = verifyCallAttestation(env);
  assert.ok(v.ok);
  assert.equal(v.attester, addressFromPrivateKey(KEYS[0]));
});

test('window sanity: toTs < fromTs refused at build', () => {
  assert.throws(() => buildWmCallAttestation({
    ...callFields(), fromTs: TS, toTs: TS - 1,
    attester: addressFromPrivateKey(KEYS[0]), sig: 'ab'.repeat(65),
  }));
});

test('tampering any bound field kills the signature', () => {
  const env = createCallAttestation({ privateKey: KEYS[0], ...callFields() });
  for (const [field, value] of [
    ['roomId', 'room-2'],
    ['fingerprint', '🔥 🚀 0000'],
    ['participantsHash', participantsHash(['inbox-eve'])],
    ['toTs', env.toTs + 1],
  ]) {
    assert.ok(!verifyCallAttestation({ ...env, [field]: value }).ok, `tampered ${field} must not verify`);
  }
});

test('a mutual set verifies; disagreement, duplicates, and forgery are refused', () => {
  const fields = callFields();
  const set = KEYS.map((privateKey) => createCallAttestation({ privateKey, ...fields }));
  const v = verifyAttestationSet(set);
  assert.ok(v.ok);
  assert.equal(v.attesters.length, 3);

  const otherCall = createCallAttestation({ privateKey: KEYS[2], ...callFields() });
  assert.match(verifyAttestationSet([set[0], otherCall]).error, /disagree/);
  assert.match(verifyAttestationSet([set[0], set[0]]).error, /duplicate/);
  const forged = { ...set[1], attester: addressFromPrivateKey(KEYS[0]) };
  assert.ok(!verifyAttestationSet([set[0], forged]).ok);
  assert.match(verifyAttestationSet([]).error ?? 'empty set', /empty/);
});
