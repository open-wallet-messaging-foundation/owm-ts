// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// Warm introductions (wm-intro, 519): signing, verification, tamper + replay arms.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createIntro, verifyIntro, canonicalIntroPayload } from '../src/intro.js';
import { addressFromPrivateKey } from '../src/eth-sign.js';
import { parseMessage, randomNonce } from '../src/envelope.js';

const KEY_A = '11'.repeat(32); // introducer
const KEY_M = '22'.repeat(32); // mallory
const TS = 1770000000000;
const CAROL = '0x3333333333333333333333333333333333333333';

const baseIntro = () => ({
  privateKey: KEY_A,
  nonce: randomNonce(),
  about: CAROL,
  aboutInboxId: 'inbox-carol',
  aboutName: 'Carol',
  actor: 'human',
  purpose: 'you two should talk OTC',
  ts: TS,
});

test('a signed intro builds a strictly valid envelope and verifies', () => {
  const env = createIntro(baseIntro());
  assert.ok(parseMessage(JSON.stringify(env)).ok);
  const v = verifyIntro(env);
  assert.ok(v.ok);
  assert.equal(v.introducer, addressFromPrivateKey(KEY_A));
});

test('tampering with any vouched field kills the signature', () => {
  const env = createIntro(baseIntro());
  for (const [field, value] of [
    ['about', '0x4444444444444444444444444444444444444444'],
    ['aboutInboxId', 'inbox-eve'],
    ['aboutName', 'Eve'],
    ['actor', 'agent'],
    ['purpose', 'wire me money'],
    ['ts', TS + 1],
  ]) {
    const bad = verifyIntro({ ...env, [field]: value });
    assert.ok(!bad.ok, `tampered ${field} must not verify`);
  }
});

test('an impostor cannot claim someone else\'s intro', () => {
  const env = createIntro(baseIntro());
  // Mallory re-signs the same content but declares A as introducer: the
  // recovered signer will not match the self-declared introducer.
  const mallory = createIntro({ ...baseIntro(), privateKey: KEY_M });
  const forged = { ...mallory, introducer: env.introducer };
  const v = verifyIntro(forged);
  assert.ok(!v.ok);
  assert.match(v.error, /not the introducer/);
});

test('the canonical payload is domain-tagged and nonce-bound (no cross-intro replay)', () => {
  const a = baseIntro();
  const p1 = canonicalIntroPayload({ ...a, introducer: addressFromPrivateKey(KEY_A) });
  assert.match(p1, /^owm-intro-v1\n/);
  const p2 = canonicalIntroPayload({ ...a, introducer: addressFromPrivateKey(KEY_A), nonce: randomNonce() });
  assert.notEqual(p1, p2);
});

test('verifyIntro rejects garbage without throwing', () => {
  assert.ok(!verifyIntro(null).ok);
  const env = createIntro(baseIntro());
  assert.ok(!verifyIntro({ ...env, sig: 'zz'.repeat(65) }).ok);
});
