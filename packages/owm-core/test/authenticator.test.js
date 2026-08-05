// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateChallenge, sign, verify, enroll, challengeMessage,
  createSession, sessionValid, signSession, verifySession,
  addressFromPrivateKey,
} from '../src/index.js';

const KEY = 'a'.repeat(64);
const ADDR = addressFromPrivateKey(KEY);

test('happy path: challenge → sign → verify recovers the signer', () => {
  const c = generateChallenge({ rp: 'app.example' });
  const sig = sign(c, KEY);
  const r = verify({ challenge: c, signature: sig });
  assert.equal(r.ok, true);
  assert.equal(r.address.toLowerCase(), ADDR.toLowerCase());
});

test('expectedAddress binds the check to the enrolled wallet', () => {
  const c = generateChallenge({ rp: 'app.example' });
  const sig = sign(c, KEY);
  assert.equal(verify({ challenge: c, signature: sig, expectedAddress: ADDR }).ok, true);
  const other = addressFromPrivateKey('b'.repeat(64));
  const r = verify({ challenge: c, signature: sig, expectedAddress: other });
  assert.equal(r.ok, false);
  assert.match(r.error, /not from the enrolled wallet/);
});

test('wrong signer is rejected', () => {
  const c = generateChallenge({ rp: 'app.example' });
  const sig = sign(c, 'b'.repeat(64));
  const r = verify({ challenge: c, signature: sig, expectedAddress: ADDR });
  assert.equal(r.ok, false);
});

test('expired challenge is rejected', () => {
  const c = generateChallenge({ rp: 'app.example', ttlS: 120, now: 1000 });
  const sig = sign(c, KEY);
  assert.equal(verify({ challenge: c, signature: sig, now: 1000 }).ok, true);
  const r = verify({ challenge: c, signature: sig, now: 1000 + 121 });
  assert.equal(r.ok, false);
  assert.match(r.error, /expired/);
});

test('tampered message does not verify (WYSIWYS binding)', () => {
  const c = generateChallenge({ rp: 'app.example' });
  const sig = sign(c, KEY);
  const forged = { ...c, message: challengeMessage({ ...c, action: 'Wire $1,000,000' }) };
  const r = verify({ challenge: forged, signature: sig, expectedAddress: ADDR });
  assert.equal(r.ok, false);
});

test('garbage signature is rejected, not thrown', () => {
  const c = generateChallenge({ rp: 'app.example' });
  const r = verify({ challenge: c, signature: '0xdeadbeef' });
  assert.equal(r.ok, false);
});

test('enroll stores a public address and NO secret', () => {
  const e = enroll({ address: ADDR });
  assert.equal(e.secret, null);
  assert.equal(e.address.toLowerCase(), ADDR.toLowerCase());
});

test('sessions: createSession / sessionValid honour the timeout', () => {
  const s = createSession({ address: ADDR, ttlS: 3600, now: 1000 });
  assert.equal(sessionValid(s, 1000 + 10), true);
  assert.equal(sessionValid(s, 1000 + 3601), false);
});

test('signed session token round-trips and expires', () => {
  const t = signSession({ address: ADDR, ttlS: 3600, key: 'server-secret', now: 1000 });
  const ok = verifySession(t, 'server-secret', 1000 + 10);
  assert.equal(ok.ok, true);
  assert.equal(ok.address.toLowerCase(), ADDR.toLowerCase());
  assert.equal(verifySession(t, 'server-secret', 1000 + 3601).ok, false); // expired
  assert.equal(verifySession(t, 'WRONG-secret', 1000 + 10).ok, false); // bad key
  assert.equal(verifySession(`${t}x`, 'server-secret', 1000 + 10).ok, false); // tampered
});
