// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import test from 'node:test';
import assert from 'node:assert/strict';
import { OwmAuthServer } from '../src/server.js';
import { OwmAuthenticator } from '../src/authenticator.js';
import { TwoFactor } from '../src/two-factor.js';

const KEY = `0x${'11'.repeat(32)}`;
const START = 1770000000000;

async function setup(opts = {}) {
  const clock = { t: START };
  const server = new OwmAuthServer({ rp: 'rp.example', clock: () => clock.t, ...opts });
  const wallet = new OwmAuthenticator({ privateKey: KEY });
  const { envelope, matchCode } = await server.createEnrollmentChallenge({ userId: 'u1' });
  await server.verifyEnrollmentProof(wallet.handleAuthChallenge(envelope, { matchCode, now: clock.t }));
  const twoFactor = new TwoFactor({ server });
  return { twoFactor, server, wallet, clock };
}

test('the totp.verify seam: request → transport → submit → awaitApproval resolves', async () => {
  const { twoFactor, wallet, clock } = await setup();
  const { challengeId, matchCode, envelope } = await twoFactor.request('u1');
  assert.match(matchCode, /^[0-9]{2}$/);
  const pending = twoFactor.awaitApproval(challengeId, { timeoutMs: 5000 });
  // "transport": wallet receives the envelope, user types the match code
  const resp = wallet.handleAuthChallenge(envelope, { matchCode, now: clock.t });
  const submitRes = await twoFactor.submit(resp);
  assert.ok(submitRes.ok);
  const approved = await pending;
  assert.deepEqual({ ok: approved.ok, userId: approved.userId }, { ok: true, userId: 'u1' });
});

test('timeout rejects with reason timeout', async () => {
  const { twoFactor } = await setup();
  const { challengeId } = await twoFactor.request('u1', 'log in');
  await assert.rejects(
    twoFactor.awaitApproval(challengeId, { timeoutMs: 25 }),
    (e) => e.reason === 'timeout',
  );
  // after timeout the ceremony is gone
  await assert.rejects(
    twoFactor.awaitApproval(challengeId, { timeoutMs: 25 }),
    (e) => e.reason === 'unknown-challenge',
  );
});

test('a wallet decline rejects the waiting login with reason declined', async () => {
  const { twoFactor, wallet, clock } = await setup();
  const { challengeId, envelope } = await twoFactor.request('u1');
  const pending = twoFactor.awaitApproval(challengeId, { timeoutMs: 5000 });
  const abort = wallet.handleAuthChallenge(envelope, { approve: false, now: clock.t });
  await twoFactor.submit(abort, { challengeId });
  await assert.rejects(pending, (e) => e.reason === 'declined');
});

test('a failed verification (wrong match) is terminal for the ceremony', async () => {
  const { twoFactor, wallet, clock } = await setup();
  const { challengeId, matchCode, envelope } = await twoFactor.request('u1');
  const pending = twoFactor.awaitApproval(challengeId, { timeoutMs: 5000 });
  const wrong = matchCode === '00' ? '01' : '00';
  const resp = wallet.handleAuthChallenge(envelope, { matchCode: wrong, now: clock.t });
  const res = await twoFactor.submit(resp);
  assert.equal(res.reason, 'match-mismatch');
  await assert.rejects(pending, (e) => e.reason === 'match-mismatch');
});

test('lockout surfaces through the seam: reject carries locked, request() then throws', async () => {
  const alerts = [];
  const { twoFactor, wallet, clock } = await setup({ maxFailures: 2, onSecurityAlert: (a) => alerts.push(a) });
  for (let i = 0; i < 2; i++) {
    const { challengeId, matchCode, envelope } = await twoFactor.request('u1');
    const pending = twoFactor.awaitApproval(challengeId, { timeoutMs: 5000 });
    const wrong = matchCode === '00' ? '01' : '00';
    await twoFactor.submit(wallet.handleAuthChallenge(envelope, { matchCode: wrong, now: clock.t }));
    await assert.rejects(pending, (e) => e.reason === 'match-mismatch' && e.locked === (i === 1));
  }
  assert.equal(alerts.length, 1);
  await assert.rejects(() => twoFactor.request('u1'), /locked/);
});

test('submit settles a ceremony even when nobody is awaiting yet (no unhandled rejection)', async () => {
  const { twoFactor, wallet, clock } = await setup();
  const { challengeId, matchCode, envelope } = await twoFactor.request('u1');
  const wrong = matchCode === '00' ? '01' : '00';
  await twoFactor.submit(wallet.handleAuthChallenge(envelope, { matchCode: wrong, now: clock.t }));
  // late awaiter learns it is gone
  await assert.rejects(
    twoFactor.awaitApproval(challengeId, { timeoutMs: 25 }),
    (e) => e.reason === 'unknown-challenge',
  );
});
