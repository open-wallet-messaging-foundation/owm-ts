// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildContactCard, buildScxAbort } from '@open-wallet-messaging/core';
import { OwmAuthServer } from '../src/server.js';
import { OwmAuthenticator } from '../src/authenticator.js';

const KEY = `0x${'11'.repeat(32)}`;
const OTHER_KEY = `0x${'22'.repeat(32)}`;
const START = 1770000000000;

function makeClock(start = START) {
  const c = { t: start };
  c.fn = () => c.t;
  return c;
}

async function enrolledServer(opts = {}) {
  const clock = makeClock();
  const server = new OwmAuthServer({ rp: 'rp.example', clock: clock.fn, ...opts });
  const wallet = new OwmAuthenticator({ privateKey: KEY });
  const { envelope, matchCode } = await server.createEnrollmentChallenge({ userId: 'u1' });
  const proof = wallet.handleAuthChallenge(envelope, { matchCode, now: clock.t });
  const res = await server.verifyEnrollmentProof(proof);
  assert.ok(res.ok);
  return { server, wallet, clock };
}

test('enrollment via proof-of-possession pins the signing address', async () => {
  const clock = makeClock();
  const server = new OwmAuthServer({ rp: 'rp.example', clock: clock.fn });
  const wallet = new OwmAuthenticator({ privateKey: KEY });
  const { envelope, matchCode, challengeId } = await server.createEnrollmentChallenge({ userId: 'u1' });
  assert.equal(challengeId, envelope.challenge);
  assert.match(matchCode, /^[0-9]{2}$/);
  const proof = wallet.handleAuthChallenge(envelope, { matchCode, now: clock.t });
  const res = await server.verifyEnrollmentProof(proof);
  assert.ok(res.ok);
  assert.equal(res.userId, 'u1');
  assert.equal(res.address, wallet.addressFor('rp.example'));
  assert.equal((await server.getEnrollment('u1')).address, res.address);
});

test('enrollment proof with the wrong match code fails and pins nothing', async () => {
  const clock = makeClock();
  const server = new OwmAuthServer({ rp: 'rp.example', clock: clock.fn });
  const wallet = new OwmAuthenticator({ privateKey: KEY });
  const { envelope, matchCode } = await server.createEnrollmentChallenge({ userId: 'u1' });
  const wrong = matchCode === '00' ? '01' : '00';
  const proof = wallet.handleAuthChallenge(envelope, { matchCode: wrong, now: clock.t });
  const res = await server.verifyEnrollmentProof(proof);
  assert.equal(res.ok, false);
  assert.equal(res.reason, 'match-mismatch');
  assert.equal(await server.getEnrollment('u1'), null);
});

test('SCX-card enrollment reuses verifyContactCard and is transcript-bound', async () => {
  const server = new OwmAuthServer({ rp: 'rp.example' });
  const th = 'aa'.repeat(32);
  const card = buildContactCard({ privateKey: KEY, inboxId: 'inbox-1', ts: START, transcriptHash: th });
  const ok = await server.acceptScxCard({ userId: 'u1', card, transcriptHash: th });
  assert.ok(ok.ok);
  assert.equal(ok.address, card.address.toLowerCase());
  // same card, different ceremony transcript → refused
  const bad = await server.acceptScxCard({ userId: 'u2', card, transcriptHash: 'bb'.repeat(32) });
  assert.equal(bad.reason, 'bad-card-signature');
  assert.equal(await server.getEnrollment('u2'), null);
});

test('happy path: challenge → wallet signs with typed match code → verified once', async () => {
  const { server, wallet, clock } = await enrolledServer();
  const { envelope, matchCode, challengeId } = await server.createChallenge({ userId: 'u1', action: 'release the wire' });
  assert.equal(envelope.rp, 'rp.example');
  assert.equal(envelope.action, 'release the wire');
  assert.ok(!('match' in envelope), 'the match code must NOT ride the challenge');
  const resp = wallet.handleAuthChallenge(envelope, { matchCode, now: clock.t });
  const res = await server.verifyResponse(resp);
  assert.ok(res.ok);
  assert.equal(res.userId, 'u1');
  assert.equal(res.action, 'release the wire');
  // replay: the nonce is burned
  const replay = await server.verifyResponse(resp);
  assert.equal(replay.reason, 'unknown-challenge');
  assert.equal(challengeId, envelope.challenge);
});

test('expired challenge is refused (and burned)', async () => {
  const { server, wallet, clock } = await enrolledServer();
  const { envelope, matchCode } = await server.createChallenge({ userId: 'u1', action: 'log in' });
  const resp = wallet.handleAuthChallenge(envelope, { matchCode, now: clock.t });
  clock.t += 121000; // past the 120 s ceiling
  const res = await server.verifyResponse(resp);
  assert.equal(res.reason, 'expired');
  assert.equal((await server.verifyResponse(resp)).reason, 'unknown-challenge');
});

test('wrong match code fails; matchCode option overrides the stored code', async () => {
  const { server, wallet, clock } = await enrolledServer();
  const a = await server.createChallenge({ userId: 'u1', action: 'log in' });
  const wrong = a.matchCode === '77' ? '78' : '77';
  const resp = wallet.handleAuthChallenge(a.envelope, { matchCode: wrong, now: clock.t });
  assert.equal((await server.verifyResponse(resp)).reason, 'match-mismatch');
  // caller-held match code (initiating screen kept it)
  const b = await server.createChallenge({ userId: 'u1', action: 'log in' });
  const resp2 = wallet.handleAuthChallenge(b.envelope, { matchCode: b.matchCode, now: clock.t });
  assert.ok((await server.verifyResponse(resp2, { matchCode: b.matchCode })).ok);
});

test('a response signed by a non-enrolled key is wrong-address', async () => {
  const { server, clock } = await enrolledServer();
  const rogue = new OwmAuthenticator({ privateKey: OTHER_KEY });
  const { envelope, matchCode } = await server.createChallenge({ userId: 'u1', action: 'log in' });
  const resp = rogue.handleAuthChallenge(envelope, { matchCode, now: clock.t });
  assert.equal((await server.verifyResponse(resp)).reason, 'wrong-address');
});

test('tampered signature and garbage envelopes are rejected', async () => {
  const { server, wallet, clock } = await enrolledServer();
  const { envelope, matchCode } = await server.createChallenge({ userId: 'u1', action: 'log in' });
  const resp = wallet.handleAuthChallenge(envelope, { matchCode, now: clock.t });
  const flipped = resp.sig.startsWith('00') ? `11${resp.sig.slice(2)}` : `00${resp.sig.slice(2)}`;
  assert.equal((await server.verifyResponse({ ...resp, sig: flipped })).reason, 'bad-signature');
  assert.equal((await server.verifyResponse({ hello: 'world' })).reason, 'bad-envelope');
  assert.equal((await server.verifyResponse({ ...resp, extra: 1 })).reason, 'bad-envelope');
});

test('wallet decline (scx-abort) burns the challenge and counts as a rejection', async () => {
  const { server, wallet, clock } = await enrolledServer();
  const { envelope, challengeId } = await server.createChallenge({ userId: 'u1', action: 'log in' });
  const abort = wallet.handleAuthChallenge(envelope, { approve: false, now: clock.t });
  assert.equal(abort._kind, 'scx-abort');
  assert.equal(abort.reason, 'declined');
  const res = await server.verifyResponse(abort, { challengeId });
  assert.equal(res.reason, 'declined');
  assert.equal(res.userId, 'u1');
  // burned: a second decline for the same challenge is unknown
  assert.equal((await server.verifyResponse(abort, { challengeId })).reason, 'unknown-challenge');
  // an abort without transport context cannot be attributed
  assert.equal((await server.verifyResponse(buildScxAbort({ reason: 'declined' }))).reason, 'unknown-challenge');
});

test('lockout after maxFailures fires the security alert once and blocks new challenges', async () => {
  const alerts = [];
  const { server, wallet, clock } = await enrolledServer({
    maxFailures: 3,
    onSecurityAlert: (a) => alerts.push(a),
  });
  for (let i = 0; i < 3; i++) {
    const { envelope, matchCode } = await server.createChallenge({ userId: 'u1', action: 'log in' });
    const wrong = matchCode === '00' ? '01' : '00';
    const resp = wallet.handleAuthChallenge(envelope, { matchCode: wrong, now: clock.t });
    const res = await server.verifyResponse(resp);
    assert.equal(res.reason, 'match-mismatch');
    assert.equal(res.locked, i === 2);
  }
  assert.equal(alerts.length, 1);
  assert.deepEqual({ userId: alerts[0].userId, reason: alerts[0].reason, failures: alerts[0].failures }, {
    userId: 'u1', reason: 'lockout', failures: 3,
  });
  assert.ok(await server.isLocked('u1'));
  await assert.rejects(() => server.createChallenge({ userId: 'u1', action: 'log in' }), /locked/);
  // unlock restores service
  await server.unlockUser('u1');
  assert.ok(!(await server.isLocked('u1')));
  const { envelope, matchCode } = await server.createChallenge({ userId: 'u1', action: 'log in' });
  const resp = wallet.handleAuthChallenge(envelope, { matchCode, now: clock.t });
  assert.ok((await server.verifyResponse(resp)).ok);
});

test('a success clears the failure counter', async () => {
  const { server, wallet, clock } = await enrolledServer({ maxFailures: 2 });
  const a = await server.createChallenge({ userId: 'u1', action: 'log in' });
  const wrongCode = a.matchCode === '00' ? '01' : '00';
  await server.verifyResponse(wallet.handleAuthChallenge(a.envelope, { matchCode: wrongCode, now: clock.t }));
  const b = await server.createChallenge({ userId: 'u1', action: 'log in' });
  assert.ok((await server.verifyResponse(wallet.handleAuthChallenge(b.envelope, { matchCode: b.matchCode, now: clock.t }))).ok);
  // counter reset: one more failure does not lock (maxFailures = 2)
  const c = await server.createChallenge({ userId: 'u1', action: 'log in' });
  const wrongC = c.matchCode === '00' ? '01' : '00';
  const res = await server.verifyResponse(wallet.handleAuthChallenge(c.envelope, { matchCode: wrongC, now: clock.t }));
  assert.equal(res.locked, false);
});

test('createChallenge requires enrollment; stores are pluggable via get/put/delete', async () => {
  const puts = [];
  class SpyStore {
    #m = new Map();
    async get(k) { return this.#m.get(k) ?? null; }
    async put(k, v) { puts.push(k); this.#m.set(k, v); }
    async delete(k) { this.#m.delete(k); }
  }
  const server = new OwmAuthServer({ rp: 'rp.example', challengeStore: new SpyStore(), enrollmentStore: new SpyStore() });
  await assert.rejects(() => server.createChallenge({ userId: 'nobody', action: 'log in' }), /not enrolled/);
  await server.createEnrollmentChallenge({ userId: 'u9' });
  assert.equal(puts.length, 1); // challenge landed in the injected store
});
