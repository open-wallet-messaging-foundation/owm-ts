// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// 2FA / step-up demo — the whole OWM-AUTH ceremony in one process, no
// transport, no network. Server and "wallet" are both here so you can
// watch every envelope. Run: node two-factor.mjs
//
// What you'll see: enrollment → a happy-path login → a WYSIWYS step-up
// approval → a wrong match code (terminal, challenge burned) → a lockout
// with the security alert firing.

import assert from 'node:assert/strict';
import { OwmAuthServer, TwoFactor, OwmAuthenticator } from '../../packages/owm-auth/src/index.js';

const step = (title) => console.log(`\n=== ${title} ===`);
const wrongCode = (code) => (code === '00' ? '01' : '00');

// --- cast of characters ------------------------------------------------------

const alerts = [];
const server = new OwmAuthServer({
  rp: 'demo.example.org',
  maxFailures: 3,
  onSecurityAlert: (a) => { alerts.push(a); },
});
const twoFactor = new TwoFactor({ server });

// The user's wallet — normally an app on their phone. Seed mode: one
// derived sub-key per relying party, so this site sees its own address.
const wallet = new OwmAuthenticator({ seed: 'decafbad'.repeat(4) });
console.log('wallet address for demo.example.org :', wallet.addressFor('demo.example.org'));
console.log('wallet address for other.site       :', wallet.addressFor('other.site'), '(unlinkable)');

// --- 1. enrollment -----------------------------------------------------------

step('Enrollment (in-session proof-of-possession)');
const enroll = await server.createEnrollmentChallenge({ userId: 'ada' });
console.log('[site screen] shows match code:', enroll.matchCode);
console.log('[wallet]      renders:', JSON.stringify({ rp: enroll.envelope.rp, action: enroll.envelope.action }));
const proof = wallet.handleAuthChallenge(enroll.envelope, { matchCode: enroll.matchCode });
const pinned = await server.verifyEnrollmentProof(proof);
assert.ok(pinned.ok);
console.log('pinned address for user "ada":', pinned.address);

// --- 2. happy-path login ------------------------------------------------------

step('Login: challenge → user types the match code → approved');
const login = await twoFactor.request('ada', 'log in');
console.log('[site screen] shows match code:', login.matchCode);
console.log('[envelope]    contains NO match code:', !('match' in login.envelope));
const approvalPending = twoFactor.awaitApproval(login.challengeId, { timeoutMs: 5000 });
// "transport": the wallet receives the envelope; the user reads the code
// off the site screen and types it into the wallet:
const response = wallet.handleAuthChallenge(login.envelope, { matchCode: login.matchCode });
await twoFactor.submit(response);
const approved = await approvalPending;
assert.equal(approved.userId, 'ada');
console.log('login approved:', { userId: approved.userId, address: approved.address });

// replay: the nonce burned on verification
const replay = await server.verifyResponse(response);
assert.equal(replay.reason, 'unknown-challenge');
console.log('replaying the same response:', replay.reason, '(single-use nonce, burned)');

// --- 3. step-up approval (WYSIWYS) ---------------------------------------------

step('Step-up: the action text IS what gets signed');
const wire = await twoFactor.request('ada', 'Release wire #4711: $25,000 to acct …991');
console.log('[wallet] renders verbatim:', JSON.stringify(wire.envelope.action));
const wirePending = twoFactor.awaitApproval(wire.challengeId, { timeoutMs: 5000 });
await twoFactor.submit(wallet.handleAuthChallenge(wire.envelope, { matchCode: wire.matchCode }));
console.log('wire release approved:', (await wirePending).ok);

// --- 4. a wrong match code is terminal ------------------------------------------

step('Wrong match code: one attempt, then the challenge is gone');
const bad = await twoFactor.request('ada', 'log in');
const badPending = twoFactor.awaitApproval(bad.challengeId, { timeoutMs: 5000 });
const badResponse = wallet.handleAuthChallenge(bad.envelope, { matchCode: wrongCode(bad.matchCode) });
const badResult = await twoFactor.submit(badResponse);
console.log('verification result:', badResult.reason);
await badPending.then(
  () => { throw new Error('should have rejected'); },
  (e) => console.log('awaitApproval rejected with reason:', e.reason),
);
// the failed attempt burned the challenge — no retry against the same nonce
const retry = await server.verifyResponse(wallet.handleAuthChallenge(bad.envelope, { matchCode: bad.matchCode }));
assert.equal(retry.reason, 'unknown-challenge');
console.log('retry with the RIGHT code after a failure:', retry.reason, '(retry-after-failure is the attack)');

// --- 5. lockout ---------------------------------------------------------------

step('Lockout: maxFailures = 3, declines and failures both count');
// failure #1 was the wrong match code above; add a decline (#2) …
const d = await twoFactor.request('ada', 'log in');
const decline = wallet.handleAuthChallenge(d.envelope, { approve: false });
console.log('wallet declined with:', decline._kind, '/', decline.reason);
await twoFactor.submit(decline, { challengeId: d.challengeId }); // aborts carry no id — pass it
// … and one more wrong code (#3):
const f = await twoFactor.request('ada', 'log in');
const locked = await twoFactor.submit(wallet.handleAuthChallenge(f.envelope, { matchCode: wrongCode(f.matchCode) }));
assert.equal(locked.locked, true);
console.log('third strike:', locked.reason, '→ locked:', locked.locked);
console.log('security alert fired once:', alerts.length === 1, JSON.stringify(alerts[0]));
await twoFactor.request('ada', 'log in').then(
  () => { throw new Error('should have thrown'); },
  (e) => console.log('new challenge for a locked user:', e.message),
);

step('Support desk unlocks; service restored');
await server.unlockUser('ada');
const again = await twoFactor.request('ada', 'log in');
const againPending = twoFactor.awaitApproval(again.challengeId, { timeoutMs: 5000 });
await twoFactor.submit(wallet.handleAuthChallenge(again.envelope, { matchCode: again.matchCode }));
assert.ok((await againPending).ok);
console.log('login works again. done.');
