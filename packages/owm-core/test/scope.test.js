// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OWM-SCOPE: taxonomy, payload-bound scope recovery, least-privilege
// subsumption, and the declared-vs-bound consistency check.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SCOPES, isKnownScope, parseScope, scopeForCanonical,
  scopeCovers, scopeSatisfies, expandScope, checkDeclaredScope,
} from '../src/scope.js';
import { canonicalAuthPayload, canonicalGrantPayload } from '../src/auth.js';
import { canonicalBroadcastRequest } from '../src/pay.js';
import { canonicalCallAttestation } from '../src/presence.js';

test('the taxonomy is frozen and every entry is owm-namespaced', () => {
  assert.ok(Object.isFrozen(SCOPES));
  assert.ok(SCOPES.every((s) => s.startsWith('owm.')));
  assert.ok(isKnownScope('owm.pay.settle'));
  assert.ok(!isKnownScope('owm.pay.drain'));
  assert.ok(!isKnownScope('*'));
});

test('scope is recovered from the domain tag bound INSIDE the signed bytes', () => {
  const auth = canonicalAuthPayload({ rp: 'bank', action: 'login', challenge: 'ab'.repeat(32), match: '12', exp: 1770000000 });
  assert.equal(scopeForCanonical(auth), 'owm.auth.respond');

  const grant = canonicalGrantPayload({ rp: 'rp', client: 'c', scope: 'owm.message.send', aud: 'a', nonce: 'cd'.repeat(32), iat: 1, exp: 2 });
  assert.equal(scopeForCanonical(grant), 'owm.grant.issue');

  const jar = canonicalBroadcastRequest({ nonce: '0123456789abcdef', purpose: 'donation', targets: ['eip155:1:0x1111111111111111111111111111111111111111'], requester: '0x1111111111111111111111111111111111111111', ts: 1, exp: 2 });
  assert.equal(scopeForCanonical(jar), 'owm.pay.request');

  const att = canonicalCallAttestation({ roomId: 'r', callId: '0123456789abcdef', fingerprint: 'x', participantsHash: 'ab'.repeat(32), fromTs: 1, toTs: 2, attester: '0x1111111111111111111111111111111111111111' });
  assert.equal(scopeForCanonical(att), 'owm.presence.attest');

  assert.equal(scopeForCanonical('no domain tag here'), null);
  assert.equal(scopeForCanonical(''), null);
});

test('least-privilege subsumption respects the segment boundary', () => {
  assert.ok(scopeCovers('owm.pay', 'owm.pay.settle'));
  assert.ok(scopeCovers('owm.pay.settle', 'owm.pay.settle'));
  assert.ok(scopeCovers('*', 'owm.grant.issue'));
  assert.ok(!scopeCovers('owm.pay.settle', 'owm.pay')); // narrow does not cover broad
  assert.ok(!scopeCovers('owm.pay', 'owm.payment.settle')); // boundary stops prefix bleed
  assert.ok(!scopeCovers('owm.message.send', 'owm.pay.settle'));
});

test('scopeSatisfies drives the agent least-privilege check', () => {
  // An agent granted only messaging cannot get a payment signed.
  const agentGrant = 'owm.message.send owm.auth.respond';
  assert.ok(scopeSatisfies(agentGrant, 'owm.message.send'));
  assert.ok(!scopeSatisfies(agentGrant, 'owm.pay.settle'));
  assert.ok(!scopeSatisfies(agentGrant, 'owm.grant.issue'));
  // A broad delegation covers beneath it, but you should prefer the narrow.
  assert.ok(scopeSatisfies('owm.pay', 'owm.pay.settle'));
  assert.ok(scopeSatisfies(['owm.bind.enroll', 'owm.bind.rotate'], 'owm.bind.rotate'));
});

test('expandScope shows a human exactly what a broad grant authorizes', () => {
  const expanded = expandScope('owm.bind');
  assert.deepEqual(expanded, ['owm.bind.enroll', 'owm.bind.rotate', 'owm.bind.revoke']);
  assert.equal(expandScope('*').length, SCOPES.length);
  assert.deepEqual(parseScope('owm.pay.settle owm.message.send'), ['owm.pay.settle', 'owm.message.send']);
});

test('checkDeclaredScope: payload-bound wins, contradiction is refused, non-OWM bytes fall back honestly', () => {
  const auth = canonicalAuthPayload({ rp: 'bank', action: 'login', challenge: 'ab'.repeat(32), match: '12', exp: 1770000000 });

  const good = checkDeclaredScope('owm.auth.respond', auth);
  assert.deepEqual(good, { ok: true, scope: 'owm.auth.respond', source: 'payload-bound' });

  // A gateway lying about scope is caught — the signer recomputes from bytes.
  const lie = checkDeclaredScope('owm.pay.settle', auth);
  assert.ok(!lie.ok);
  assert.match(lie.error, /contradicts payload-bound/);

  // XMTP enrollment bytes carry no OWM tag: declared scope accepted, but the
  // source is flagged 'declared' so the human is never silently trusted.
  const enroll = checkDeclaredScope('owm.identity.enroll', 'XMTP : Authenticate to inbox\n0xabc…');
  assert.deepEqual(enroll, { ok: true, scope: 'owm.identity.enroll', source: 'declared' });

  const junk = checkDeclaredScope('owm.pay.drain', 'some non-owm string');
  assert.ok(!junk.ok);
  assert.match(junk.error, /unknown scope/);
});
