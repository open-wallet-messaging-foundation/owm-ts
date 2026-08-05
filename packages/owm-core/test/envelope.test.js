// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildPing, buildPong, buildKnock, parseMessage, randomNonce,
} from '../src/envelope.js';
import { KIND, wireName, kindCode, isOwmKind, isVendorKind } from '../src/kinds.js';

const TS = 1770000000000;

test('kind registry round-trips code <-> wire', () => {
  assert.equal(wireName(KIND.WmPing), 'wm-ping');
  assert.equal(kindCode('wm-ping'), 500);
  assert.equal(kindCode('scx-abort'), 514);
  assert.equal(wireName(516), 'wm-signed-announcement');
  assert.equal(wireName(12345), null);
  assert.equal(kindCode('no-such-kind'), null);
});

test('owm and vendor range predicates', () => {
  assert.ok(isOwmKind(500) && isOwmKind(549) && isOwmKind(550) && isOwmKind(799));
  assert.ok(!isOwmKind(499) && !isOwmKind(800) && !isOwmKind(1.5));
  assert.ok(isVendorKind(1000, 'vnd.krypty.yield-alert'));
  assert.ok(!isVendorKind(1000, 'yield-alert'));
  assert.ok(!isVendorKind(999, 'vnd.x'));
});

test('ping builds valid and round-trips through parse', () => {
  const ping = buildPing({ purpose: 'call', ts: TS });
  const parsed = parseMessage(JSON.stringify(ping));
  assert.ok(parsed.ok);
  assert.equal(parsed.kind, 'wm-ping');
  assert.equal(parsed.body.purpose, 'call');
});

test('pong and knock build valid', () => {
  const pong = buildPong({ nonce: randomNonce(), auto: true, ts: TS });
  assert.ok(parseMessage(JSON.stringify(pong)).ok);
  const knock = buildKnock({ purpose: 'attention', ts: TS, note: 'hello' });
  assert.ok(parseMessage(JSON.stringify(knock)).ok);
});

test('ping rejects a bad purpose at build time', () => {
  assert.throws(() => buildPing({ purpose: 'marketing-spam', ts: TS }));
});

test('parse rejects an extra key (strict)', () => {
  const ping = buildPing({ purpose: 'attention', ts: TS });
  const tampered = { ...ping, injected: 'x' };
  const parsed = parseMessage(JSON.stringify(tampered));
  assert.ok(!parsed.ok);
  assert.match(parsed.error, /extra key/);
});

test('parse rejects a missing key and a type mismatch', () => {
  const ping = buildPing({ purpose: 'attention', ts: TS });
  const { nonce, ...missing } = ping;
  assert.match(parseMessage(JSON.stringify(missing)).error, /missing key/);
  const badType = { ...ping, ts: 'yesterday' };
  assert.match(parseMessage(JSON.stringify(badType)).error, /type mismatch/);
});

test('knock note over 280 chars is rejected', () => {
  assert.throws(() => buildKnock({ purpose: 'attention', ts: TS, note: 'x'.repeat(281) }));
});

test('unknown kind surfaces as unknown, plain text as plain', () => {
  const unknown = parseMessage(JSON.stringify({ _kind: 'from-the-future', v: 9 }));
  assert.ok(!unknown.ok && unknown.unknown && unknown.kind === 'from-the-future');
  assert.ok(parseMessage('just chatting').plain);
  assert.ok(parseMessage('[1,2,3]').plain);
});

test('nonces are hex, sized, and unique', () => {
  const a = randomNonce();
  const b = randomNonce();
  assert.match(a, /^[0-9a-f]{32}$/);
  assert.notEqual(a, b);
});
