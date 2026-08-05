// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildAuthChallenge, verifyAuthResponse, addressFromPrivateKey,
  computeGrantId, verifyGrantRevoke,
} from '@open-wallet-messaging/core';
import { OwmAuthenticator } from '../src/authenticator.js';

const KEY = `0x${'11'.repeat(32)}`;
const SEED = `0x${'ab'.repeat(32)}`;
const NOW = 1770000000000;

test('seed mode derives one sub-identity per RP; the primary never appears', () => {
  const wallet = new OwmAuthenticator({ seed: SEED });
  const a = wallet.addressFor('rp-one.example');
  const b = wallet.addressFor('rp-two.example');
  assert.notEqual(a, b);
  assert.equal(a, wallet.addressFor('rp-one.example')); // deterministic
  assert.match(a, /^0x[0-9a-f]{40}$/);
});

test('constructor demands exactly one of privateKey / seed', () => {
  assert.throws(() => new OwmAuthenticator({}));
  assert.throws(() => new OwmAuthenticator({ privateKey: KEY, seed: SEED }));
});

test('handleAuthChallenge signs with the per-RP key and verifies', () => {
  const wallet = new OwmAuthenticator({ seed: SEED });
  const ch = buildAuthChallenge({ rp: 'rp-one.example', action: 'sign in', now: NOW });
  const resp = wallet.handleAuthChallenge(ch, { matchCode: '42', now: NOW });
  assert.equal(resp._kind, 'wm-auth-response');
  assert.equal(resp.addr, wallet.addressFor('rp-one.example'));
  const res = verifyAuthResponse(resp, {
    rp: 'rp-one.example', action: 'sign in', challenge: ch.challenge, match: '42',
    exp: ch.exp, enrolledAddress: wallet.addressFor('rp-one.example'), now: NOW,
  });
  assert.ok(res.ok);
});

test('decline and expiry produce terminal scx-abort envelopes, never signatures', () => {
  const wallet = new OwmAuthenticator({ privateKey: KEY });
  const ch = buildAuthChallenge({ rp: 'rp.example', action: 'log in', now: NOW });
  const declined = wallet.handleAuthChallenge(ch, { approve: false, now: NOW });
  assert.deepEqual({ kind: declined._kind, reason: declined.reason }, { kind: 'scx-abort', reason: 'declined' });
  const stale = wallet.handleAuthChallenge(ch, { matchCode: '42', now: NOW + 121000 });
  assert.deepEqual({ kind: stale._kind, reason: stale.reason }, { kind: 'scx-abort', reason: 'timeout' });
  assert.throws(() => wallet.handleAuthChallenge(ch, { now: NOW })); // no matchCode typed
  assert.throws(() => wallet.handleAuthChallenge({ junk: 1 }, { matchCode: '42', now: NOW }));
});

test('revokeGrant remembers the RP of grants this wallet approved', () => {
  const wallet = new OwmAuthenticator({ seed: SEED });
  const iat = Math.floor(NOW / 1000);
  const req = {
    _kind: 'wm-grant-request', v: 1, rp: 'rp-one.example', client: 'app',
    scope: 'read:x', aud: 'api.rp-one.example', nonce: 'cd'.repeat(32), iat, exp: iat + 600,
  };
  const grant = wallet.approveGrantRequest(req);
  assert.equal(grant.addr, wallet.addressFor('rp-one.example'));
  const grantId = computeGrantId(req);
  const revoke = wallet.revokeGrant(grantId, { now: NOW }); // no rp given — remembered
  assert.ok(verifyGrantRevoke(revoke, { expectedAddress: wallet.addressFor('rp-one.example') }).ok);
  // unknown grantId in seed mode requires rp
  assert.throws(() => wallet.revokeGrant('ff'.repeat(32), { now: NOW }));
  // single-key mode never needs rp
  const single = new OwmAuthenticator({ privateKey: KEY });
  const r2 = single.revokeGrant('ff'.repeat(32), { now: NOW });
  assert.ok(verifyGrantRevoke(r2, { expectedAddress: addressFromPrivateKey(KEY) }).ok);
});

test('grant approval can be declined', () => {
  const wallet = new OwmAuthenticator({ privateKey: KEY });
  const iat = Math.floor(NOW / 1000);
  const req = {
    _kind: 'wm-grant-request', v: 1, rp: 'rp.example', client: 'app',
    scope: 'read:x', aud: 'api', nonce: 'cd'.repeat(32), iat, exp: iat + 600,
  };
  const abort = wallet.approveGrantRequest(req, { approve: false });
  assert.deepEqual({ kind: abort._kind, reason: abort.reason }, { kind: 'scx-abort', reason: 'declined' });
});
