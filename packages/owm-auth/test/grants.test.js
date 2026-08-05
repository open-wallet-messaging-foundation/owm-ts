// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import test from 'node:test';
import assert from 'node:assert/strict';
import { computeGrantId, signGrant, randomNonce } from '@open-wallet-messaging/core';
import { GrantServer } from '../src/grants.js';
import { MemoryGrantRegistry } from '../src/stores.js';
import { OwmAuthenticator } from '../src/authenticator.js';

const KEY = `0x${'11'.repeat(32)}`;
const OTHER_KEY = `0x${'22'.repeat(32)}`;
const START = 1770000000000;

function setup(opts = {}) {
  const clock = { t: START };
  const server = new GrantServer({
    rp: 'rp.example', aud: 'api.rp.example', clock: () => clock.t, ...opts,
  });
  const wallet = new OwmAuthenticator({ privateKey: KEY });
  return { server, wallet, clock };
}

test('request → approve → accept: full issuance round-trip with single-use nonce', async () => {
  const { server, wallet } = setup();
  const req = server.buildGrantRequest({ client: 'shiny-app', scope: 'read:balance pay:invoice' });
  assert.equal(req._kind, 'wm-grant-request');
  assert.equal(req.exp - req.iat, 900); // short-exp default: 15 min
  const grant = wallet.approveGrantRequest(req);
  assert.equal(grant._kind, 'wm-grant');
  const res = await server.acceptGrant(grant);
  assert.ok(res.ok);
  assert.equal(res.client, 'shiny-app');
  assert.equal(res.scope, 'read:balance pay:invoice');
  assert.equal(res.address, wallet.addressFor('rp.example'));
  assert.equal(res.grantId, computeGrantId(req));
  // nonce burned: the same grant cannot be issued twice
  assert.equal((await server.acceptGrant(grant)).reason, 'unknown-nonce');
});

test('acceptGrant refuses a grant answering no outstanding request', async () => {
  const { server, wallet, clock } = setup();
  const unsolicited = signGrant({
    privateKey: KEY, rp: 'rp.example', client: 'x', scope: 'a',
    aud: 'api.rp.example', nonce: randomNonce(32),
    iat: Math.floor(clock.t / 1000), exp: Math.floor(clock.t / 1000) + 60,
  });
  assert.equal((await server.acceptGrant(unsolicited)).reason, 'unknown-nonce');
  assert.ok(wallet); // silence unused
});

test('verifyGrant: aud mismatch, rp mismatch, tampering, expiry, wrong signer', async () => {
  const { server, wallet, clock } = setup();
  const req = server.buildGrantRequest({ client: 'app', scope: 'read:x' });
  const grant = wallet.approveGrantRequest(req);
  assert.ok((await server.verifyGrant(grant)).ok);
  // another resource server with a different aud refuses the same grant
  const otherAud = new GrantServer({ rp: 'rp.example', aud: 'other-api.example', clock: () => clock.t });
  assert.equal((await otherAud.verifyGrant(grant)).reason, 'aud-mismatch');
  // a different RP refuses it
  const otherRp = new GrantServer({ rp: 'other.example', aud: 'api.rp.example', clock: () => clock.t });
  assert.equal((await otherRp.verifyGrant(grant)).reason, 'rp-mismatch');
  // tampered scope breaks the signature
  assert.equal((await server.verifyGrant({ ...grant, scope: 'read:x write:everything' })).reason, 'bad-signature');
  // expiry
  clock.t += 901000;
  assert.equal((await server.verifyGrant(grant)).reason, 'expired');
  clock.t = START;
  // pinned per-RP address enforced when supplied
  assert.equal(
    (await server.verifyGrant(grant, { expectedAddress: new OwmAuthenticator({ privateKey: OTHER_KEY }).addressFor('rp.example') })).reason,
    'wrong-address',
  );
});

test('long-lived grants REQUIRE a registry: fail closed without one', async () => {
  const { server, wallet } = setup(); // no registry, threshold 3600 s
  const req = server.buildGrantRequest({ client: 'app', scope: 'read:x', ttlS: 30 * 24 * 3600 });
  const grant = wallet.approveGrantRequest(req);
  const res = await server.acceptGrant(grant);
  assert.equal(res.reason, 'long-exp-requires-registry');
  // the same grant is fine when a registry is configured
  const { server: withReg, wallet: w2 } = setup({ registry: new MemoryGrantRegistry() });
  const req2 = withReg.buildGrantRequest({ client: 'app', scope: 'read:x', ttlS: 30 * 24 * 3600 });
  const grant2 = w2.approveGrantRequest(req2);
  assert.ok((await withReg.acceptGrant(grant2)).ok);
  // and a short grant is fine without any registry
  const req3 = server.buildGrantRequest({ client: 'app', scope: 'read:x', ttlS: 600 });
  assert.ok((await server.acceptGrant(wallet.approveGrantRequest(req3))).ok);
});

test('revocation wins over everything and only the granting key may revoke', async () => {
  const { server, wallet } = setup({ registry: new MemoryGrantRegistry() });
  const req = server.buildGrantRequest({ client: 'app', scope: 'pay:invoice' });
  const grant = wallet.approveGrantRequest(req);
  const { grantId } = await server.acceptGrant(grant);
  assert.ok((await server.verifyGrant(grant)).ok);
  // a rogue key cannot revoke someone else's grant
  const rogue = new OwmAuthenticator({ privateKey: OTHER_KEY });
  const badRevoke = rogue.revokeGrant(grantId, { rp: 'rp.example' });
  assert.equal((await server.revoke(badRevoke)).reason, 'wrong-address');
  assert.ok((await server.verifyGrant(grant)).ok, 'still valid after failed revoke');
  // the granting wallet revokes
  const revoke = wallet.revokeGrant(grantId);
  assert.equal(revoke._kind, 'wm-grant-revoke');
  assert.ok((await server.revoke(revoke)).ok);
  assert.equal((await server.verifyGrant(grant)).reason, 'revoked');
});

test('revoke of an unknown grant and revoke without a registry fail loudly', async () => {
  const { server: noReg, wallet } = setup();
  const someRevoke = wallet.revokeGrant('ab'.repeat(32), { rp: 'rp.example' });
  assert.equal((await noReg.revoke(someRevoke)).reason, 'no-registry');
  const { server } = setup({ registry: new MemoryGrantRegistry() });
  assert.equal((await server.revoke(someRevoke)).reason, 'unknown-grant');
  // garbage envelope
  assert.equal((await server.revoke({ nonsense: true })).reason, 'bad-signature');
});

test('grant requests render-ready: strict envelope, WYSIWYS scope string', async () => {
  const { server } = setup();
  const req = server.buildGrantRequest({ client: 'Wire Desk', scope: 'wire:release:USD-25000:acct-991' });
  assert.equal(req.scope, 'wire:release:USD-25000:acct-991');
  assert.throws(() => server.buildGrantRequest({ client: 'x', scope: 'bad\nscope' }));
});
