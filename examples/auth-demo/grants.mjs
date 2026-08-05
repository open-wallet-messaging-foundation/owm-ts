// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// Delegated grants demo — OAuth's core job as a wallet-signed capability,
// verified OFFLINE: request → WYSIWYS approval → offline verification →
// revocation. Run: node grants.mjs
//
// No token endpoint, no client secret, no introspection round-trip. The
// honest trade-off (offline verification is bounded by exp) is shown too:
// a long-lived grant fails closed without a registry.

import assert from 'node:assert/strict';
import {
  GrantServer, MemoryGrantRegistry, OwmAuthenticator,
} from '../../packages/owm-auth/src/index.js';

const step = (title) => console.log(`\n=== ${title} ===`);

const registry = new MemoryGrantRegistry();
const server = new GrantServer({
  rp: 'example.org',
  aud: 'api.example.org',      // this resource server's own identifier
  registry,                    // enables revocation + long-lived grants
});
const wallet = new OwmAuthenticator({ seed: 'cafebabe'.repeat(4) });

// --- 1. request ------------------------------------------------------------------

step('Request: the RP asks, the wallet renders it VERBATIM');
const request = server.buildGrantRequest({
  client: 'shiny-app',
  scope: 'read:balance pay:invoice',
  ttlS: 900, // 15 min — the short-exp default
});
console.log('wm-grant-request the user will see:', JSON.stringify({
  client: request.client, scope: request.scope, aud: request.aud,
  lifetime_s: request.exp - request.iat,
}));

// --- 2. approve --------------------------------------------------------------------

step('Approve: the wallet signs exactly what the user saw');
const grant = wallet.approveGrantRequest(request);
assert.equal(grant._kind, 'wm-grant');
console.log('signed by per-RP address:', grant.addr);
assert.equal(grant.addr, wallet.addressFor('example.org'));

const issued = await server.acceptGrant(grant);
assert.ok(issued.ok);
console.log('accepted at issuance, grantId:', `${issued.grantId.slice(0, 16)}…`);
// the request nonce burned — the same grant cannot be issued twice
assert.equal((await server.acceptGrant(grant)).reason, 'unknown-nonce');
console.log('re-presenting at issuance:', 'unknown-nonce', '(single-use request nonce)');

// --- 3. verify offline ---------------------------------------------------------------

step('Verify at presentation time — offline, every request');
const check = await server.verifyGrant(grant);
assert.ok(check.ok);
console.log('valid:', JSON.stringify({ client: check.client, scope: check.scope, address: check.address }));

// tampering breaks the signature (scope is inside the canonical string)
const tampered = await server.verifyGrant({ ...grant, scope: 'read:balance pay:invoice admin:everything' });
console.log('tampered scope:', tampered.reason);
assert.equal(tampered.reason, 'bad-signature');

// a resource server with a different audience refuses the same grant
const otherApi = new GrantServer({ rp: 'example.org', aud: 'other-api.example.org' });
console.log('presented to another audience:', (await otherApi.verifyGrant(grant)).reason);

// --- 4. the exp trade-off --------------------------------------------------------------

step('Long-lived grants fail closed without a registry');
const noRegistry = new GrantServer({ rp: 'example.org', aud: 'api.example.org' });
const longReq = noRegistry.buildGrantRequest({ client: 'batch-runner', scope: 'read:reports', ttlS: 30 * 24 * 3600 });
const longGrant = wallet.approveGrantRequest(longReq);
const rejected = await noRegistry.acceptGrant(longGrant);
console.log('30-day grant, no registry:', rejected.reason);
assert.equal(rejected.reason, 'long-exp-requires-registry');
console.log('(offline verification is bounded by exp — instant revocation needs one registry lookup)');

// --- 5. revoke ---------------------------------------------------------------------------

step('Revoke: only the key that signed the grant may revoke it');
const rogue = new OwmAuthenticator({ seed: 'deadbeef'.repeat(4) });
const badRevoke = rogue.revokeGrant(issued.grantId, { rp: 'example.org' });
console.log('rogue key tries to revoke:', (await server.revoke(badRevoke)).reason);
assert.ok((await server.verifyGrant(grant)).ok, 'still valid after the failed revoke');

const revoke = wallet.revokeGrant(issued.grantId); // rp remembered from approval
const done = await server.revoke(revoke);
assert.ok(done.ok);
console.log('granting wallet revokes:', done.ok);

const afterRevoke = await server.verifyGrant(grant);
console.log('verifying the (unexpired) grant now:', afterRevoke.reason, '— revocation wins over everything. done.');
assert.equal(afterRevoke.reason, 'revoked');
