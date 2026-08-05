// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OIDC bridge demo — a complete authorization-code + PKCE flow against
// createOidcIssuer, entirely in-process: discovery → authorize → token →
// id_token verified against the JWKS. The "wallet ceremony" inside the
// issuer is a real OWM-AUTH challenge round-trip. Run: node oidc-bridge.mjs
//
// In production the four issuer functions mount behind four HTTP routes;
// the flow below is exactly what an OIDC client library performs.

import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import {
  createOidcIssuer, verifyJwtES256, OwmAuthServer, OwmAuthenticator,
} from '../../packages/owm-auth/src/index.js';

const step = (title) => console.log(`\n=== ${title} ===`);

// --- the wallet ceremony the issuer will call -----------------------------------
// Any wallet dance works here (XMTP challenge, SIWE, a QR). This demo runs
// the real OWM-AUTH primitives in-process: enroll once, then each
// authorize() triggers a challenge → typed match code → signed response.

const rpServer = new OwmAuthServer({ rp: 'auth.example.org' });
const wallet = new OwmAuthenticator({ seed: 'feedface'.repeat(4) });
{
  const e = await rpServer.createEnrollmentChallenge({ userId: 'ada' });
  await rpServer.verifyEnrollmentProof(wallet.handleAuthChallenge(e.envelope, { matchCode: e.matchCode }));
}

async function walletCeremony() {
  const { envelope, matchCode } = await rpServer.createChallenge({ userId: 'ada', action: 'sign in' });
  const reply = wallet.handleAuthChallenge(envelope, { matchCode }); // user typed the code
  const res = await rpServer.verifyResponse(reply);
  if (!res.ok) throw new Error(`ceremony failed: ${res.reason}`); // throwing denies the authorize
  return { address: res.address };
}

// --- the issuer -----------------------------------------------------------------

const oidc = createOidcIssuer({
  issuer: 'https://auth.example.org',
  ceremony: walletCeremony,
  clients: { 'demo-app': { redirect_uris: ['https://app.example.org/cb'] } },
});

step('Discovery');
const d = oidc.discovery();
console.log(JSON.stringify({
  issuer: d.issuer,
  authorization_endpoint: d.authorization_endpoint,
  token_endpoint: d.token_endpoint,
  code_challenge_methods_supported: d.code_challenge_methods_supported,
  id_token_signing_alg_values_supported: d.id_token_signing_alg_values_supported,
}, null, 2));

step('Authorize (PKCE S256 required)');
// the client's PKCE pair:
const code_verifier = randomBytes(32).toString('base64url');
const code_challenge = createHash('sha256').update(code_verifier, 'utf8').digest('base64url');

const az = await oidc.authorize({
  client_id: 'demo-app',
  redirect_uri: 'https://app.example.org/cb',
  response_type: 'code',
  scope: 'openid',
  state: 'af0ifjsldkj',
  nonce: 'n-0S6_WzA2Mj',
  code_challenge,
  code_challenge_method: 'S256',
});
assert.ok(az.ok);
console.log('redirect back to the app:', az.redirectTo.replace(az.code, `${az.code.slice(0, 8)}…`));
const returnedCode = new URL(az.redirectTo).searchParams.get('code');
assert.equal(new URL(az.redirectTo).searchParams.get('state'), 'af0ifjsldkj');
console.log('state passed through: true');

step('Token');
const tok = await oidc.token({
  grant_type: 'authorization_code',
  code: returnedCode,
  redirect_uri: 'https://app.example.org/cb', // exact match enforced
  client_id: 'demo-app',
  code_verifier,
});
assert.equal(tok.status, 200);
console.log('token response:', JSON.stringify({
  token_type: tok.body.token_type,
  expires_in: tok.body.expires_in,
  scope: tok.body.scope,
  id_token: `${tok.body.id_token.slice(0, 40)}…`,
}, null, 2));

step('Verify the id_token against the issuer JWKS');
const idt = verifyJwtES256(tok.body.id_token, oidc.jwks());
assert.ok(idt.ok);
console.log('claims:', JSON.stringify(idt.claims, null, 2));
assert.equal(idt.claims.iss, 'https://auth.example.org');
assert.equal(idt.claims.aud, 'demo-app');
assert.equal(idt.claims.nonce, 'n-0S6_WzA2Mj');
console.log('sub is a CAIP-10 account:', idt.claims.sub.startsWith('eip155:1:0x'));

step('Codes are single-use, burned on first presentation');
const replay = await oidc.token({
  grant_type: 'authorization_code',
  code: returnedCode,
  redirect_uri: 'https://app.example.org/cb',
  client_id: 'demo-app',
  code_verifier,
});
console.log('replaying the code:', replay.body.error);
assert.equal(replay.body.error, 'invalid_grant');

// and a wrong verifier kills a fresh code too — even the right verifier
// can't redeem it afterwards (interception dies here):
const az2 = await oidc.authorize({
  client_id: 'demo-app', redirect_uri: 'https://app.example.org/cb',
  response_type: 'code', scope: 'openid',
  code_challenge, code_challenge_method: 'S256',
});
const wrong = await oidc.token({
  grant_type: 'authorization_code', code: az2.code,
  redirect_uri: 'https://app.example.org/cb', client_id: 'demo-app',
  code_verifier: 'not-the-right-verifier',
});
const rightAfterWrong = await oidc.token({
  grant_type: 'authorization_code', code: az2.code,
  redirect_uri: 'https://app.example.org/cb', client_id: 'demo-app',
  code_verifier,
});
console.log('wrong verifier:', wrong.body.error, '→ then the RIGHT verifier:', rightAfterWrong.body.error);
assert.equal(rightAfterWrong.body.error, 'invalid_grant');

step('Unknown clients never get a redirect');
const unknown = await oidc.authorize({
  client_id: 'evil-app', redirect_uri: 'https://evil.example/cb',
  response_type: 'code', code_challenge, code_challenge_method: 'S256',
});
console.log('unknown client_id → status', unknown.status, '| redirectTo:', unknown.redirectTo, '— done.');
assert.equal(unknown.status, 400);
assert.equal(unknown.redirectTo, undefined);
