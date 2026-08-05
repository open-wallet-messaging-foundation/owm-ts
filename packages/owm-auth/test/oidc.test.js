// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import {
  buildAuthChallenge, signAuthResponse, addressFromPrivateKey,
  toChecksumAddress, signPersonalMessage,
} from '@open-wallet-messaging/core';
import { createOidcIssuer, createWalletSession } from '../src/oidc.js';
import { verifyJwtES256 } from '../src/jwt.js';
import { OwmSiweMessage } from '../src/siwe.js';

const KEY = `0x${'11'.repeat(32)}`;
const ADDR = addressFromPrivateKey(KEY);
const START = 1770000000000;

const s256 = (v) => createHash('sha256').update(v, 'utf8').digest('base64url');

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: s256(verifier) };
}

const AUTHZ = (extra = {}) => ({
  client_id: 'client-1',
  redirect_uri: 'https://app.example/cb',
  response_type: 'code',
  scope: 'openid',
  state: 'xyz',
  nonce: 'n-0S6_WzA2Mj',
  ...extra,
});

function issuer(extra = {}) {
  const clock = { t: START };
  const it = createOidcIssuer({
    issuer: 'https://auth.rp.example',
    ceremony: async () => ({ address: ADDR }),
    clock: () => clock.t,
    ...extra,
  });
  return { it, clock };
}

test('discovery and jwks advertise the minimal PKCE-only ES256 profile', () => {
  const { it } = issuer();
  const d = it.discovery();
  assert.equal(d.issuer, 'https://auth.rp.example');
  assert.equal(d.authorization_endpoint, 'https://auth.rp.example/authorize');
  assert.equal(d.token_endpoint, 'https://auth.rp.example/token');
  assert.equal(d.jwks_uri, 'https://auth.rp.example/jwks');
  assert.deepEqual(d.code_challenge_methods_supported, ['S256']);
  assert.deepEqual(d.id_token_signing_alg_values_supported, ['ES256']);
  const { keys } = it.jwks();
  assert.equal(keys.length, 1);
  assert.deepEqual({ kty: keys[0].kty, crv: keys[0].crv, alg: keys[0].alg }, { kty: 'EC', crv: 'P-256', alg: 'ES256' });
  assert.ok(keys[0].kid);
});

test('full code flow: authorize (PKCE) → token → id_token verifies against jwks', async () => {
  const { it } = issuer();
  const { verifier, challenge } = pkce();
  const az = await it.authorize(AUTHZ({ code_challenge: challenge, code_challenge_method: 'S256' }));
  assert.ok(az.ok);
  assert.ok(az.redirectTo.startsWith('https://app.example/cb?code='));
  assert.ok(az.redirectTo.includes('&state=xyz'), 'state passes through');
  const tok = await it.token({
    grant_type: 'authorization_code', code: az.code,
    redirect_uri: 'https://app.example/cb', client_id: 'client-1', code_verifier: verifier,
  });
  assert.equal(tok.status, 200);
  assert.equal(tok.body.token_type, 'Bearer');
  const idt = verifyJwtES256(tok.body.id_token, it.jwks(), { now: START });
  assert.ok(idt.ok);
  assert.equal(idt.claims.iss, 'https://auth.rp.example');
  assert.equal(idt.claims.aud, 'client-1');
  assert.equal(idt.claims.sub, `eip155:1:${ADDR}`);
  assert.equal(idt.claims.nonce, 'n-0S6_WzA2Mj');
});

test('wrong code_verifier is rejected; the code is burned on first presentation', async () => {
  const { it } = issuer();
  const { verifier, challenge } = pkce();
  const az = await it.authorize(AUTHZ({ code_challenge: challenge, code_challenge_method: 'S256' }));
  const bad = await it.token({
    grant_type: 'authorization_code', code: az.code,
    redirect_uri: 'https://app.example/cb', client_id: 'client-1', code_verifier: 'wrong-verifier',
  });
  assert.equal(bad.body.error, 'invalid_grant');
  // burned: even the RIGHT verifier cannot redeem it now
  const replay = await it.token({
    grant_type: 'authorization_code', code: az.code,
    redirect_uri: 'https://app.example/cb', client_id: 'client-1', code_verifier: verifier,
  });
  assert.equal(replay.body.error, 'invalid_grant');
});

test('code replay, redirect_uri mismatch, client mismatch, expiry — all invalid_grant', async () => {
  const { it, clock } = issuer();
  const mk = async () => {
    const { verifier, challenge } = pkce();
    const az = await it.authorize(AUTHZ({ code_challenge: challenge, code_challenge_method: 'S256' }));
    return { verifier, code: az.code };
  };
  const good = await mk();
  const ok = await it.token({
    grant_type: 'authorization_code', code: good.code,
    redirect_uri: 'https://app.example/cb', client_id: 'client-1', code_verifier: good.verifier,
  });
  assert.equal(ok.status, 200);
  const replay = await it.token({
    grant_type: 'authorization_code', code: good.code,
    redirect_uri: 'https://app.example/cb', client_id: 'client-1', code_verifier: good.verifier,
  });
  assert.equal(replay.body.error, 'invalid_grant');
  const b = await mk();
  assert.equal((await it.token({
    grant_type: 'authorization_code', code: b.code,
    redirect_uri: 'https://app.example/cb/other', client_id: 'client-1', code_verifier: b.verifier,
  })).body.error, 'invalid_grant'); // exact redirect_uri match
  const c = await mk();
  assert.equal((await it.token({
    grant_type: 'authorization_code', code: c.code,
    redirect_uri: 'https://app.example/cb', client_id: 'client-2', code_verifier: c.verifier,
  })).body.error, 'invalid_grant');
  const d = await mk();
  clock.t += 121000; // past codeTtlS
  assert.equal((await it.token({
    grant_type: 'authorization_code', code: d.code,
    redirect_uri: 'https://app.example/cb', client_id: 'client-1', code_verifier: d.verifier,
  })).body.error, 'invalid_grant');
});

test('PKCE is mandatory and denial maps to access_denied; static clients enforced', async () => {
  const { it } = issuer();
  const noPkce = await it.authorize(AUTHZ());
  assert.equal(noPkce.ok, false);
  assert.equal(noPkce.error, 'invalid_request');
  assert.ok(noPkce.redirectTo.includes('error=invalid_request'));
  const denying = createOidcIssuer({
    issuer: 'https://auth.rp.example',
    ceremony: async () => { throw new Error('user said no'); },
  });
  const { challenge } = pkce();
  const denied = await denying.authorize(AUTHZ({ code_challenge: challenge, code_challenge_method: 'S256' }));
  assert.equal(denied.error, 'access_denied');
  // static registration: unknown client / unregistered redirect never redirect
  const strict = createOidcIssuer({
    issuer: 'https://auth.rp.example',
    ceremony: async () => ({ address: ADDR }),
    clients: { 'client-1': { redirect_uris: ['https://app.example/cb'] } },
  });
  const unknown = await strict.authorize(AUTHZ({ client_id: 'nope', code_challenge: challenge, code_challenge_method: 'S256' }));
  assert.deepEqual({ status: unknown.status, redirectTo: unknown.redirectTo }, { status: 400, redirectTo: undefined });
  const badUri = await strict.authorize(AUTHZ({ redirect_uri: 'https://evil.example/cb', code_challenge: challenge, code_challenge_method: 'S256' }));
  assert.equal(badUri.status, 400);
});

// --- native profile ------------------------------------------------------------

test('native session: sign-in via OWM-AUTH issues a verifiable session JWT', async () => {
  const clock = { t: START };
  const session = createWalletSession({ rp: 'rp.example', ttlS: 3600, clock: () => clock.t });
  const ch = buildAuthChallenge({ rp: 'rp.example', action: 'sign in', now: clock.t });
  const resp = signAuthResponse({ privateKey: KEY, challenge: ch, match: '42' });
  const res = await session.verifySignIn({
    authResponse: resp,
    expected: { challenge: ch.challenge, match: '42', exp: ch.exp, enrolledAddress: ADDR },
  });
  assert.ok(res.ok);
  assert.equal(res.method, 'owm-auth');
  const v = session.verifySession(res.token);
  assert.ok(v.ok);
  assert.equal(v.claims.iss, 'rp.example');
  assert.equal(v.claims.sub, `eip155:1:${ADDR}`);
  // the JWT also verifies against the exported JWKS with a generic verifier
  assert.ok(verifyJwtES256(res.token, session.jwks(), { now: clock.t }).ok);
  // a non-"sign in" ceremony is refused
  const bad = await session.verifySignIn({
    authResponse: resp,
    expected: { challenge: ch.challenge, match: '42', exp: ch.exp, action: 'release the wire' },
  });
  assert.equal(bad.reason, 'wrong-action');
});

test('native session: sign-in via SIWE; expired sessions and foreign issuers fail', async () => {
  const clock = { t: Date.parse('2026-07-13T00:05:00.000Z') };
  const session = createWalletSession({ rp: 'app.example.org', ttlS: 60, clock: () => clock.t });
  const msg = new OwmSiweMessage({
    domain: 'app.example.org',
    address: toChecksumAddress(ADDR),
    uri: 'https://app.example.org/login',
    version: '1',
    chainId: 1,
    nonce: 'abcdefgh1234',
    issuedAt: '2026-07-13T00:04:00.000Z',
  });
  const text = msg.prepareMessage();
  const res = await session.verifySignIn({ message: text, signature: `0x${signPersonalMessage(text, KEY)}` });
  assert.ok(res.ok);
  assert.equal(res.method, 'siwe');
  assert.equal(res.address, ADDR);
  assert.ok(session.verifySession(res.token).ok);
  // expired session
  clock.t += 61000;
  assert.equal(session.verifySession(res.token).reason, 'expired');
  clock.t -= 61000;
  // wrong domain in the SIWE message → refused
  const foreign = await session.verifySignIn({ message: text, signature: `0x${signPersonalMessage(text, KEY)}`, domain: 'other.example' });
  assert.equal(foreign.reason, 'siwe-verification-failed');
  // a token minted by another RP's session fails verification here
  const other = createWalletSession({ rp: 'other.example', clock: () => clock.t });
  const otherToken = other.issueSession(ADDR);
  assert.equal(session.verifySession(otherToken).ok, false);
  // tampered token
  const [h, p, s] = res.token.split('.');
  const forged = `${h}.${Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p, 'base64url')), sub: 'eip155:1:0xdead' })).toString('base64url')}.${s}`;
  assert.equal(session.verifySession(forged).reason, 'bad-signature');
});
