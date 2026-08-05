// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AUTH_DOMAIN, GRANT_DOMAIN, GRANT_REVOKE_DOMAIN, AUTH_MAX_TTL_S,
  canonicalAuthPayload, canonicalGrantPayload, canonicalGrantRevokePayload,
  buildAuthChallenge, signAuthResponse, verifyAuthResponse,
  signGrant, verifyGrant, computeGrantId, signGrantRevoke, verifyGrantRevoke,
  deriveRpSubKey,
} from '../src/auth.js';
import {
  buildWmAuthChallenge, buildWmAuthResponse, buildWmGrantRequest,
  buildWmGrant, buildWmGrantRevoke, parseMessage, randomNonce,
} from '../src/envelope.js';
import { addressFromPrivateKey, signPersonalMessage, recoverPersonalMessage, toChecksumAddress } from '../src/eth-sign.js';
import { buildContactCard, verifyContactCard } from '../src/scx.js';

const KEY = `0x${'11'.repeat(32)}`;
const OTHER_KEY = `0x${'22'.repeat(32)}`;
const ADDR = addressFromPrivateKey(KEY);
const NOW = 1770000000000; // unix ms
const NOW_S = NOW / 1000;
const CH = 'ab'.repeat(32); // 64-hex challenge nonce
const NONCE = 'cd'.repeat(32);

// --- canonical strings (normative) -----------------------------------------

test('canonical auth string is exactly the WM-7 newline format', () => {
  const s = canonicalAuthPayload({
    rp: 'cryptodeposit.org', action: 'log in', challenge: CH, match: '42', exp: NOW_S + 120,
  });
  assert.equal(s, `owm-auth-v1\ncryptodeposit.org\nlog in\n${CH}\n42\n-\n${NOW_S + 120}`);
  const withBinding = canonicalAuthPayload({
    rp: 'r', action: 'a', challenge: CH, match: '07', binding: 'sess-hash', exp: 5,
  });
  assert.equal(withBinding, `owm-auth-v1\nr\na\n${CH}\n07\nsess-hash\n5`);
  assert.equal(AUTH_DOMAIN, 'owm-auth-v1');
});

test('canonical grant and revoke strings are exactly the WM-7 formats', () => {
  const g = canonicalGrantPayload({
    rp: 'rp.example', client: 'app-1', scope: 'read:balance pay:invoice',
    aud: 'api.rp.example', nonce: NONCE, iat: 100, exp: 200,
  });
  assert.equal(g, `owm-grant-v1\nrp.example\napp-1\nread:balance pay:invoice\napi.rp.example\n${NONCE}\n100\n200`);
  const r = canonicalGrantRevokePayload({ grantId: 'ef'.repeat(32), ts: 300 });
  assert.equal(r, `owm-grant-revoke-v1\n${'ef'.repeat(32)}\n300`);
  assert.equal(GRANT_DOMAIN, 'owm-grant-v1');
  assert.equal(GRANT_REVOKE_DOMAIN, 'owm-grant-revoke-v1');
});

test('canonical builders reject newline smuggling and malformed fields', () => {
  assert.throws(() => canonicalAuthPayload({ rp: 'a\nb', action: 'x', challenge: CH, match: '42', exp: 5 }));
  assert.throws(() => canonicalAuthPayload({ rp: 'a', action: 'x', challenge: 'short', match: '42', exp: 5 }));
  assert.throws(() => canonicalAuthPayload({ rp: 'a', action: 'x', challenge: CH, match: 'ab', exp: 5 }));
  assert.throws(() => canonicalGrantPayload({ rp: 'a', client: 'c\r', scope: 's', aud: 'd', nonce: NONCE, iat: 1, exp: 2 }));
  assert.throws(() => canonicalGrantRevokePayload({ grantId: 'nothex', ts: 1 }));
});

// --- OWM-AUTH ----------------------------------------------------------------

test('buildAuthChallenge: 32-byte hex nonce, exp <= iat + 120 s, TTL capped', () => {
  const env = buildAuthChallenge({ rp: 'rp', action: 'log in', now: NOW });
  assert.equal(env._kind, 'wm-auth-challenge');
  assert.match(env.challenge, /^[0-9a-f]{64}$/);
  assert.equal(env.iat, NOW_S);
  assert.equal(env.exp, NOW_S + AUTH_MAX_TTL_S);
  const short = buildAuthChallenge({ rp: 'rp', action: 'log in', now: NOW, ttlS: 30 });
  assert.equal(short.exp - short.iat, 30);
  assert.throws(() => buildAuthChallenge({ rp: 'rp', action: 'log in', now: NOW, ttlS: 121 }));
  assert.throws(() => buildAuthChallenge({ rp: 'rp', action: 'log in' })); // no now
});

test('auth response round-trips: sign then verify against server expectations', () => {
  const ch = buildAuthChallenge({ rp: 'rp', action: 'release the wire', now: NOW, challenge: CH });
  const resp = signAuthResponse({ privateKey: KEY, challenge: ch, match: '42' });
  assert.equal(resp._kind, 'wm-auth-response');
  assert.equal(resp.addr, ADDR);
  const res = verifyAuthResponse(resp, {
    rp: 'rp', action: 'release the wire', challenge: CH, match: '42',
    exp: ch.exp, enrolledAddress: ADDR, now: NOW + 5000,
  });
  assert.deepEqual(res, { ok: true, address: ADDR });
});

test('verifyAuthResponse: full transcript of distinct failure reasons', () => {
  const ch = buildAuthChallenge({ rp: 'rp', action: 'log in', now: NOW, challenge: CH });
  const resp = signAuthResponse({ privateKey: KEY, challenge: ch, match: '42' });
  const expected = {
    rp: 'rp', action: 'log in', challenge: CH, match: '42',
    exp: ch.exp, enrolledAddress: ADDR, now: NOW + 1000,
  };
  // challenge-mismatch: response for some other nonce
  assert.equal(verifyAuthResponse(resp, { ...expected, challenge: 'ff'.repeat(32) }).reason, 'challenge-mismatch');
  // expired: 121 s later
  assert.equal(verifyAuthResponse(resp, { ...expected, now: NOW + 121000 }).reason, 'expired');
  // match-mismatch: user typed a different code than the screen displayed
  assert.equal(verifyAuthResponse(resp, { ...expected, match: '43' }).reason, 'match-mismatch');
  // bad-signature: tampered sig
  const tampered = { ...resp, sig: resp.sig.replace(/^../, resp.sig.startsWith('00') ? '11' : '00') };
  assert.equal(verifyAuthResponse(tampered, expected).reason, 'bad-signature');
  // bad-signature: server expects a different action than was signed
  assert.equal(verifyAuthResponse(resp, { ...expected, action: 'drain the treasury' }).reason, 'bad-signature');
  // wrong-address: valid signature by a non-enrolled key
  const rogue = signAuthResponse({ privateKey: OTHER_KEY, challenge: ch, match: '42' });
  assert.equal(verifyAuthResponse(rogue, expected).reason, 'wrong-address');
  // bad-signature: addr field claims the enrolled address but sig is by another key
  const spoofed = { ...rogue, addr: ADDR };
  assert.equal(verifyAuthResponse(spoofed, expected).reason, 'bad-signature');
});

test('binding rides the challenge and is covered by the signature', () => {
  const ch = buildAuthChallenge({ rp: 'rp', action: 'log in', binding: 'session-hash-1', now: NOW, challenge: CH });
  const resp = signAuthResponse({ privateKey: KEY, challenge: ch, match: '11' });
  const expected = {
    rp: 'rp', action: 'log in', challenge: CH, match: '11',
    binding: 'session-hash-1', exp: ch.exp, enrolledAddress: ADDR, now: NOW,
  };
  assert.ok(verifyAuthResponse(resp, expected).ok);
  assert.equal(verifyAuthResponse(resp, { ...expected, binding: 'session-hash-2' }).reason, 'bad-signature');
  assert.equal(verifyAuthResponse(resp, { ...expected, binding: undefined }).reason, 'bad-signature');
});

test('wallet refuses malformed and over-TTL challenges', () => {
  assert.throws(() => signAuthResponse({ privateKey: KEY, challenge: { _kind: 'wm-auth-challenge', v: 1 }, match: '42' }));
  const overTtl = buildWmAuthChallenge({
    rp: 'rp', action: 'log in', challenge: CH, iat: NOW_S, exp: NOW_S + 121,
  });
  assert.throws(() => signAuthResponse({ privateKey: KEY, challenge: overTtl, match: '42' }), /refusing to sign/);
});

// --- OWM-GRANT ---------------------------------------------------------------

const GRANT_FIELDS = {
  rp: 'rp.example', client: 'shiny-app', scope: 'read:balance',
  aud: 'api.rp.example', nonce: NONCE, iat: NOW_S, exp: NOW_S + 900,
};

test('grant round-trips and grantId is SHA-256 of the canonical string', async () => {
  const grant = signGrant({ privateKey: KEY, ...GRANT_FIELDS });
  assert.equal(grant._kind, 'wm-grant');
  const res = verifyGrant(grant, { now: NOW + 1000, expectedAddress: ADDR });
  assert.ok(res.ok);
  assert.equal(res.address, ADDR);
  assert.equal(res.grantId, computeGrantId(GRANT_FIELDS));
  // independent SHA-256 of the canonical string
  const { createHash } = await import('node:crypto');
  const independent = createHash('sha256').update(canonicalGrantPayload(GRANT_FIELDS), 'utf8').digest('hex');
  assert.equal(res.grantId, independent);
  // deterministic; any field change changes the id
  assert.equal(computeGrantId(GRANT_FIELDS), computeGrantId({ ...GRANT_FIELDS }));
  assert.notEqual(computeGrantId(GRANT_FIELDS), computeGrantId({ ...GRANT_FIELDS, scope: 'read:balance x' }));
});

test('verifyGrant: tampered fields, wrong signer, expiry', () => {
  const grant = signGrant({ privateKey: KEY, ...GRANT_FIELDS });
  assert.equal(verifyGrant({ ...grant, scope: 'read:balance pay:anything' }, {}).reason, 'bad-signature');
  assert.equal(verifyGrant(grant, { expectedAddress: addressFromPrivateKey(OTHER_KEY) }).reason, 'wrong-address');
  assert.equal(verifyGrant(grant, { now: (GRANT_FIELDS.exp + 1) * 1000 }).reason, 'expired');
  assert.ok(verifyGrant(grant, {}).ok, 'offline verification without now/expectedAddress checks sig only');
});

test('grant revoke round-trips and is bound to the granting key', () => {
  const grantId = computeGrantId(GRANT_FIELDS);
  const rev = signGrantRevoke({ privateKey: KEY, grantId, ts: NOW_S + 10 });
  assert.equal(rev._kind, 'wm-grant-revoke');
  assert.ok(verifyGrantRevoke(rev, { expectedAddress: ADDR }).ok);
  assert.equal(verifyGrantRevoke(rev, { expectedAddress: addressFromPrivateKey(OTHER_KEY) }).reason, 'wrong-address');
  const tampered = { ...rev, ts: NOW_S + 11 };
  assert.notEqual(verifyGrantRevoke(tampered, { expectedAddress: ADDR }).address, ADDR.toLowerCase());
});

// --- domain separation --------------------------------------------------------

test('an auth signature never verifies as a grant, a revoke, or an SCX card (and vice versa)', () => {
  // Sign an auth response, then try to pass its sig off in other domains.
  const ch = buildAuthChallenge({ rp: 'rp', action: 'log in', now: NOW, challenge: CH });
  const resp = signAuthResponse({ privateKey: KEY, challenge: ch, match: '42' });
  const grantWithAuthSig = buildWmGrant({ ...GRANT_FIELDS, addr: ADDR, sig: resp.sig });
  assert.equal(verifyGrant(grantWithAuthSig, {}).reason, 'bad-signature');
  const revokeWithAuthSig = buildWmGrantRevoke({ grantId: CH, ts: NOW_S, sig: resp.sig });
  assert.equal(verifyGrantRevoke(revokeWithAuthSig, { expectedAddress: ADDR }).reason, 'wrong-address');
  // SCX card with an auth sig fails card verification.
  const th = 'aa'.repeat(32);
  const card = buildContactCard({ privateKey: KEY, inboxId: 'inbox-1', ts: NOW, transcriptHash: th });
  assert.ok(verifyContactCard(card, th).ok);
  assert.ok(!verifyContactCard({ ...card, sig: resp.sig }, th).ok);
  // And an SCX card sig cannot stand in for an auth response sig.
  const respWithCardSig = { ...resp, sig: card.sig };
  assert.equal(verifyAuthResponse(respWithCardSig, {
    rp: 'rp', action: 'log in', challenge: CH, match: '42', exp: ch.exp, enrolledAddress: ADDR, now: NOW,
  }).reason, 'bad-signature');
  // A grant sig is not a revoke sig even over overlapping bytes.
  const grant = signGrant({ privateKey: KEY, ...GRANT_FIELDS });
  const revokeWithGrantSig = buildWmGrantRevoke({ grantId: computeGrantId(GRANT_FIELDS), ts: NOW_S, sig: grant.sig });
  assert.equal(verifyGrantRevoke(revokeWithGrantSig, { expectedAddress: ADDR }).reason, 'wrong-address');
});

// --- envelope strictness for kinds 530-534 ------------------------------------

test('wm-auth-challenge envelope: strict validation', () => {
  const env = buildWmAuthChallenge({ rp: 'rp', action: 'log in', challenge: CH, iat: NOW_S, exp: NOW_S + 60 });
  assert.ok(parseMessage(JSON.stringify(env)).ok);
  const { rp, ...missing } = env;
  assert.match(parseMessage(JSON.stringify(missing)).error, /missing key/);
  assert.match(parseMessage(JSON.stringify({ ...env, extra: 1 })).error, /extra key/);
  assert.match(parseMessage(JSON.stringify({ ...env, iat: 'now' })).error, /type mismatch/);
  assert.match(parseMessage(JSON.stringify({ ...env, challenge: 'zz'.repeat(32) })).error, /check failed: challenge/);
  assert.match(parseMessage(JSON.stringify({ ...env, action: 'x'.repeat(141) })).error, /check failed: action/);
  assert.match(parseMessage(JSON.stringify({ ...env, binding: 'a\nb' })).error, /check failed: binding/);
  assert.throws(() => buildWmAuthChallenge({ rp: 'rp', action: 'a\r\nb', challenge: CH, iat: NOW_S, exp: NOW_S }));
});

test('wm-auth-response envelope: strict validation', () => {
  const env = buildWmAuthResponse({ challenge: CH, match: '42', addr: ADDR, sig: '0'.repeat(130) });
  assert.ok(parseMessage(JSON.stringify(env)).ok);
  const { sig, ...missing } = env;
  assert.match(parseMessage(JSON.stringify(missing)).error, /missing key/);
  assert.match(parseMessage(JSON.stringify({ ...env, injected: true })).error, /extra key/);
  assert.match(parseMessage(JSON.stringify({ ...env, match: 42 })).error, /type mismatch/);
  assert.match(parseMessage(JSON.stringify({ ...env, match: '4a' })).error, /check failed: match/);
  assert.match(parseMessage(JSON.stringify({ ...env, match: '123456789' })).error, /check failed: match/);
  assert.match(parseMessage(JSON.stringify({ ...env, addr: 'not-an-address' })).error, /check failed: addr/);
});

test('wm-grant-request and wm-grant envelopes: strict validation', () => {
  const req = buildWmGrantRequest({ ...GRANT_FIELDS });
  assert.ok(parseMessage(JSON.stringify(req)).ok);
  assert.match(parseMessage(JSON.stringify({ ...req, scope: 'a  b' })).error, /check failed: scope/); // double space
  assert.match(parseMessage(JSON.stringify({ ...req, scope: ' lead' })).error, /check failed: scope/);
  assert.match(parseMessage(JSON.stringify({ ...req, nonce: 'short' })).error, /check failed: nonce/);
  const { aud, ...missing } = req;
  assert.match(parseMessage(JSON.stringify(missing)).error, /missing key/);
  const grant = signGrant({ privateKey: KEY, ...GRANT_FIELDS });
  assert.ok(parseMessage(JSON.stringify(grant)).ok);
  assert.match(parseMessage(JSON.stringify({ ...grant, exp: '2100' })).error, /type mismatch/);
  assert.match(parseMessage(JSON.stringify({ ...grant, addr: ADDR, x: 1 })).error, /extra key/);
});

test('wm-grant-revoke envelope: strict validation', () => {
  const rev = signGrantRevoke({ privateKey: KEY, grantId: 'ef'.repeat(32), ts: NOW_S });
  assert.ok(parseMessage(JSON.stringify(rev)).ok);
  assert.match(parseMessage(JSON.stringify({ ...rev, grantId: 'EF'.repeat(32) })).error, /check failed: grantId/); // uppercase hex refused
  assert.match(parseMessage(JSON.stringify({ ...rev, ts: 1.5 })).error, /check failed: ts/);
  const { sig, ...missing } = rev;
  assert.match(parseMessage(JSON.stringify(missing)).error, /missing key/);
});

// --- eth-sign shared helpers ---------------------------------------------------

test('signPersonalMessage / recoverPersonalMessage round-trip and reject garbage', () => {
  const sig = signPersonalMessage('hello owm', KEY);
  assert.match(sig, /^[0-9a-f]{130}$/);
  assert.equal(recoverPersonalMessage('hello owm', sig), ADDR);
  assert.notEqual(recoverPersonalMessage('hello own', sig), ADDR); // 1-char change
  assert.equal(recoverPersonalMessage('hello owm', 'zz'), null);
  assert.equal(recoverPersonalMessage('hello owm', `${sig.slice(0, 128)}00`), null); // bad v
});

test('toChecksumAddress produces EIP-55 (known vector) and validates input', () => {
  // EIP-55 reference vector
  assert.equal(
    toChecksumAddress('0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed'),
    '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
  );
  assert.equal(toChecksumAddress(ADDR), toChecksumAddress(ADDR.toUpperCase().replace(/^0X/, '0x')));
  assert.throws(() => toChecksumAddress('0x123'));
});

// --- per-RP sub-identity ---------------------------------------------------------

test('deriveRpSubKey: deterministic, per-RP distinct, yields a working key', () => {
  const seed = `0x${'ab'.repeat(32)}`;
  const k1 = deriveRpSubKey(seed, 'rp-one.example');
  const k2 = deriveRpSubKey(seed, 'rp-two.example');
  assert.equal(k1, deriveRpSubKey(seed, 'rp-one.example'));
  assert.notEqual(k1, k2);
  assert.match(k1, /^[0-9a-f]{64}$/);
  // the derived scalar signs and recovers like any other key
  const addr = addressFromPrivateKey(k1);
  const sig = signPersonalMessage('per-rp', k1);
  assert.equal(recoverPersonalMessage('per-rp', sig), addr);
  assert.notEqual(addr, addressFromPrivateKey(k2));
  assert.throws(() => deriveRpSubKey('0xabcd', 'rp')); // seed too short
  assert.throws(() => deriveRpSubKey(seed, ''));
});

test('a nonce from randomNonce(32) is a valid challenge/grant nonce', () => {
  const n = randomNonce(32);
  assert.match(n, /^[0-9a-f]{64}$/);
  const env = buildAuthChallenge({ rp: 'rp', action: 'log in', now: NOW });
  assert.notEqual(env.challenge, buildAuthChallenge({ rp: 'rp', action: 'log in', now: NOW }).challenge);
});
