// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// Sign-in demo — both first factors, then native sessions, no network.
// Run: node sign-in.mjs
//
// Part 1: an EIP-4361 (SIWE) message round-trip with OwmSiweMessage —
//         the drop-in for the `siwe` package.
// Part 2: createWalletSession — sign in with EITHER a SIWE message or an
//         OWM-AUTH ceremony, get a compact ES256 session JWT, verify it
//         against the exported JWKS. No OIDC anywhere.

import assert from 'node:assert/strict';
import {
  OwmSiweMessage, generateNonce, SiweErrorType, createWalletSession, verifyJwtES256,
} from '../../packages/owm-auth/src/index.js';
import {
  signPersonalMessage, addressFromPrivateKey, toChecksumAddress,
  buildAuthChallenge, signAuthResponse,
} from '../../packages/owm-core/src/index.js';

const step = (title) => console.log(`\n=== ${title} ===`);

// The user's wallet key (normally on their phone; here so the demo runs).
const KEY = `0x${'42'.repeat(32)}`;
const ADDRESS = addressFromPrivateKey(KEY);

// --- part 1: SIWE round-trip ---------------------------------------------------

step('SIWE: build → sign → verify');
const nonce = generateNonce(); // server-side, stored with the session
const msg = new OwmSiweMessage({
  domain: 'app.example.org',
  address: toChecksumAddress(ADDRESS), // mixed-case must be EIP-55 valid
  statement: 'Sign in to Example',
  uri: 'https://app.example.org/login',
  version: '1',
  chainId: 1,
  nonce,
});
const text = msg.prepareMessage();
console.log('the user signs exactly this text:\n---\n' + text + '\n---');
const signature = `0x${signPersonalMessage(text, KEY)}`; // the wallet's part

const verified = await msg.verify({ signature, domain: 'app.example.org', nonce });
assert.equal(verified.success, true);
console.log('verify: success =', verified.success);

// the message string parses back and re-serialises byte-for-byte
assert.equal(new OwmSiweMessage(text).prepareMessage(), text);
console.log('parse → format round-trips byte-for-byte: true');

// unhappy path: a nonce mismatch, siwe-compatible error type
const badNonce = await msg.verify(
  { signature, nonce: 'someOtherNonce1' },
  { suppressExceptions: true }, // resolve instead of reject
);
assert.equal(badNonce.success, false);
console.log('wrong nonce →', JSON.stringify(badNonce.error.type),
  '(same error strings as the siwe package)');
assert.equal(badNonce.error.type, SiweErrorType.NONCE_MISMATCH);

// --- part 2: native wallet sessions ---------------------------------------------

step('Native sessions: SIWE in → session JWT out');
const clock = { t: Date.now() }; // injectable clock, as in the tests
const session = createWalletSession({ rp: 'app.example.org', ttlS: 3600, clock: () => clock.t });

const viaSiwe = await session.verifySignIn({ message: text, signature });
assert.ok(viaSiwe.ok);
console.log('method:', viaSiwe.method, '| token (truncated):', `${viaSiwe.token.slice(0, 40)}…`);

const check = session.verifySession(viaSiwe.token);
assert.ok(check.ok);
console.log('verifySession claims:', JSON.stringify(check.claims));

// any service holding the JWKS can verify with a generic JWT verifier
const generic = verifyJwtES256(viaSiwe.token, session.jwks(), { now: clock.t });
assert.ok(generic.ok);
console.log('verifies against exported JWKS with a plain JWT verifier: true');

step('Native sessions: OWM-AUTH ceremony in → session JWT out');
// Server side mints a challenge with action "sign in"; the wallet signs it
// with the match code the user typed (see two-factor.mjs for the full 2FA
// choreography — here we drive the primitives directly).
const challenge = buildAuthChallenge({ rp: 'app.example.org', action: 'sign in', now: clock.t });
const authResponse = signAuthResponse({ privateKey: KEY, challenge, match: '42' });
const viaAuth = await session.verifySignIn({
  authResponse,
  expected: { challenge: challenge.challenge, match: '42', exp: challenge.exp, enrolledAddress: ADDRESS },
});
assert.ok(viaAuth.ok);
console.log('method:', viaAuth.method, '| sub:', session.verifySession(viaAuth.token).claims.sub);

// a step-up ceremony can NEVER mint a login session
const stepUp = await session.verifySignIn({
  authResponse,
  expected: { challenge: challenge.challenge, match: '42', exp: challenge.exp, action: 'release the wire' },
});
assert.equal(stepUp.reason, 'wrong-action');
console.log('a non-"sign in" action is refused:', stepUp.reason);

step('Sessions expire');
clock.t += 3601_000; // one hour and a second later
const expired = session.verifySession(viaSiwe.token);
assert.equal(expired.reason, 'expired');
console.log('one hour later:', expired.reason, '— done.');
