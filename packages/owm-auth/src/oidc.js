// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// Two sign-in profiles (WM-7 §6). Pick one:
//
//  - KEEP your OIDC plumbing → `createOidcIssuer` (the BRIDGE): a minimal,
//    framework-agnostic OIDC issuer facade that authenticates via the
//    wallet ceremony you supply. Any stack that can add "Sign in with
//    Google" can add "Sign in with Wallet" — same discovery, jwks,
//    authorization-code + PKCE, id_token.
//
//  - DROP OIDC entirely → `createWalletSession` (the NATIVE profile): no
//    redirects, no codes, no IdP. A verified OWM-AUTH response (action
//    "sign in") or a verified SIWE message yields a compact ES256 session
//    JWT; other services verify it against your exported JWKS.
//
// v0-dev honesty (bridge): minimal profile — authorization-code + PKCE
// (S256, REQUIRED), single-use codes, exact redirect_uri match, state
// passthrough, nonce claim. NOT yet: dynamic client registration, consent
// persistence, refresh tokens, userinfo endpoint. The `clients` option
// gives static registration; without it any client_id with an
// https/http(localhost-style dev) redirect_uri is accepted — dev only.

import { createHash, randomBytes } from 'node:crypto';
import { verifyAuthResponse, parseMessage, canonicalAuthPayload } from '@open-wallet-messaging/core';
import { importSigningKey, publicJwk, signJwtES256, verifyJwtES256 } from './jwt.js';
import { OwmSiweMessage } from './siwe.js';

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const caip10 = (address, chainId = 1) => `eip155:${chainId}:${address.toLowerCase()}`;

// --- Bridge profile ----------------------------------------------------------

/**
 * Bridge profile: a minimal, framework-agnostic OIDC issuer facade that
 * authenticates via the wallet ceremony you supply. Mount the four
 * returned handlers on your HTTP stack; point any OIDC client at it.
 *
 * @param {object} opts
 * @param {string} opts.issuer http(s) issuer URL. Required.
 * @param {Function} opts.ceremony `async (authorizeParams) => { address, sub? }`
 *   — YOUR wallet dance (OwmAuthServer challenge, SIWE, anything). Throw or
 *   return a falsy value to deny. Transport-agnostic by design. Required.
 * @param {object|string} [opts.signingKey] P-256 private key (KeyObject or PEM);
 *   omit to generate a fresh pair (dev).
 * @param {number} [opts.codeTtlS=120] Authorization-code lifetime.
 * @param {number} [opts.idTokenTtlS=3600] id_token lifetime.
 * @param {number} [opts.accessTokenTtlS=3600] Advertised access-token lifetime.
 * @param {?object} [opts.clients] Static registration `{ [client_id]: { redirect_uris: [...] } }`.
 *   Without it ANY client_id/redirect_uri is accepted — dev only.
 * @param {Function} [opts.clock] `() => unix ms` — inject a fake clock in tests.
 * @returns {{issuer: string, discovery: Function, jwks: Function,
 *   authorize: Function, token: Function}}
 *
 * @example
 * const oidc = createOidcIssuer({
 *   issuer: 'https://auth.example.org',
 *   ceremony: async () => ({ address: await runWalletChallenge() }),
 * });
 * // GET /.well-known/openid-configuration → oidc.discovery()
 * // GET /jwks       → oidc.jwks()
 * // GET /authorize  → await oidc.authorize(query)   (follow .redirectTo)
 * // POST /token     → await oidc.token(form)        (send .body with .status)
 */
export function createOidcIssuer({
  issuer,
  ceremony,
  signingKey,
  codeTtlS = 120,
  idTokenTtlS = 3600,
  accessTokenTtlS = 3600,
  clients = null, // { [client_id]: { redirect_uris: [...] } } — static registration
  clock = () => Date.now(),
} = {}) {
  if (typeof issuer !== 'string' || !/^https?:\/\//.test(issuer)) throw new Error('issuer must be an http(s) URL');
  if (typeof ceremony !== 'function') throw new Error('ceremony(authorizeParams) callback required');
  const iss = issuer.replace(/\/$/, '');
  const { privateKey, publicKey } = importSigningKey(signingKey);
  const jwk = publicJwk(publicKey);
  const codes = new Map(); // code -> record, single-use

  function discovery() {
    return {
      issuer: iss,
      authorization_endpoint: `${iss}/authorize`,
      token_endpoint: `${iss}/token`,
      jwks_uri: `${iss}/jwks`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      code_challenge_methods_supported: ['S256'],
      id_token_signing_alg_values_supported: ['ES256'],
      subject_types_supported: ['public'],
      scopes_supported: ['openid'],
      token_endpoint_auth_methods_supported: ['none'], // public clients + PKCE
    };
  }

  function jwks() {
    return { keys: [jwk] };
  }

  async function authorize(params = {}) {
    const {
      client_id, redirect_uri, response_type, scope, state, nonce,
      code_challenge, code_challenge_method,
    } = params;
    // Failures before redirect_uri is validated NEVER redirect.
    if (typeof client_id !== 'string' || client_id.length === 0) {
      return { ok: false, status: 400, error: 'invalid_request', error_description: 'client_id required' };
    }
    if (typeof redirect_uri !== 'string' || !/^https?:\/\//.test(redirect_uri)) {
      return { ok: false, status: 400, error: 'invalid_request', error_description: 'redirect_uri required (http(s))' };
    }
    if (clients) {
      const reg = clients[client_id];
      if (!reg) return { ok: false, status: 400, error: 'unauthorized_client', error_description: 'unknown client_id' };
      if (!reg.redirect_uris?.includes(redirect_uri)) {
        return { ok: false, status: 400, error: 'invalid_request', error_description: 'unregistered redirect_uri' };
      }
    }
    const sep = redirect_uri.includes('?') ? '&' : '?';
    const stateSuffix = state !== undefined ? `&state=${encodeURIComponent(state)}` : '';
    const errRedirect = (error, error_description) => ({
      ok: false,
      error,
      error_description,
      redirectTo: `${redirect_uri}${sep}error=${encodeURIComponent(error)}&error_description=${encodeURIComponent(error_description)}${stateSuffix}`,
    });
    if (response_type !== 'code') return errRedirect('unsupported_response_type', 'only response_type=code');
    if (code_challenge_method !== 'S256' || typeof code_challenge !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(code_challenge)) {
      return errRedirect('invalid_request', 'PKCE required: code_challenge (43-char base64url) + code_challenge_method=S256');
    }
    let result = null;
    try {
      result = await ceremony(params);
    } catch { /* denied */ }
    if (!result || typeof result.address !== 'string') {
      return errRedirect('access_denied', 'wallet ceremony failed or was declined');
    }
    const code = randomBytes(32).toString('base64url');
    codes.set(code, {
      client_id,
      redirect_uri,
      nonce,
      scope: typeof scope === 'string' && scope.length > 0 ? scope : 'openid',
      sub: result.sub ?? caip10(result.address),
      code_challenge,
      exp: clock() + codeTtlS * 1000,
    });
    return { ok: true, code, redirectTo: `${redirect_uri}${sep}code=${encodeURIComponent(code)}${stateSuffix}` };
  }

  async function token(params = {}) {
    const bad = (error, error_description) => ({ ok: false, status: 400, body: { error, error_description } });
    if (params.grant_type !== 'authorization_code') return bad('unsupported_grant_type', 'only authorization_code');
    if (typeof params.code !== 'string') return bad('invalid_request', 'code required');
    const rec = codes.get(params.code);
    codes.delete(params.code); // single-use: burned on FIRST presentation, valid or not
    if (!rec) return bad('invalid_grant', 'unknown, expired, or already-used code');
    if (clock() > rec.exp) return bad('invalid_grant', 'code expired');
    if (params.client_id !== rec.client_id) return bad('invalid_grant', 'client_id mismatch');
    if (params.redirect_uri !== rec.redirect_uri) return bad('invalid_grant', 'redirect_uri mismatch'); // exact match
    if (typeof params.code_verifier !== 'string'
        || b64u(createHash('sha256').update(params.code_verifier, 'utf8').digest()) !== rec.code_challenge) {
      return bad('invalid_grant', 'PKCE verification failed');
    }
    const iat = Math.floor(clock() / 1000);
    const idToken = signJwtES256({
      iss, sub: rec.sub, aud: rec.client_id, iat, exp: iat + idTokenTtlS,
      ...(rec.nonce !== undefined ? { nonce: rec.nonce } : {}),
    }, privateKey, { kid: jwk.kid });
    return {
      ok: true,
      status: 200,
      body: {
        access_token: randomBytes(32).toString('base64url'),
        token_type: 'Bearer',
        expires_in: accessTokenTtlS,
        scope: rec.scope,
        id_token: idToken,
      },
    };
  }

  return { issuer: iss, discovery, jwks, authorize, token };
}

// --- Native profile ------------------------------------------------------------

/**
 * Native profile — no OIDC anywhere. verifySignIn accepts EITHER
 * `{ authResponse, expected }` (a wm-auth-response verified against the
 * challenge state you hold; action is forced to "sign in") OR
 * `{ message, signature, domain?, nonce?, time? }` (an EIP-4361 message,
 * string or OwmSiweMessage, plus signature), and on success issues a
 * compact ES256 session JWT `{ iss: rp, sub: <caip10 address>, iat, exp }`
 * that any service holding jwks() can verify (verifySession here, or any
 * standard JWT library).
 *
 * @param {object} opts
 * @param {string} opts.rp Relying-party identifier (becomes the JWT `iss`). Required.
 * @param {object|string} [opts.signingKey] P-256 private key (KeyObject or PEM);
 *   omit to generate a fresh pair (dev).
 * @param {number} [opts.ttlS=3600] Session JWT lifetime in seconds.
 * @param {number} [opts.chainId=1] CAIP-10 chain id for `sub`.
 * @param {Function} [opts.clock] `() => unix ms` — inject a fake clock in tests.
 * @param {?object} [opts.verifier] Optional chain verifier from
 *   `createChainVerifier` — enables ERC-1271/6492 smart-contract-wallet
 *   sign-ins on both paths. Consulted ONLY after EOA recovery fails; fail
 *   closed. See erc1271.js for the RPC trust note.
 * @returns {{rp: string, issueSession: Function, verifySignIn: Function,
 *   verifySession: Function, jwks: Function}}
 *
 * @example
 * const session = createWalletSession({ rp: 'example.org' });
 * const res = await session.verifySignIn({ message: siweText, signature });
 * if (res.ok) reply.setCookie('session', res.token);
 * // later, on any service holding session.jwks():
 * const check = session.verifySession(req.cookies.session);
 */
export function createWalletSession({
  rp,
  signingKey,
  ttlS = 3600,
  chainId = 1,
  clock = () => Date.now(),
  verifier = null,
} = {}) {
  if (typeof rp !== 'string' || rp.length === 0) throw new Error('rp required');
  const { privateKey, publicKey } = importSigningKey(signingKey);
  const jwk = publicJwk(publicKey);

  function issueSession(address, extraClaims = {}) {
    const iat = Math.floor(clock() / 1000);
    return signJwtES256({
      iss: rp, sub: caip10(address, chainId), iat, exp: iat + ttlS, ...extraClaims,
    }, privateKey, { kid: jwk.kid });
  }

  // ERC-1271/6492 fallback for the OWM-AUTH path (WM-7 §8): rebuild the
  // canonical string from the CALLER's expected state, verify the
  // envelope's sig for the envelope's addr via the injected verifier,
  // then re-apply the enrolled-address pin. Fail closed on any throw.
  async function verifyAuthResponseViaChain(envelope, expected) {
    try {
      const parsed = parseMessage(JSON.stringify(envelope));
      if (!parsed.ok || parsed.kind !== 'wm-auth-response') return { ok: false, reason: 'bad-signature' };
      const body = parsed.body;
      const payload = canonicalAuthPayload({
        rp: expected.rp,
        action: expected.action,
        challenge: expected.challenge,
        match: expected.match,
        binding: expected.binding,
        exp: expected.exp,
      });
      const v = await verifier.verifySignature({ address: body.addr, payload, signature: body.sig });
      if (!v.ok) return { ok: false, reason: 'bad-signature' };
      const address = body.addr.toLowerCase();
      if (expected.enrolledAddress !== undefined && address !== expected.enrolledAddress.toLowerCase()) {
        return { ok: false, reason: 'wrong-address' };
      }
      return { ok: true, address };
    } catch {
      return { ok: false, reason: 'bad-signature' }; // fail closed
    }
  }

  async function verifySignIn(input = {}) {
    if (input.authResponse !== undefined) {
      const expected = { now: clock(), ...input.expected, rp: input.expected?.rp ?? rp, action: 'sign in' };
      if (input.expected?.action !== undefined && input.expected.action !== 'sign in') {
        return { ok: false, reason: 'wrong-action' }; // a sign-in is ONLY the "sign in" ceremony
      }
      let res = verifyAuthResponse(input.authResponse, expected);
      // Contract-wallet retry only after EOA recovery failed — every
      // pre-signature check (challenge, expiry, match) already passed.
      if (!res.ok && res.reason === 'bad-signature' && verifier) {
        res = await verifyAuthResponseViaChain(input.authResponse, expected);
      }
      if (!res.ok) return res;
      return { ok: true, method: 'owm-auth', address: res.address, token: issueSession(res.address) };
    }
    if (input.message !== undefined && input.signature !== undefined) {
      const msg = input.message instanceof OwmSiweMessage ? input.message : new OwmSiweMessage(input.message);
      const res = await msg.verify(
        { signature: input.signature, domain: input.domain ?? rp, nonce: input.nonce, time: input.time ?? new Date(clock()).toISOString() },
        { suppressExceptions: true, verifier },
      );
      if (!res.success) return { ok: false, reason: 'siwe-verification-failed', error: res.error };
      const address = msg.address.toLowerCase();
      return { ok: true, method: 'siwe', address, token: issueSession(address) };
    }
    return { ok: false, reason: 'bad-input' };
  }

  function verifySession(token) {
    const res = verifyJwtES256(token, jwk, { now: clock() });
    if (!res.ok) return res;
    if (res.claims.iss !== rp) return { ok: false, reason: 'wrong-issuer' };
    return { ok: true, claims: res.claims };
  }

  function jwks() {
    return { keys: [jwk] };
  }

  return { rp, issueSession, verifySignIn, verifySession, jwks };
}
