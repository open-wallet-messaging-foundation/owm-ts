// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// Minimal ES256 (P-256 / SHA-256) JWT + JWKS helpers on node:crypto only.
// Used by the OIDC bridge (id_token) and the native wallet-session profile.
// Deliberately tiny: one alg, no alg negotiation — "alg":"none" and
// RS/HS confusion attacks are structurally impossible here.

import {
  generateKeyPairSync, createPublicKey, createPrivateKey, createHash,
  sign as cryptoSign, verify as cryptoVerify,
} from 'node:crypto';

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const b64uJson = (obj) => b64u(JSON.stringify(obj));

/**
 * Generate a fresh P-256 key pair for ES256 signing.
 * @returns {{privateKey: object, publicKey: object}} node:crypto KeyObjects.
 */
export function generateEs256KeyPair() {
  return generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

/**
 * Accept a KeyObject, a PEM string (PKCS#8/SEC1), or undefined (generate a
 * fresh pair).
 * @param {object|string} [key]
 * @returns {{privateKey: object, publicKey: object}} KeyObjects.
 * @throws {Error} When the key is not a P-256 EC key.
 */
export function importSigningKey(key) {
  if (key === undefined || key === null) return generateEs256KeyPair();
  const privateKey = typeof key === 'string' ? createPrivateKey(key) : key;
  if (privateKey.asymmetricKeyType !== 'ec') throw new Error('signingKey must be a P-256 EC key');
  return { privateKey, publicKey: createPublicKey(privateKey) };
}

/**
 * RFC 7638 JWK thumbprint (EC): SHA-256 over the canonical member subset.
 * @param {object} jwk EC public JWK with crv/kty/x/y.
 * @returns {string} base64url thumbprint (used as `kid`).
 */
export function jwkThumbprint(jwk) {
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  return b64u(createHash('sha256').update(canonical, 'utf8').digest());
}

/**
 * Export a public KeyObject as a signing JWK with alg/use/kid set.
 * @param {object} publicKey P-256 public KeyObject.
 * @returns {object} `{ kty, crv, x, y, alg: 'ES256', use: 'sig', kid }`.
 */
export function publicJwk(publicKey) {
  const { kty, crv, x, y } = publicKey.export({ format: 'jwk' });
  const jwk = { kty, crv, x, y, alg: 'ES256', use: 'sig' };
  jwk.kid = jwkThumbprint(jwk);
  return jwk;
}

/**
 * Sign a compact ES256 JWT (raw r||s signature per JWS).
 * @param {object} claims JWT claims (remember: iat/exp/nbf are unix SECONDS).
 * @param {object} privateKey P-256 private KeyObject.
 * @param {object} [opts]
 * @param {string} [opts.kid] Key id to place in the header.
 * @returns {string} Compact JWT.
 */
export function signJwtES256(claims, privateKey, { kid } = {}) {
  const header = { alg: 'ES256', typ: 'JWT', ...(kid ? { kid } : {}) };
  const signingInput = `${b64uJson(header)}.${b64uJson(claims)}`;
  const sig = cryptoSign('sha256', Buffer.from(signingInput, 'utf8'), {
    key: privateKey, dsaEncoding: 'ieee-p1363', // raw r||s, per JWS
  });
  return `${signingInput}.${b64u(sig)}`;
}

/**
 * Verify a compact ES256 JWT: signature, exp, nbf. Only ES256 is accepted
 * — "alg":"none" and RS/HS confusion are structurally impossible.
 * @param {string} token Compact JWT.
 * @param {object} keyOrJwks A public KeyObject, a single JWK, or a JWKS
 *   `{ keys: [...] }` (selected by header kid when present).
 * @param {object} [opts]
 * @param {number} [opts.now] Unix MS (converted internally; claims are unix seconds).
 * @returns {{ok: true, header: object, claims: object} | {ok: false, reason: string}}
 *   Failure reasons: 'malformed' | 'bad-alg' | 'unknown-kid' | 'bad-key' |
 *   'bad-signature' | 'expired' | 'not-yet-valid'.
 */
export function verifyJwtES256(token, keyOrJwks, { now = Date.now() } = {}) {
  if (typeof token !== 'string') return { ok: false, reason: 'malformed' };
  const parts = token.split('.');
  if (parts.length !== 3) return { ok: false, reason: 'malformed' };
  let header; let claims; let sig;
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    sig = Buffer.from(parts[2], 'base64url');
  } catch {
    return { ok: false, reason: 'malformed' };
  }
  if (header.alg !== 'ES256') return { ok: false, reason: 'bad-alg' };
  let publicKey;
  try {
    if (keyOrJwks && Array.isArray(keyOrJwks.keys)) {
      const jwk = header.kid
        ? keyOrJwks.keys.find((k) => k.kid === header.kid)
        : keyOrJwks.keys[0];
      if (!jwk) return { ok: false, reason: 'unknown-kid' };
      publicKey = createPublicKey({ key: jwk, format: 'jwk' });
    } else if (keyOrJwks && keyOrJwks.kty) {
      publicKey = createPublicKey({ key: keyOrJwks, format: 'jwk' });
    } else {
      publicKey = keyOrJwks;
    }
  } catch {
    return { ok: false, reason: 'bad-key' };
  }
  const okSig = cryptoVerify(
    'sha256',
    Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8'),
    { key: publicKey, dsaEncoding: 'ieee-p1363' },
    sig,
  );
  if (!okSig) return { ok: false, reason: 'bad-signature' };
  const nowS = Math.floor(now / 1000);
  if (typeof claims.exp === 'number' && nowS > claims.exp) return { ok: false, reason: 'expired' };
  if (typeof claims.nbf === 'number' && nowS < claims.nbf) return { ok: false, reason: 'not-yet-valid' };
  return { ok: true, header, claims };
}
