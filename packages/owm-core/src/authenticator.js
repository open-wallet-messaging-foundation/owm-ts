// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// @open-wallet-messaging/core — walletAuthenticator: a DROP-IN replacement for TOTP authenticator
// libraries (Google / Microsoft Authenticator, otplib, speakeasy) and a starting
// point for a full auth stack (a Clerk / Supabase-Auth substitute).
//
// The swap, in one sentence: instead of a shared secret + a 6-digit code, the
// user signs a one-time challenge with their wallet. Consequences:
//   • NO shared secret is ever stored server-side — nothing to phish, leak, or
//     brute-force (a stolen user table has no auth secrets in it).
//   • The signature is over THIS challenge — it is useless if replayed, and it
//     can't be read out over the phone the way an OTP is (the #1 smishing hole).
//   • Enrolling a user = storing their PUBLIC address. That's it.
//
// API is intentionally shaped like otplib so it reads as a mental drop-in:
//   otplib:  generateSecret() · generate(secret) · verify({token, secret})
//   owm:     generateChallenge() · sign(challenge, key) · verify({challenge, signature})
//
// Sessions (the "login timeout") are built in: verify() → createSession()/
// signSession() with a TTL. SSO: this pairs with the OWM-GRANT OIDC bridge
// profile (WM-7 §5.1), which turns a verified wallet signature into a
// standard OIDC id_token for apps that already speak OIDC.

import {
  signPersonalMessage,
  recoverPersonalMessage,
  toChecksumAddress,
} from './eth-sign.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

export const AUTHENTICATOR_DOMAIN = 'owm-authenticator-v1';
export const DEFAULT_CHALLENGE_TTL_S = 120; // the sign-in window
export const DEFAULT_SESSION_TTL_S = 3600; // the login timeout

function nowS() {
  return Math.floor(Date.now() / 1000);
}

function randomHex(bytes = 32) {
  const u = new Uint8Array(bytes);
  (globalThis.crypto || crypto).getRandomValues(u);
  return Array.from(u, (b) => b.toString(16).padStart(2, '0')).join('');
}

// The EXACT bytes the wallet signs — domain-separated and human-readable, so a
// wallet UI shows the user what they're approving (WYSIWYS). The domain tag on
// line 1 means a signature here can never be replayed as some other OWM payload.
export function challengeMessage({ rp, action, challenge, exp }) {
  return [AUTHENTICATOR_DOMAIN, rp, action, challenge, String(exp)].join('\n');
}

// SERVER — mint a one-time challenge. Drop-in for otplib.generateSecret(), but
// per-attempt: you hold it for the short window, not a long-lived shared secret.
export function generateChallenge({ rp, action = 'Sign in', ttlS = DEFAULT_CHALLENGE_TTL_S, now = nowS() } = {}) {
  if (!rp) throw new Error('generateChallenge: `rp` (your app name or domain) is required');
  const challenge = randomHex(32);
  const exp = now + ttlS;
  return { rp, action, challenge, exp, message: challengeMessage({ rp, action, challenge, exp }) };
}

// CLIENT (server/CLI/tests holding a key) — sign the challenge. In a browser the
// wallet signs instead: `await walletClient.signMessage({ message: c.message })`.
export function sign(challenge, privateKey) {
  const message = challenge.message || challengeMessage(challenge);
  return signPersonalMessage(message, privateKey);
}

// SERVER — verify. Drop-in for otplib.verify({token, secret}) → boolean, but
// stronger: returns WHICH address authenticated, with no shared secret involved.
// Pass `expectedAddress` (the enrolled wallet) to bind the check to one user.
export function verify({ challenge, signature, expectedAddress, now = nowS() } = {}) {
  if (!challenge || !signature) return { ok: false, error: 'challenge and signature are required' };
  if (challenge.exp && now > challenge.exp) return { ok: false, error: 'challenge expired' };
  let recovered;
  try {
    recovered = toChecksumAddress(recoverPersonalMessage(challenge.message || challengeMessage(challenge), signature));
  } catch (e) {
    return { ok: false, error: `bad signature: ${e.message}` };
  }
  if (expectedAddress && recovered.toLowerCase() !== String(expectedAddress).toLowerCase()) {
    return { ok: false, error: 'signature valid but not from the enrolled wallet', address: recovered };
  }
  return { ok: true, address: recovered };
}

// ENROLLMENT — replaces the otpauth:// QR + shared secret. Enrolling stores the
// user's PUBLIC address; there is no secret. (Prove control at enrol time by
// running one verify() over an enrol challenge before you store the address.)
export function enroll({ address }) {
  if (!address) throw new Error('enroll: `address` is required');
  return { method: 'owm-wallet', address: toChecksumAddress(address), secret: null };
}

// A deep link a wallet app can open to sign the challenge (the analog of the
// otpauth:// QR you'd scan into an authenticator app).
export function challengeUri({ rp, message }) {
  return `owm://auth?rp=${encodeURIComponent(rp)}&msg=${encodeURIComponent(message)}`;
}

// ── Sessions (the login timeout) ───────────────────────────────────────────
// createSession: a plain, framework-agnostic session object you drop into your
// own store/cookie. `ttlS` IS the login timeout.
export function createSession({ address, ttlS = DEFAULT_SESSION_TTL_S, now = nowS() }) {
  return { address: toChecksumAddress(address), issuedAt: now, expiresAt: now + ttlS };
}
export function sessionValid(session, now = nowS()) {
  return !!session && typeof session.expiresAt === 'number' && now < session.expiresAt;
}

// Stateless signed session token (a Clerk/Supabase-style JWT-lite) — HMAC over a
// hex-encoded payload, so it verifies with no session store. `key` is YOUR server
// secret (string or bytes). `ttlS` is the login timeout.
function keyBytes(key) { return typeof key === 'string' ? utf8ToBytes(key) : key; }
function macHex(body, key) { return bytesToHex(hmac(sha256, keyBytes(key), utf8ToBytes(body))); }
function ctEq(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i += 1) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

export function signSession({ address, ttlS = DEFAULT_SESSION_TTL_S, key, now = nowS() }) {
  if (!key) throw new Error('signSession: a server `key` (string or bytes) is required');
  const payload = { a: toChecksumAddress(address), iat: now, exp: now + ttlS };
  const body = bytesToHex(utf8ToBytes(JSON.stringify(payload)));
  return `${body}.${macHex(body, key)}`;
}
export function verifySession(token, key, now = nowS()) {
  if (typeof token !== 'string' || !token.includes('.')) return { ok: false, error: 'malformed session token' };
  const [body, mac] = token.split('.');
  if (!ctEq(macHex(body, key), mac || '')) return { ok: false, error: 'bad session signature' };
  let payload;
  try { payload = JSON.parse(new TextDecoder().decode(hexToBytes(body))); } catch { return { ok: false, error: 'bad session payload' }; }
  if (now >= payload.exp) return { ok: false, error: 'session expired', address: payload.a };
  return { ok: true, address: payload.a, issuedAt: payload.iat, expiresAt: payload.exp };
}

// otplib-style convenience object.
export const walletAuthenticator = {
  generateChallenge, sign, verify, enroll, challengeUri, challengeMessage,
  createSession, sessionValid, signSession, verifySession,
};
