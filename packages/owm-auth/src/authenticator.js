// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OwmAuthenticator — the reference WALLET side of WM-7, used by tests,
// demos, and (later) the React Native app. Holds either a single private
// key or a seed from which one sub-key per RP is derived
// (deriveRpSubKey: keccak(seed || rp) → scalar — a documented PLACEHOLDER
// for BIP-32 hardened derivation; see WM-7 §5). With a seed, the primary
// address never appears: every RP sees its own address, exactly as
// passkeys mint a keypair per site.
//
// A real wallet wraps these calls in device unlock + WYSIWYS rendering of
// rp/action/scope. This class is the protocol half only.

import {
  signAuthResponse, signGrant, signGrantRevoke, computeGrantId,
  deriveRpSubKey, addressFromPrivateKey, buildScxAbort, parseMessage,
} from '@open-wallet-messaging/core';

/**
 * Reference WALLET side of WM-7: answers auth challenges, approves grant
 * requests, and revokes grants. Single-key mode (`privateKey`) or per-RP
 * sub-key mode (`seed` — one address per relying party, like passkeys).
 *
 * @example
 * const wallet = new OwmAuthenticator({ seed: 'a1'.repeat(16) });
 * const response = wallet.handleAuthChallenge(challengeEnvelope, {
 *   matchCode: '42',   // the digits the user typed from the initiating screen
 * });
 */
export class OwmAuthenticator {
  #privateKey = null;
  #seed = null;
  #grants = new Map(); // grantId -> { rp } : grants this wallet approved

  /**
   * @param {object} opts Exactly one of:
   * @param {string|Uint8Array} [opts.privateKey] 32-byte secp256k1 key (single-key mode).
   * @param {string|Uint8Array} [opts.seed] >= 16-byte seed (per-RP sub-key mode).
   * @throws {Error} When both or neither are supplied.
   */
  constructor({ privateKey, seed } = {}) {
    if ((privateKey === undefined) === (seed === undefined)) {
      throw new Error('exactly one of privateKey (single-key mode) or seed (per-RP mode) required');
    }
    if (privateKey !== undefined) this.#privateKey = privateKey;
    else this.#seed = seed;
  }

  /**
   * The signing key used for a relying party (the single key, or the
   * derived per-RP sub-key in seed mode).
   * @param {string} rp
   * @returns {string} 64-hex private key.
   */
  keyFor(rp) {
    return this.#privateKey ?? deriveRpSubKey(this.#seed, rp);
  }

  /**
   * The address this wallet presents to a relying party.
   * @param {string} rp
   * @returns {string} 0x-prefixed lowercase address.
   */
  addressFor(rp) {
    return addressFromPrivateKey(this.keyFor(rp));
  }

  #requireKind(envelope, kind) {
    const parsed = parseMessage(typeof envelope === 'string' ? envelope : JSON.stringify(envelope));
    if (!parsed.ok || parsed.kind !== kind) {
      throw new Error(`expected a strictly valid ${kind} envelope${parsed.error ? `: ${parsed.error}` : ''}`);
    }
    return parsed.body;
  }

  /**
   * Respond to a wm-auth-challenge (530). The matchCode is what the USER
   * TYPED from the initiating screen — it never arrived on the wire.
   * `approve: false` (or an expired challenge) yields the terminal
   * scx-abort rejection instead of a signature.
   * @param {object|string} envelope The challenge (object or JSON string).
   * @param {object} [opts]
   * @param {string} [opts.matchCode] 1–8 digits the user typed (required when approving).
   * @param {boolean} [opts.approve=true] false → scx-abort('declined').
   * @param {string} [opts.binding] Strict-mode override obtained out-of-band.
   * @param {number} [opts.now] Unix ms (for tests).
   * @returns {object} wm-auth-response (531) or scx-abort (514).
   * @throws {Error} On a malformed challenge or a missing/invalid matchCode.
   */
  handleAuthChallenge(envelope, { matchCode, approve = true, binding, now = Date.now() } = {}) {
    const env = this.#requireKind(envelope, 'wm-auth-challenge');
    if (!approve) return buildScxAbort({ reason: 'declined' });
    if (Math.floor(now / 1000) > env.exp) return buildScxAbort({ reason: 'timeout' });
    if (typeof matchCode !== 'string' || !/^[0-9]{1,8}$/.test(matchCode)) {
      throw new Error('matchCode (the digits the user typed) required');
    }
    return signAuthResponse({
      privateKey: this.keyFor(env.rp), challenge: env, match: matchCode, binding,
    });
  }

  /**
   * Approve a wm-grant-request (532) → signed wm-grant (533), echoing the
   * request fields verbatim (what the user saw is what gets signed).
   * @param {object|string} envelope The grant request (object or JSON string).
   * @param {object} [opts]
   * @param {boolean} [opts.approve=true] false → scx-abort('declined').
   * @returns {object} wm-grant (533) or scx-abort (514).
   * @throws {Error} On a malformed request envelope.
   */
  approveGrantRequest(envelope, { approve = true } = {}) {
    const env = this.#requireKind(envelope, 'wm-grant-request');
    if (!approve) return buildScxAbort({ reason: 'declined' });
    const { rp, client, scope, aud, nonce, iat, exp } = env;
    const grant = signGrant({ privateKey: this.keyFor(rp), rp, client, scope, aud, nonce, iat, exp });
    this.#grants.set(computeGrantId({ rp, client, scope, aud, nonce, iat, exp }), { rp });
    return grant;
  }

  /**
   * Revoke a previously approved grant → wm-grant-revoke (534). For grants
   * this instance approved, the RP (and thus the signing sub-key) is
   * remembered; otherwise pass `{ rp }` (seed mode needs it to re-derive).
   * @param {string} grantId 64-hex grant id (SHA-256 of the canonical grant string).
   * @param {object} [opts]
   * @param {string} [opts.rp] Relying party, when this instance didn't approve the grant.
   * @param {number} [opts.now] Unix ms (for tests).
   * @returns {object} wm-grant-revoke (534).
   * @throws {Error} In seed mode when the rp cannot be determined.
   */
  revokeGrant(grantId, { rp, now = Date.now() } = {}) {
    const knownRp = rp ?? this.#grants.get(grantId)?.rp;
    if (this.#privateKey === null && knownRp === undefined) {
      throw new Error('rp required to derive the signing key for an unknown grantId');
    }
    const key = this.#privateKey ?? deriveRpSubKey(this.#seed, knownRp);
    return signGrantRevoke({ privateKey: key, grantId, ts: Math.floor(now / 1000) });
  }
}
