// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// GrantServer — the relying-party / resource-server side of OWM-GRANT
// (WM-7 §4). A grant is a signed capability, verified OFFLINE (no token
// endpoint, no client secret). The OAuth trade-off is preserved honestly:
// offline verification is bounded by exp, so grants carry a short exp by
// default, and any grant whose LIFETIME (exp - iat) exceeds
// `longExpThresholdS` REQUIRES a grant registry — verifyGrant fails closed
// without one. Revocation (wm-grant-revoke, signed by the granting key)
// wins over everything.

import {
  buildWmGrantRequest, randomNonce, parseMessage,
  verifyGrant as coreVerifyGrant, verifyGrantRevoke,
  canonicalGrantPayload, canonicalGrantRevokePayload, computeGrantId,
} from '@open-wallet-messaging/core';
import { MemoryGrantRegistry } from './stores.js';

export { MemoryGrantRegistry };

/**
 * Relying-party / resource-server side of OWM-GRANT (WM-7 §4): request,
 * accept, verify (offline), and revoke wallet-signed capability grants.
 *
 * @example
 * const grants = new GrantServer({ rp: 'example.org', aud: 'api.example.org' });
 * const request = grants.buildGrantRequest({ client: 'shiny-app', scope: 'read:balance' });
 * // wallet renders + approves the request, returns a signed wm-grant…
 * const res = await grants.acceptGrant(signedGrant);
 * if (res.ok) console.log(res.grantId, res.scope);
 */
export class GrantServer {
  #rp; #aud; #registry; #defaultTtlS; #longExpThresholdS; #clock; #verifier;
  #pendingNonces = new Map(); // nonce -> { exp (unix s) } : requests we issued

  /**
   * @param {object} opts
   * @param {string} opts.rp Relying-party identifier. Required.
   * @param {string} opts.aud This resource server's audience identifier. Required.
   * @param {?object} [opts.registry] Grant registry (async `get/put/revoke/isRevoked`).
   *   Required for revocation and for grants living longer than `longExpThresholdS`.
   * @param {number} [opts.defaultTtlS=900] Default grant lifetime (15 min).
   * @param {number} [opts.longExpThresholdS=3600] Lifetimes above this fail without a registry.
   * @param {Function} [opts.clock] `() => unix ms` — inject a fake clock in tests.
   * @param {?object} [opts.verifier] Optional chain verifier from
   *   `createChainVerifier` — enables ERC-1271/6492 smart-contract-wallet
   *   signatures on grants and revokes. Consulted ONLY after EOA recovery
   *   fails; fail closed. See erc1271.js for the RPC trust note.
   * @throws {Error} When rp or aud is missing.
   */
  constructor({
    rp,
    aud,
    registry = null,
    defaultTtlS = 900, // 15 min — short-exp default
    longExpThresholdS = 3600, // grants living longer than 1 h need the registry
    clock = () => Date.now(),
    verifier = null,
  } = {}) {
    if (typeof rp !== 'string' || rp.length === 0) throw new Error('rp required');
    if (typeof aud !== 'string' || aud.length === 0) throw new Error('aud required');
    this.#rp = rp;
    this.#aud = aud;
    this.#registry = registry;
    this.#defaultTtlS = defaultTtlS;
    this.#longExpThresholdS = longExpThresholdS;
    this.#clock = clock;
    this.#verifier = verifier;
  }

  /** @returns {string} The relying-party identifier. */
  get rp() { return this.#rp; }

  /** @returns {string} The audience identifier this server verifies against. */
  get aud() { return this.#aud; }

  /**
   * Build a wm-grant-request (532) for the wallet to render verbatim
   * (WYSIWYS consent). The nonce is remembered so only grants answering a
   * request WE sent are accepted at issuance (acceptGrant), single-use.
   * @param {object} opts
   * @param {string} opts.client Human-readable client name (rendered to the user).
   * @param {string} opts.scope Space-separated scope tokens (<= 512 chars).
   * @param {string} [opts.aud] Audience (defaults to this server's aud).
   * @param {number} [opts.ttlS] Requested lifetime in seconds (default: defaultTtlS).
   * @returns {object} The wm-grant-request envelope.
   */
  buildGrantRequest({ client, scope, aud = this.#aud, ttlS = this.#defaultTtlS } = {}) {
    const iat = Math.floor(this.#clock() / 1000);
    const nonce = randomNonce(32);
    const envelope = buildWmGrantRequest({
      rp: this.#rp, client, scope, aud, nonce, iat, exp: iat + ttlS,
    });
    this.#pendingNonces.set(nonce, { exp: envelope.exp });
    return envelope;
  }

  /**
   * Issuance-time acceptance: the grant must answer an outstanding request
   * (single-use nonce, burned on success) and verify fully; on success it
   * is registered in the registry (when configured).
   * @param {object} grantEnvelope The signed wm-grant (533).
   * @param {object} [opts]
   * @param {string} [opts.expectedAddress] Pin the granting per-RP address.
   * @returns {Promise<{ok: true, grantId: string, address: string, client: string,
   *   scope: string, exp: number} | {ok: false, reason: string}>}
   */
  async acceptGrant(grantEnvelope, { expectedAddress } = {}) {
    const nonce = grantEnvelope?.nonce;
    if (!nonce || !this.#pendingNonces.has(nonce)) return { ok: false, reason: 'unknown-nonce' };
    const res = await this.verifyGrant(grantEnvelope, { expectedAddress });
    if (res.ok) this.#pendingNonces.delete(nonce); // burn only on success: a garbled reply must not kill the request
    return res;
  }

  /**
   * Presentation-time verification, fully OFFLINE: signature chain + exp +
   * aud (+ rp) + long-exp registry rule + revocation.
   * @param {object} grantEnvelope The signed wm-grant (533).
   * @param {object} [opts]
   * @param {string} [opts.expectedAddress] Pin the granting per-RP address.
   * @param {number} [opts.now] Unix ms (defaults to the injected clock).
   * @returns {Promise<{ok: true, grantId: string, address: string, client: string,
   *   scope: string, exp: number} | {ok: false, reason: string}>}
   *   Failure reasons: 'bad-signature' | 'wrong-address' | 'expired' |
   *   'aud-mismatch' | 'rp-mismatch' | 'long-exp-requires-registry' | 'revoked'.
   */
  async verifyGrant(grantEnvelope, { expectedAddress, now = this.#clock() } = {}) {
    const parsed = parseMessage(JSON.stringify(grantEnvelope));
    if (!parsed.ok || parsed.kind !== 'wm-grant') return { ok: false, reason: 'bad-signature', error: parsed.error };
    const env = parsed.body;
    let res = coreVerifyGrant(env, { now, expectedAddress });
    // ERC-1271/6492 fallback (WM-7 §8): only with a configured verifier,
    // only after EOA recovery failed. The chain path re-runs the checks
    // core sequences AFTER its signature check (address pin, expiry).
    if (!res.ok && res.reason === 'bad-signature' && this.#verifier) {
      res = await this.#verifyGrantViaChain(env, { expectedAddress, now });
    }
    if (!res.ok) return res;
    if (env.aud !== this.#aud) return { ok: false, reason: 'aud-mismatch' };
    if (env.rp !== this.#rp) return { ok: false, reason: 'rp-mismatch' };
    if (env.exp - env.iat > this.#longExpThresholdS && !this.#registry) {
      return { ok: false, reason: 'long-exp-requires-registry' };
    }
    if (this.#registry) {
      if (await this.#registry.isRevoked(res.grantId)) return { ok: false, reason: 'revoked' };
      if (!(await this.#registry.get(res.grantId))) {
        await this.#registry.put(res.grantId, { addr: res.address, exp: env.exp, envelope: env });
      }
    }
    return {
      ok: true,
      grantId: res.grantId,
      address: res.address,
      client: env.client,
      scope: env.scope,
      exp: env.exp,
    };
  }

  /**
   * Process a wm-grant-revoke (534): only the key that signed the grant may
   * revoke it. Requires a registry (revocation state must live somewhere).
   * @param {object} revokeEnvelope The signed wm-grant-revoke.
   * @returns {Promise<{ok: true, grantId: string} | {ok: false, reason: string}>}
   *   Failure reasons: 'no-registry' | 'bad-signature' | 'unknown-grant' | 'wrong-address'.
   */
  async revoke(revokeEnvelope) {
    if (!this.#registry) return { ok: false, reason: 'no-registry' };
    const parsed = parseMessage(JSON.stringify(revokeEnvelope));
    if (!parsed.ok || parsed.kind !== 'wm-grant-revoke') return { ok: false, reason: 'bad-signature', error: parsed.error };
    const env = parsed.body;
    const rec = await this.#registry.get(env.grantId);
    if (!rec) return { ok: false, reason: 'unknown-grant' };
    let res = verifyGrantRevoke(env, { expectedAddress: rec.addr });
    // A contract-granted grant is revoked by a contract signature: the
    // owner key's EOA recovery yields 'wrong-address' (or garbage yields
    // 'bad-signature') — retry against the GRANTING address via ERC-1271.
    if (!res.ok && this.#verifier && (res.reason === 'bad-signature' || res.reason === 'wrong-address')) {
      try {
        const payload = canonicalGrantRevokePayload({ grantId: env.grantId, ts: env.ts });
        const v = await this.#verifier.verifySignature({ address: rec.addr, payload, signature: env.sig });
        if (v.ok) res = { ok: true, address: rec.addr.toLowerCase() };
      } catch { /* fail closed: keep the EOA failure */ }
    }
    if (!res.ok) return res;
    await this.#registry.revoke(env.grantId);
    return { ok: true, grantId: env.grantId };
  }

  // Smart-contract-wallet path for wm-grant: verify env.sig for env.addr
  // via the injected verifier, then re-apply the post-signature checks
  // core would have run (expected address pin, expiry). Fail closed on
  // any throw.
  async #verifyGrantViaChain(env, { expectedAddress, now }) {
    try {
      const { rp, client, scope, aud, nonce, iat, exp } = env;
      const payload = canonicalGrantPayload({ rp, client, scope, aud, nonce, iat, exp });
      const v = await this.#verifier.verifySignature({ address: env.addr, payload, signature: env.sig });
      if (!v.ok) return { ok: false, reason: 'bad-signature' };
      const address = env.addr.toLowerCase();
      if (expectedAddress !== undefined && address !== expectedAddress.toLowerCase()) {
        return { ok: false, reason: 'wrong-address' };
      }
      if (Math.floor(now / 1000) > exp) return { ok: false, reason: 'expired' };
      return { ok: true, address, grantId: computeGrantId({ rp, client, scope, aud, nonce, iat, exp }) };
    } catch {
      return { ok: false, reason: 'bad-signature' }; // fail closed
    }
  }
}
