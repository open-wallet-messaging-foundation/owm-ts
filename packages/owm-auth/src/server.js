// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OwmAuthServer — the relying-party side of OWM-AUTH (WM-7 §3).
//
// Enrollment pins a wallet address to a userId (SCX card or in-session
// proof-of-possession — NEVER a pasted address). Each auth attempt is:
// createChallenge() → show the returned 2-digit match code on the
// INITIATING screen, send the envelope to the wallet E2EE → the user types
// the code into the wallet, signs → verifyResponse(). The match code never
// rides the challenge (number-ENTRY: a victim who never saw a code cannot
// approve an unsolicited prompt).
//
// Single-use nonces: every verification attempt burns the challenge,
// success or failure. Per-user lockout after `maxFailures`
// failures/rejections fires `onSecurityAlert` once and blocks further
// challenges until unlockUser().

import {
  buildAuthChallenge, verifyAuthResponse, verifyContactCard, parseMessage,
  canonicalAuthPayload,
} from '@open-wallet-messaging/core';
import { randomInt } from 'node:crypto';
import { MemoryChallengeStore, MemoryEnrollmentStore } from './stores.js';

/** Default number of failed/declined attempts before a user is locked out. */
export const DEFAULT_MAX_FAILURES = 5;
const ENROLL_ACTION = 'enroll this wallet as your second factor';

/**
 * Relying-party (server) side of OWM-AUTH (WM-7 §3): pins one wallet
 * address per user at enrollment, mints single-use challenges, verifies
 * signed responses, and enforces per-user lockout.
 *
 * @example
 * const server = new OwmAuthServer({ rp: 'example.org' });
 * const { envelope, matchCode, challengeId } =
 *   await server.createChallenge({ userId: 'u1', action: 'log in' });
 * // 1. show matchCode on the initiating screen
 * // 2. send envelope to the enrolled wallet over your transport
 * // 3. verify whatever comes back:
 * const result = await server.verifyResponse(walletReply);
 */
export class OwmAuthServer {
  #rp; #challenges; #enrollments; #maxFailures; #ttlS; #matchDigits;
  #onSecurityAlert; #clock; #verifier;
  // Failure/lock ledger for users with no enrollment record yet (enrollment
  //-phase failures). Once enrolled, lock state lives in the enrollment
  // record so pluggable stores persist it.
  #preEnrollLocks = new Map();

  /**
   * @param {object} opts
   * @param {string} opts.rp Relying-party identifier (e.g. your domain). Required.
   * @param {object} [opts.challengeStore] Async `get/put/delete` keyed by challenge id (default in-memory).
   * @param {object} [opts.enrollmentStore] Async `get/put/delete` keyed by userId (default in-memory).
   * @param {number} [opts.maxFailures=5] Failures/declines before lockout (integer >= 1).
   * @param {number} [opts.ttlS=120] Challenge lifetime in seconds (WM-7 ceiling: 120).
   * @param {number} [opts.matchDigits=2] Match-code length, 2..8 digits.
   * @param {?Function} [opts.onSecurityAlert] Called once on lockout with `{ rp, userId, failures, reason }`.
   * @param {Function} [opts.clock] `() => unix ms` — inject a fake clock in tests.
   * @param {?object} [opts.verifier] Optional chain verifier from
   *   `createChainVerifier` — enables ERC-1271/6492 smart-contract-wallet
   *   signatures. Consulted ONLY after EOA recovery fails; without it,
   *   behaviour is exactly the EOA-only default. See erc1271.js for the
   *   RPC trust note.
   * @throws {Error} When rp is missing or maxFailures / matchDigits are out of range.
   */
  constructor({
    rp,
    challengeStore = new MemoryChallengeStore(),
    enrollmentStore = new MemoryEnrollmentStore(),
    maxFailures = DEFAULT_MAX_FAILURES,
    ttlS = 120,
    matchDigits = 2,
    onSecurityAlert = null,
    clock = () => Date.now(),
    verifier = null,
  } = {}) {
    if (typeof rp !== 'string' || rp.length === 0) throw new Error('rp required');
    if (!Number.isInteger(maxFailures) || maxFailures < 1) throw new Error('maxFailures must be >= 1');
    if (!Number.isInteger(matchDigits) || matchDigits < 2 || matchDigits > 8) throw new Error('matchDigits must be 2..8');
    this.#rp = rp;
    this.#challenges = challengeStore;
    this.#enrollments = enrollmentStore;
    this.#maxFailures = maxFailures;
    this.#ttlS = ttlS;
    this.#matchDigits = matchDigits;
    this.#onSecurityAlert = onSecurityAlert;
    this.#clock = clock;
    this.#verifier = verifier;
  }

  /** @returns {string} The relying-party identifier this server enforces. */
  get rp() { return this.#rp; }

  // Crypto-random, zero-padded ("00".."99" for the 2-digit default).
  #newMatchCode() {
    return String(randomInt(0, 10 ** this.#matchDigits)).padStart(this.#matchDigits, '0');
  }

  async #lockState(userId) {
    const enr = await this.#enrollments.get(userId);
    if (enr) return { enr, failures: enr.failures ?? 0, locked: enr.locked === true };
    const pre = this.#preEnrollLocks.get(userId) ?? { failures: 0, locked: false };
    return { enr: null, failures: pre.failures, locked: pre.locked };
  }

  async #recordFailure(userId) {
    const { enr, failures } = await this.#lockState(userId);
    const next = failures + 1;
    const locked = next >= this.#maxFailures;
    if (enr) {
      await this.#enrollments.put(userId, { ...enr, failures: next, locked: locked || enr.locked === true });
    } else {
      this.#preEnrollLocks.set(userId, { failures: next, locked });
    }
    if (locked) {
      try {
        await this.#onSecurityAlert?.({ rp: this.#rp, userId, failures: next, reason: 'lockout' });
      } catch { /* alert hooks must never break verification */ }
    }
    return { failures: next, locked };
  }

  async #clearFailures(userId) {
    const enr = await this.#enrollments.get(userId);
    if (enr && (enr.failures ?? 0) > 0) await this.#enrollments.put(userId, { ...enr, failures: 0 });
    this.#preEnrollLocks.delete(userId);
  }

  /**
   * Whether the user is currently locked out.
   * @param {string} userId
   * @returns {Promise<boolean>}
   */
  async isLocked(userId) { return (await this.#lockState(userId)).locked; }

  /**
   * Clear a user's lock and failure counter (support-desk path).
   * @param {string} userId
   * @returns {Promise<void>}
   */
  async unlockUser(userId) {
    const enr = await this.#enrollments.get(userId);
    if (enr) await this.#enrollments.put(userId, { ...enr, failures: 0, locked: false });
    this.#preEnrollLocks.delete(userId);
  }

  /**
   * The stored enrollment record for a user, or null.
   * @param {string} userId
   * @returns {Promise<?object>} `{ address, enrolledVia, enrolledAt, failures, locked, ... }`
   */
  async getEnrollment(userId) { return this.#enrollments.get(userId); }

  // --- enrollment -----------------------------------------------------------

  /**
   * Start in-session proof-of-possession enrollment: the same ceremony as
   * an auth challenge, but no address is pinned yet — verifyEnrollmentProof
   * pins whatever address validly signs. MUST only be offered inside an
   * already-authenticated session (WM-7 §3.1).
   * @param {object} opts
   * @param {string} opts.userId
   * @param {string} [opts.action] Human-readable prompt (default: enrollment wording).
   * @returns {Promise<{envelope: object, matchCode: string, challengeId: string}>}
   * @throws {Error} When userId is missing or the user is locked.
   */
  async createEnrollmentChallenge({ userId, action = ENROLL_ACTION } = {}) {
    if (!userId) throw new Error('userId required');
    if ((await this.#lockState(userId)).locked) throw new Error(`user locked: ${userId}`);
    const envelope = buildAuthChallenge({ rp: this.#rp, action, now: this.#clock(), ttlS: this.#ttlS });
    const matchCode = this.#newMatchCode();
    await this.#challenges.put(envelope.challenge, {
      phase: 'enroll', userId, action, matchCode, exp: envelope.exp,
    });
    return { envelope, matchCode, challengeId: envelope.challenge };
  }

  /**
   * Verify an enrollment proof (wm-auth-response 531) and pin the signing
   * address to the challenged userId.
   * @param {object} envelope The wallet's wm-auth-response (or scx-abort decline).
   * @param {object} [opts]
   * @param {string} [opts.matchCode] Override the stored expected code.
   * @returns {Promise<{ok: true, userId: string, address: string, action: string}
   *                   | {ok: false, reason: string, locked?: boolean}>}
   */
  async verifyEnrollmentProof(envelope, { matchCode } = {}) {
    const res = await this.#verify(envelope, { matchCode, phase: 'enroll' });
    if (!res.ok) return res;
    await this.#enrollments.put(res.userId, {
      address: res.address, enrolledVia: 'challenge-proof', enrolledAt: this.#clock(), failures: 0, locked: false,
    });
    this.#preEnrollLocks.delete(res.userId);
    return res;
  }

  /**
   * SCX enrollment: pin the address from a contact card exchanged over a
   * WM-3 ceremony. The card's signature is bound to THAT ceremony's
   * transcript, so a card from any other exchange fails here.
   * @param {object} opts
   * @param {string} opts.userId
   * @param {object} opts.card The wm-contact-card received during SCX.
   * @param {string} opts.transcriptHash YOUR side's transcript hash (64 hex).
   * @returns {Promise<{ok: true, userId: string, address: string}
   *                   | {ok: false, reason: string, error?: string}>}
   */
  async acceptScxCard({ userId, card, transcriptHash }) {
    if (!userId) throw new Error('userId required');
    const res = verifyContactCard(card, transcriptHash);
    if (!res.ok) return { ok: false, reason: 'bad-card-signature', error: res.error };
    await this.#enrollments.put(userId, {
      address: res.address, inboxId: card.inboxId, enrolledVia: 'scx', enrolledAt: this.#clock(), failures: 0, locked: false,
    });
    return { ok: true, userId, address: res.address };
  }

  // --- the ceremony -----------------------------------------------------------

  /**
   * Mint a single-use auth/step-up challenge for an enrolled user.
   * Display `matchCode` on the initiating screen; send `envelope` to the
   * wallet E2EE. The match code never rides the envelope (number-entry).
   * @param {object} opts
   * @param {string} opts.userId
   * @param {string} opts.action Human-readable, signed verbatim (1–140 chars, no newlines).
   * @param {string} [opts.binding] Strict-mode session binding (WM-7 §6).
   * @returns {Promise<{envelope: object, matchCode: string, challengeId: string}>}
   * @throws {Error} When the user is not enrolled or is locked.
   */
  async createChallenge({ userId, action, binding } = {}) {
    if (!userId) throw new Error('userId required');
    if (typeof action !== 'string' || action.length === 0) throw new Error('action required');
    const { enr, locked } = await this.#lockState(userId);
    if (!enr) throw new Error(`user not enrolled: ${userId}`);
    if (locked) throw new Error(`user locked: ${userId}`);
    const envelope = buildAuthChallenge({ rp: this.#rp, action, binding, now: this.#clock(), ttlS: this.#ttlS });
    const matchCode = this.#newMatchCode();
    await this.#challenges.put(envelope.challenge, {
      phase: 'auth', userId, action, binding, matchCode, exp: envelope.exp,
    });
    return { envelope, matchCode, challengeId: envelope.challenge };
  }

  /**
   * Verify a wallet reply. Accepts a wm-auth-response (531) or an
   * scx-abort decline (the wallet's "no"). Aborts carry no challenge id,
   * so pass `{ challengeId }` from the transport context in that case.
   * Every attempt burns the challenge, success or failure.
   * @param {object} envelope Parsed envelope object (not a JSON string).
   * @param {object} [opts]
   * @param {string} [opts.matchCode] Override the stored expected code
   *   (e.g. the initiating screen kept it rather than the server).
   * @param {string} [opts.challengeId] Required for scx-abort inputs.
   * @returns {Promise<{ok: true, userId: string, address: string, action: string}
   *                   | {ok: false, reason: string, userId?: string, locked?: boolean}>}
   *   Failure reasons: 'bad-envelope' | 'unknown-challenge' | 'declined' |
   *   'locked' | 'not-enrolled' | 'challenge-mismatch' | 'expired' |
   *   'match-mismatch' | 'bad-signature' | 'wrong-address'.
   */
  async verifyResponse(envelope, opts = {}) {
    return this.#verify(envelope, { ...opts, phase: 'auth' });
  }

  async #verify(envelope, { matchCode, challengeId, phase }) {
    // Wallet declined? Burn + count as a rejection (MFA-bombing defence).
    if (envelope && envelope._kind === 'scx-abort') {
      const id = challengeId;
      const rec = id ? await this.#challenges.get(id) : null;
      if (!rec || rec.phase !== phase) return { ok: false, reason: 'unknown-challenge' };
      await this.#challenges.delete(id);
      const { locked } = await this.#recordFailure(rec.userId);
      return { ok: false, reason: 'declined', userId: rec.userId, locked };
    }

    const parsed = parseMessage(JSON.stringify(envelope));
    if (!parsed.ok || parsed.kind !== 'wm-auth-response') {
      return { ok: false, reason: 'bad-envelope', error: parsed.error };
    }
    const rec = await this.#challenges.get(parsed.body.challenge);
    if (!rec || rec.phase !== phase) return { ok: false, reason: 'unknown-challenge' }; // replay or never issued
    await this.#challenges.delete(parsed.body.challenge); // single-use: burn NOW, any outcome

    const { enr, locked } = await this.#lockState(rec.userId);
    if (locked) return { ok: false, reason: 'locked', userId: rec.userId };
    if (phase === 'auth' && !enr) return { ok: false, reason: 'not-enrolled', userId: rec.userId };

    let res = verifyAuthResponse(parsed.body, {
      rp: this.#rp,
      action: rec.action,
      challenge: parsed.body.challenge,
      match: matchCode ?? rec.matchCode,
      binding: rec.binding,
      exp: rec.exp,
      enrolledAddress: phase === 'auth' ? enr.address : undefined,
      now: this.#clock(),
    });
    // ERC-1271/6492 fallback (WM-7 §8): only with a configured verifier,
    // only after EOA recovery failed (every pre-signature check — nonce,
    // expiry, match code — already passed), and always fail closed.
    if (!res.ok && res.reason === 'bad-signature' && this.#verifier) {
      res = await this.#verifyViaChain(parsed.body, rec, matchCode, enr, phase);
    }
    if (!res.ok) {
      const { locked: nowLocked } = await this.#recordFailure(rec.userId);
      return { ok: false, reason: res.reason, userId: rec.userId, locked: nowLocked };
    }
    await this.#clearFailures(rec.userId);
    return { ok: true, userId: rec.userId, address: res.address, action: rec.action };
  }

  // Smart-contract-wallet path: rebuild the canonical string from SERVER
  // state (never from the envelope) and ask the injected verifier. The
  // claimed signer is the envelope's addr — for phase 'auth' it must
  // still be the enrolled address. Any verifier failure or throw
  // collapses to the same 'bad-signature' the EOA path yields.
  async #verifyViaChain(body, rec, matchCode, enr, phase) {
    try {
      const payload = canonicalAuthPayload({
        rp: this.#rp,
        action: rec.action,
        challenge: body.challenge,
        match: matchCode ?? rec.matchCode,
        binding: rec.binding,
        exp: rec.exp,
      });
      const v = await this.#verifier.verifySignature({ address: body.addr, payload, signature: body.sig });
      if (!v.ok) return { ok: false, reason: 'bad-signature' };
      const address = body.addr.toLowerCase();
      if (phase === 'auth' && enr && address !== enr.address.toLowerCase()) {
        return { ok: false, reason: 'wrong-address' };
      }
      return { ok: true, address };
    } catch {
      return { ok: false, reason: 'bad-signature' }; // fail closed
    }
  }
}
