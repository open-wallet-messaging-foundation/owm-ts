// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// TwoFactor — the speakeasy/otplib migration seam over the WM-7 §3 ceremony.
//
// Honest framing: OWM-AUTH is challenge-push-sign, not code-entry, so the
// drop-in is at the VERIFICATION SEAM, not the API signature. Where a TOTP
// deployment did
//
//     if (!totp.verify({ token: userInput, secret })) reject();
//
// an OWM deployment does
//
//     const { challengeId, matchCode, envelope } = await twoFactor.request(userId);
//     // show matchCode on the initiating screen; send envelope to the
//     // wallet E2EE (XMTP transport, out of scope here)
//     await twoFactor.awaitApproval(challengeId, { timeoutMs: 60000 });
//
// with the transport feeding wallet replies into twoFactor.submit(). The
// server stores a public address instead of a shared secret: a database
// breach no longer breaks the second factor.

/**
 * The `totp.verify()` call-site replacement: request a challenge, await
 * approval as a promise, feed wallet replies in via `submit()`.
 *
 * @example
 * const twoFactor = new TwoFactor({ server });
 * const { challengeId, matchCode, envelope } = await twoFactor.request('u1');
 * // show matchCode on the login screen; send envelope to the wallet;
 * // feed wallet replies into twoFactor.submit(reply)
 * await twoFactor.awaitApproval(challengeId, { timeoutMs: 60_000 });
 */
export class TwoFactor {
  #server;
  #defaultAction;
  #pending = new Map(); // challengeId -> { userId, promise, resolve, reject, timer, settled }

  /**
   * @param {object} opts
   * @param {OwmAuthServer} opts.server The enrolled OwmAuthServer. Required.
   * @param {string} [opts.defaultAction='log in'] Action text used by request() by default.
   */
  constructor({ server, defaultAction = 'log in' } = {}) {
    if (!server) throw new Error('server (OwmAuthServer) required');
    this.#server = server;
    this.#defaultAction = defaultAction;
  }

  /**
   * Start a 2FA ceremony. Display matchCode on the initiating screen;
   * deliver envelope to the enrolled wallet over your transport.
   * @param {string} userId
   * @param {string} [action] Human-readable action (default: the constructor's defaultAction).
   * @param {object} [opts]
   * @param {string} [opts.binding] Strict-mode session binding.
   * @returns {Promise<{challengeId: string, matchCode: string, envelope: object}>}
   * @throws {Error} When the user is not enrolled or is locked.
   */
  async request(userId, action = this.#defaultAction, { binding } = {}) {
    const { envelope, matchCode, challengeId } = await this.#server.createChallenge({ userId, action, binding });
    const entry = { userId, settled: false, timer: null };
    entry.promise = new Promise((resolve, reject) => {
      entry.resolve = resolve;
      entry.reject = reject;
    });
    entry.promise.catch(() => {}); // settled before awaitApproval attaches must not crash the process
    this.#pending.set(challengeId, entry);
    return { challengeId, matchCode, envelope };
  }

  #settle(challengeId, entry, fn) {
    entry.settled = true;
    if (entry.timer) clearTimeout(entry.timer);
    this.#pending.delete(challengeId);
    fn();
  }

  /**
   * Transport callback: feed every wallet reply (wm-auth-response 531 or
   * scx-abort decline) in here. For declines pass challengeId (aborts
   * carry no nonce). Settles the matching awaitApproval() promise.
   * @param {object} envelope The wallet's reply envelope.
   * @param {object} [opts]
   * @param {string} [opts.challengeId] Required for scx-abort declines.
   * @returns {Promise<object>} The raw verification result from OwmAuthServer.
   */
  async submit(envelope, { challengeId } = {}) {
    const id = challengeId ?? envelope?.challenge;
    const result = await this.#server.verifyResponse(envelope, { challengeId: id });
    const entry = id !== undefined ? this.#pending.get(id) : undefined;
    if (entry && !entry.settled) {
      if (result.ok) {
        this.#settle(id, entry, () => entry.resolve({ ok: true, userId: result.userId, address: result.address }));
      } else {
        this.#settle(id, entry, () => entry.reject(
          Object.assign(new Error(`owm-auth: ${result.reason}`), { reason: result.reason, userId: entry.userId, locked: result.locked === true }),
        ));
      }
    }
    return result;
  }

  /**
   * Await the outcome of a ceremony started with request(). Resolves
   * `{ ok: true, userId, address }` on approval; REJECTS (Error with
   * `.reason`, and `.locked` when applicable) on timeout, lockout,
   * decline, or any failed verification — every attempt burns the
   * challenge, so a failure is terminal for this ceremony.
   * @param {string} challengeId From request().
   * @param {object} [opts]
   * @param {number} [opts.timeoutMs=120000] Reject with reason 'timeout' after this long.
   * @returns {Promise<{ok: true, userId: string, address: string}>}
   */
  awaitApproval(challengeId, { timeoutMs = 120000 } = {}) {
    const entry = this.#pending.get(challengeId);
    if (!entry) {
      return Promise.reject(Object.assign(new Error('unknown or already-settled challengeId'), { reason: 'unknown-challenge' }));
    }
    if (!entry.timer) {
      entry.timer = setTimeout(() => {
        if (!entry.settled) {
          this.#settle(challengeId, entry, () => entry.reject(
            Object.assign(new Error('owm-auth: timeout'), { reason: 'timeout', userId: entry.userId }),
          ));
        }
      }, timeoutMs);
      entry.timer.unref?.();
    }
    return entry.promise;
  }
}
