// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// Pluggable storage interfaces (all methods async so real backends drop
// straight in) + in-memory reference implementations.
//
//   ChallengeStore : get(id) / put(id, record) / delete(id)
//   EnrollmentStore: get(userId) / put(userId, record) / delete(userId)
//   GrantRegistry  : get(grantId) / put(grantId, record) / revoke(grantId)
//                    / isRevoked(grantId)
//
// Records are plain JSON-serialisable objects; stores never interpret them.

/**
 * In-memory ChallengeStore reference: `get(id)` → record|null, `put(id,
 * record)`, `delete(id)`. Production stores must make burn-on-verify
 * effective: a challenge deleted by one verification attempt must not be
 * readable by a concurrent one.
 */
export class MemoryChallengeStore {
  #m = new Map();
  async get(id) { return this.#m.get(id) ?? null; }
  async put(id, record) { this.#m.set(id, record); }
  async delete(id) { this.#m.delete(id); }
}

/**
 * In-memory EnrollmentStore reference: `get(userId)` → record|null,
 * `put(userId, record)`, `delete(userId)`. Records carry the enrolled
 * address plus the failure/lock ledger, so they must persist durably.
 */
export class MemoryEnrollmentStore {
  #m = new Map();
  async get(userId) { return this.#m.get(userId) ?? null; }
  async put(userId, record) { this.#m.set(userId, record); }
  async delete(userId) { this.#m.delete(userId); }
}

/**
 * In-memory GrantRegistry reference: `get(grantId)` → record|null,
 * `put(grantId, record)`, `revoke(grantId)`, `isRevoked(grantId)` → bool.
 * Revocation wins over everything and is permanent: a revoked grantId
 * stays revoked even if the grant record later expires out of the registry.
 */
export class MemoryGrantRegistry {
  #grants = new Map();
  #revoked = new Set();
  async get(grantId) { return this.#grants.get(grantId) ?? null; }
  async put(grantId, record) { this.#grants.set(grantId, record); }
  async revoke(grantId) { this.#revoked.add(grantId); }
  async isRevoked(grantId) { return this.#revoked.has(grantId); }
}
