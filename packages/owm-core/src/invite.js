// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// Room invite tokens + links. Semantics proven in production (group rooms):
// - the token is a 256-bit opaque bearer nonce, base64url;
// - it rides ONLY in the URL fragment (#t=...) — fragments are never sent in
//   HTTP requests, so servers, edge logs, and link-preview fetchers never see
//   the secret;
// - state machine: active -> redeemed | exhausted | revoked | expired;
// - optional address pre-commitment (boundTo) for high-assurance invites.

export const DEFAULT_TTL_MS = 72 * 60 * 60 * 1000; // 72h
// 'stage' (OWM-STAGE, WM-4): admit → auto-join the room's media/listening
// session, audience-muted — the one-link-does-everything ethos of an OWM
// invite link, applied to concerts.
export const JOIN_MODES = Object.freeze(['chat', 'call', 'stage']);

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

export function toBase64Url(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : null;
    const c = i + 2 < bytes.length ? bytes[i + 2] : null;
    out += B64URL[a >> 2];
    out += B64URL[((a & 3) << 4) | (b === null ? 0 : b >> 4)];
    if (b !== null) out += B64URL[((b & 15) << 2) | (c === null ? 0 : c >> 6)];
    if (c !== null) out += B64URL[c & 63];
  }
  return out;
}

export function randomToken() {
  const buf = new Uint8Array(32); // 256 bits
  globalThis.crypto.getRandomValues(buf);
  return toBase64Url(buf);
}

export function createInvite({
  token = randomToken(),
  roomId,
  label = '',
  now,
  ttlMs = DEFAULT_TTL_MS,
  maxUses = 1,
  boundTo = null,
}) {
  if (!roomId) throw new Error('roomId required');
  if (typeof now !== 'number') throw new Error('now (unix ms) required');
  return {
    token,
    roomId,
    label, // admin-private; never serialised into links
    createdAt: now,
    expiresAt: now + ttlMs,
    maxUses,
    uses: 0,
    revoked: false,
    redeemedBy: [],
    boundTo,
  };
}

export function inviteStatus(invite, now) {
  if (invite.revoked) return 'revoked';
  if (now >= invite.expiresAt) return 'expired';
  if (invite.uses >= invite.maxUses) return 'exhausted';
  return 'active';
}

export function isAdmissible(invite, now, presenter) {
  if (inviteStatus(invite, now) !== 'active') return false;
  if (invite.boundTo && invite.boundTo.toLowerCase() !== String(presenter).toLowerCase()) return false;
  return true;
}

export function redeem(invite, now, presenter) {
  if (!isAdmissible(invite, now, presenter)) throw new Error('not admissible');
  return {
    ...invite,
    uses: invite.uses + 1,
    redeemedBy: [...invite.redeemedBy, { presenter, at: now }],
  };
}

// Link shape:  <origin>/?room=<id>&admin=<inboxId>&name=<n>&m=<mode>#t=<token>
export function buildInviteLink({ origin, roomId, adminInboxId, name, mode = 'chat', token }) {
  if (!JOIN_MODES.includes(mode)) throw new Error(`bad mode: ${mode}`);
  if (!token) throw new Error('token required');
  const url = new URL(origin);
  url.searchParams.set('room', roomId);
  url.searchParams.set('admin', adminInboxId);
  if (name) url.searchParams.set('name', name);
  url.searchParams.set('m', mode);
  url.hash = `t=${token}`;
  return url.toString();
}

export function parseInviteLink(link) {
  const url = new URL(link);
  const frag = url.hash.startsWith('#') ? url.hash.slice(1) : url.hash;
  const fragParams = new URLSearchParams(frag);
  const token = fragParams.get('t');
  // Hard rule: the token must never appear in the query string.
  if (url.searchParams.get('t')) throw new Error('token in query — refusing (must ride the fragment)');
  return {
    roomId: url.searchParams.get('room'),
    adminInboxId: url.searchParams.get('admin'),
    name: url.searchParams.get('name') ?? '',
    mode: url.searchParams.get('m') ?? 'chat',
    token: token ?? null,
  };
}
