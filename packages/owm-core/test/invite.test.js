// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  randomToken, toBase64Url, createInvite, inviteStatus, isAdmissible, redeem,
  buildInviteLink, parseInviteLink, DEFAULT_TTL_MS,
} from '../src/invite.js';

const NOW = 1770000000000;
const ROOM = 'room-abc';
const ORIGIN = 'https://example.org/';

test('tokens are 256-bit base64url and unique', () => {
  const t = randomToken();
  assert.equal(t.length, 43); // 32 bytes -> 43 base64url chars, no padding
  assert.match(t, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(t, randomToken());
});

test('toBase64Url matches a known vector', () => {
  // "Man" -> "TWFu", and 0xfb 0xff -> "-_8" territory (url-safe alphabet)
  assert.equal(toBase64Url(new Uint8Array([77, 97, 110])), 'TWFu');
  assert.equal(toBase64Url(new Uint8Array([251, 255])), '-_8');
});

test('invite link: token rides the fragment, never the query', () => {
  const token = randomToken();
  const link = buildInviteLink({
    origin: ORIGIN, roomId: ROOM, adminInboxId: 'inbox1', name: 'Team Call', mode: 'call', token,
  });
  assert.ok(link.includes(`#t=${token}`));
  assert.ok(!new URL(link).searchParams.get('t'));
  const parsed = parseInviteLink(link);
  assert.deepEqual(parsed, {
    roomId: ROOM, adminInboxId: 'inbox1', name: 'Team Call', mode: 'call', token,
  });
});

test('a link smuggling the token into the query is refused', () => {
  assert.throws(() => parseInviteLink(`${ORIGIN}?room=r&admin=a&t=SECRET#t=SECRET`), /fragment/);
});

test('bad join mode is refused at build time', () => {
  assert.throws(() => buildInviteLink({
    origin: ORIGIN, roomId: ROOM, adminInboxId: 'a', mode: 'teleport', token: 'x',
  }));
});

test('single-use lifecycle: active -> redeemed -> exhausted', () => {
  let inv = createInvite({ roomId: ROOM, now: NOW, label: 'Trevor' });
  assert.equal(inviteStatus(inv, NOW), 'active');
  assert.ok(isAdmissible(inv, NOW, '0xAAA'));
  inv = redeem(inv, NOW + 1000, '0xAAA');
  assert.equal(inv.uses, 1);
  assert.equal(inviteStatus(inv, NOW + 2000), 'exhausted');
  assert.ok(!isAdmissible(inv, NOW + 2000, '0xBBB'));
  assert.throws(() => redeem(inv, NOW + 3000, '0xBBB'));
});

test('channel-drop invite: maxUses admits exactly N', () => {
  let inv = createInvite({ roomId: ROOM, now: NOW, maxUses: 3, label: 'team drop' });
  inv = redeem(inv, NOW + 1, '0x1');
  inv = redeem(inv, NOW + 2, '0x2');
  inv = redeem(inv, NOW + 3, '0x3');
  assert.equal(inviteStatus(inv, NOW + 4), 'exhausted');
  assert.equal(inv.redeemedBy.length, 3);
});

test('expiry: exactly-at-TTL is expired', () => {
  const inv = createInvite({ roomId: ROOM, now: NOW });
  assert.equal(inv.expiresAt, NOW + DEFAULT_TTL_MS);
  assert.equal(inviteStatus(inv, NOW + DEFAULT_TTL_MS - 1), 'active');
  assert.equal(inviteStatus(inv, NOW + DEFAULT_TTL_MS), 'expired');
});

test('revocation wins over everything', () => {
  const inv = { ...createInvite({ roomId: ROOM, now: NOW }), revoked: true };
  assert.equal(inviteStatus(inv, NOW), 'revoked');
  assert.ok(!isAdmissible(inv, NOW, '0xAAA'));
});

test('address pre-commitment (boundTo) is case-insensitive and exclusive', () => {
  const inv = createInvite({ roomId: ROOM, now: NOW, boundTo: '0xAbC1' });
  assert.ok(isAdmissible(inv, NOW, '0xabc1'));
  assert.ok(!isAdmissible(inv, NOW, '0xdead'));
});

test('createInvite validates inputs', () => {
  assert.throws(() => createInvite({ now: NOW }), /roomId/);
  assert.throws(() => createInvite({ roomId: ROOM }), /now/);
});
