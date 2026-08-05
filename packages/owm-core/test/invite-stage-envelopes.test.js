// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OWM-INVITE (517-519) + OWM-STAGE (540-542) envelope SPECS: strict happy + unhappy
// paths, same discipline as the 500s/510s/530s.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildWmInvite, buildWmInviteResponse, buildWmIntro,
  buildWmStageConfig, buildWmPlaybackSync, buildWmStageCue,
  parseMessage, randomNonce,
  INVITE_RESPONSES, STAGE_MODES, PLAYBACK_STATES, STAGE_CUES,
} from '../src/envelope.js';
import { buildInviteLink, parseInviteLink, JOIN_MODES } from '../src/invite.js';
import { KIND, wireName, kindCode, ACTOR_TYPES } from '../src/kinds.js';

const TS = 1770000000000;
const ADDR = '0x1111111111111111111111111111111111111111';
const SIG = 'ab'.repeat(65);

test('new kinds are registered both ways', () => {
  assert.equal(wireName(KIND.WmInvite), 'wm-invite');
  assert.equal(kindCode('wm-invite-response'), 518);
  assert.equal(wireName(519), 'wm-intro');
  assert.equal(kindCode('wm-stage-config'), 540);
  assert.equal(wireName(KIND.WmPlaybackSync), 'wm-playback-sync');
  assert.equal(kindCode('wm-stage-cue'), 542);
});

// --- wm-invite (517) --------------------------------------------------------

test('wm-invite builds, round-trips, and carries no bearer token field', () => {
  const inv = buildWmInvite({
    roomId: 'room-1', admin: 'inbox-admin', name: 'Team room',
    mode: 'stage', note: 'Friday listening party', ts: TS, exp: TS + 3600_000,
  });
  const parsed = parseMessage(JSON.stringify(inv));
  assert.ok(parsed.ok);
  assert.equal(parsed.kind, 'wm-invite');
  assert.ok(!('token' in parsed.body)); // addressed, never bearer
});

test('wm-invite rejects exp <= ts, bad mode, and an injected token key', () => {
  assert.throws(() => buildWmInvite({ roomId: 'r', admin: 'a', mode: 'chat', ts: TS, exp: TS }));
  assert.throws(() => buildWmInvite({ roomId: 'r', admin: 'a', mode: 'party', ts: TS, exp: TS + 1 }));
  const inv = buildWmInvite({ roomId: 'r', admin: 'a', mode: 'chat', ts: TS, exp: TS + 1 });
  const parsed = parseMessage(JSON.stringify({ ...inv, token: 'sneaky' }));
  assert.ok(!parsed.ok);
  assert.match(parsed.error, /extra key/);
});

// --- wm-invite-response (518) ----------------------------------------------

test('wm-invite-response round-trips for every allowed response', () => {
  for (const response of INVITE_RESPONSES) {
    const env = buildWmInviteResponse({ nonce: randomNonce(), roomId: 'r', response, ts: TS });
    assert.ok(parseMessage(JSON.stringify(env)).ok);
  }
});

test('wm-invite-response rejects a made-up verdict and a short nonce', () => {
  assert.throws(() => buildWmInviteResponse({ nonce: randomNonce(), roomId: 'r', response: 'maybe', ts: TS }));
  assert.throws(() => buildWmInviteResponse({ nonce: 'short', roomId: 'r', response: 'accept', ts: TS }));
});

// --- wm-intro (519) ---------------------------------------------------------

test('wm-intro shape builds with and without optional fields', () => {
  const base = { nonce: randomNonce(), introducer: ADDR, about: ADDR, aboutInboxId: 'inbox-c', purpose: 'OTC intro', ts: TS, sig: SIG };
  assert.ok(parseMessage(JSON.stringify(buildWmIntro(base))).ok);
  const full = buildWmIntro({ ...base, aboutName: 'Carol', actor: 'agent' });
  assert.equal(parseMessage(JSON.stringify(full)).body.actor, 'agent');
});

test('wm-intro rejects a bad actor, a newline purpose, and a bad address', () => {
  const base = { nonce: randomNonce(), introducer: ADDR, about: ADDR, aboutInboxId: 'i', purpose: 'p', ts: TS, sig: SIG };
  assert.throws(() => buildWmIntro({ ...base, actor: 'robot' }));
  assert.throws(() => buildWmIntro({ ...base, purpose: 'a\nb' }));
  assert.throws(() => buildWmIntro({ ...base, about: '0xnothex' }));
  assert.deepEqual(ACTOR_TYPES, ['human', 'agent', 'service']);
});

// --- wm-stage-config (540) --------------------------------------------------

test('wm-stage-config builds for every mode and validates performers', () => {
  for (const mode of STAGE_MODES) {
    const env = buildWmStageConfig({ mode, title: 'Friday', performers: ['inbox-dj'], capacity: 30, seq: 0, ts: TS });
    assert.ok(parseMessage(JSON.stringify(env)).ok);
  }
});

test('wm-stage-config rejects empty/oversized/non-string performers and bad capacity', () => {
  const base = { mode: 'listening-party', performers: ['dj'], seq: 0, ts: TS };
  assert.throws(() => buildWmStageConfig({ ...base, performers: [] }));
  assert.throws(() => buildWmStageConfig({ ...base, performers: [42] }));
  assert.throws(() => buildWmStageConfig({ ...base, performers: Array.from({ length: 33 }, (_, i) => `p${i}`) }));
  assert.throws(() => buildWmStageConfig({ ...base, capacity: 2.5 }));
  assert.throws(() => buildWmStageConfig({ ...base, capacity: 0 }));
});

// --- wm-playback-sync (541) -------------------------------------------------

test('wm-playback-sync round-trips and rejects fractional position, bad state, negative seq', () => {
  for (const state of PLAYBACK_STATES) {
    const env = buildWmPlaybackSync({ trackId: 'track-1', positionMs: 42_000, state, atMs: TS, seq: 7 });
    const parsed = parseMessage(JSON.stringify(env));
    assert.ok(parsed.ok);
    assert.equal(parsed.body.atMs, TS);
  }
  assert.throws(() => buildWmPlaybackSync({ trackId: 't', positionMs: 1.5, state: 'playing', atMs: TS, seq: 0 }));
  assert.throws(() => buildWmPlaybackSync({ trackId: 't', positionMs: 0, state: 'buffering', atMs: TS, seq: 0 }));
  assert.throws(() => buildWmPlaybackSync({ trackId: 't', positionMs: 0, state: 'paused', atMs: TS, seq: -1 }));
});

test('wm-playback-sync rejects a missing anchor (strict)', () => {
  const env = buildWmPlaybackSync({ trackId: 't', positionMs: 0, state: 'playing', atMs: TS, seq: 0 });
  const { atMs, ...missing } = env;
  assert.match(parseMessage(JSON.stringify(missing)).error, /missing key/);
});

// --- wm-stage-cue (542) -----------------------------------------------------

test('wm-stage-cue round-trips every cue; subject optional; bad cue rejected', () => {
  for (const cue of STAGE_CUES) {
    const env = buildWmStageCue({ cue, subject: cue === 'raise-hand' ? undefined : 'inbox-x', ts: TS });
    assert.ok(parseMessage(JSON.stringify(env)).ok);
  }
  assert.throws(() => buildWmStageCue({ cue: 'mosh-pit', ts: TS }));
});

// --- stage join mode on invite links ----------------------------------------

test('invite links carry m=stage; token still fragment-only', () => {
  assert.ok(JOIN_MODES.includes('stage'));
  const link = buildInviteLink({
    origin: 'https://example.org', roomId: 'r1', adminInboxId: 'adm',
    name: 'Friday', mode: 'stage', token: 'tok123',
  });
  const parsed = parseInviteLink(link);
  assert.equal(parsed.mode, 'stage');
  assert.equal(parsed.token, 'tok123');
  assert.ok(!new URL(link).searchParams.get('t'));
  assert.throws(() => buildInviteLink({ origin: 'https://example.org', roomId: 'r', adminInboxId: 'a', mode: 'rave', token: 'x' }));
});
