// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OWM live stage smoke — OWM-STAGE Tier 1 on the real XMTP `dev` network.
// Proves, with three ephemeral identities (dj + two listeners):
//   (1) the m=stage door link round-trips, token fragment-only;
//   (2) the invite state machine gates admission; wm-stage-config +
//       wm-playback-sync beacons strict-parse off the wire;
//   (3) a listener can compute a landing position from a beacon
//       ("track T was at positionMs when the wall clock read atMs");
//   (4) MLS forward secrecy: a latecomer CANNOT read beacons sent before
//       their welcome — which is why the DJ re-beacons on every admit;
//   (5) eviction is cryptographic deafening: after removeMembers, the
//       next-epoch beacon never reaches the removed listener, and their
//       client reports the group inactive;
//   (6) wm-stage-cue (encore) rides the room and strict-parses.
//
// Run via ./run.sh (self-bootstraps deps). Exit code != 0 on any failure.

import { randomBytes } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { toBytes } from 'viem';
import * as sdk from '@xmtp/node-sdk';
import {
  createInvite, isAdmissible, redeem, buildInviteLink, parseInviteLink,
  buildWmStageConfig, buildWmPlaybackSync, buildWmStageCue, parseMessage,
} from '../packages/owm-core/src/index.js';

let pass = 0; let fail = 0;
function expect(cond, label) {
  if (cond) { pass += 1; console.log(`  ✔ ${label}`); }
  else { fail += 1; console.error(`  ✖ ${label}`); }
}

const { Client, IdentifierKind, GroupPermissionsOptions, encodeText } = sdk;
const sendText = (conv, str) => conv.send(encodeText(str));
const dbDir = mkdtempSync(join(tmpdir(), 'owm-stage-smoke-'));

function makeSigner(account) {
  return {
    type: 'EOA',
    getIdentifier: () => ({ identifier: account.address.toLowerCase(), identifierKind: IdentifierKind.Ethereum }),
    signMessage: async (message) => toBytes(await account.signMessage({ message })),
  };
}

async function makeClient(tag) {
  const account = privateKeyToAccount(generatePrivateKey());
  const client = await Client.create(makeSigner(account), {
    env: 'dev',
    dbPath: join(dbDir, `${tag}.db3`),
    dbEncryptionKey: new Uint8Array(randomBytes(32)),
  });
  console.log(`  · ${tag}: ${account.address} inbox=${client.inboxId}`);
  return { client, account };
}

async function poll(label, fn, { tries = 30, delayMs = 1000 } = {}) {
  for (let i = 0; i < tries; i += 1) {
    const out = await fn();
    if (out) return out;
    await new Promise((r) => setTimeout(r, delayMs));
  }
  throw new Error(`poll timeout: ${label}`);
}

// Every OWM envelope of `kind` visible in a member's view of the room.
async function roomEnvelopes(member, groupId, kind) {
  await member.client.conversations.sync();
  const g = (await member.client.conversations.listGroups()).find((x) => x.id === groupId);
  if (!g) return [];
  try { await g.sync(); } catch { /* post-eviction sync can fail — local view still counts */ }
  const out = [];
  for (const msg of await g.messages()) {
    if (typeof msg.content !== 'string') continue;
    const parsed = parseMessage(msg.content);
    if (parsed.ok && parsed.kind === kind) out.push(parsed.body);
  }
  return out;
}

const NOW = Date.now();

console.log('— clients (ephemeral, dev network) —');
const dj = await makeClient('dj');
const nia = await makeClient('nia');
const ben = await makeClient('ben');

console.log('— venue: AdminOnly MLS room + m=stage door link —');
const group = await dj.client.conversations.createGroup([], {
  permissions: GroupPermissionsOptions.AdminOnly,
  groupName: 'OWM listening party (smoke)',
});
let invite = createInvite({ roomId: group.id, label: 'smoke party', now: NOW, ttlMs: 2 * 3600_000, maxUses: 2 });
const link = buildInviteLink({
  origin: 'https://party.example', roomId: group.id, adminInboxId: dj.client.inboxId,
  name: 'Smoke Party', mode: 'stage', token: invite.token,
});
const parsedLink = parseInviteLink(link);
expect(parsedLink.mode === 'stage' && parsedLink.token === invite.token
  && parsedLink.roomId === group.id && !new URL(link).searchParams.get('t'),
'm=stage door link round-trips, token in fragment only');

console.log('— nia knocks (join request over a real DM) and is admitted —');
const niaDm = await nia.client.conversations.createDmWithIdentifier({
  identifier: dj.account.address.toLowerCase(), identifierKind: IdentifierKind.Ethereum,
});
await sendText(niaDm, JSON.stringify({
  _kind: 'group-join-request', v: 1, groupId: parsedLink.roomId, token: parsedLink.token,
  requester: nia.account.address.toLowerCase(), name: 'Nia', mode: 'stage',
  nonce: randomBytes(16).toString('hex'), ts: NOW,
}));
const niaReq = await poll('dj sees nia\'s join request', async () => {
  await dj.client.conversations.sync();
  for (const conv of await dj.client.conversations.listDms()) {
    await conv.sync();
    for (const msg of await conv.messages()) {
      if (typeof msg.content !== 'string') continue;
      try {
        const body = JSON.parse(msg.content);
        if (body?._kind === 'group-join-request' && body.requester === nia.account.address.toLowerCase()) return body;
      } catch { /* plain text */ }
    }
  }
  return null;
});
expect(isAdmissible(invite, NOW, niaReq.requester), 'nia\'s ticket is admissible');
await group.addMembersByIdentifiers([{ identifier: niaReq.requester, identifierKind: IdentifierKind.Ethereum }]);
invite = redeem(invite, NOW, niaReq.requester);
expect(invite.uses === 1, 'ticket redeemed (1/2 uses)');

console.log('— stage state: config + first beacon (nia must hear it) —');
let seq = 0;
const sendEnv = (env) => sendText(group, JSON.stringify(env));
await sendEnv(buildWmStageConfig({ mode: 'listening-party', title: 'Smoke Party', performers: [dj.client.inboxId], seq: (seq += 1), ts: Date.now() }));
const beacon1 = buildWmPlaybackSync({ trackId: 'neon-tide', positionMs: 0, state: 'playing', atMs: Date.now(), seq: (seq += 1) });
await sendEnv(beacon1);

const niaConfig = await poll('nia strict-parses wm-stage-config', async () =>
  (await roomEnvelopes(nia, group.id, 'wm-stage-config'))[0] ?? null);
expect(niaConfig.mode === 'listening-party' && niaConfig.performers[0] === dj.client.inboxId,
  'wm-stage-config strict-parsed off the wire');
const niaBeacon = await poll('nia strict-parses the first beacon', async () =>
  (await roomEnvelopes(nia, group.id, 'wm-playback-sync')).find((b) => b.seq === beacon1.seq) ?? null);
const landing = niaBeacon.positionMs + (Date.now() - niaBeacon.atMs);
expect(landing >= niaBeacon.positionMs && landing < 5 * 60_000,
  `listener computes a sane landing position (${Math.round(landing / 1000)}s into the set)`);

console.log('— ben arrives late: admitted, re-beaconed, and MLS-blind to the past —');
const benDm = await ben.client.conversations.createDmWithIdentifier({
  identifier: dj.account.address.toLowerCase(), identifierKind: IdentifierKind.Ethereum,
});
await sendText(benDm, JSON.stringify({
  _kind: 'group-join-request', v: 1, groupId: parsedLink.roomId, token: parsedLink.token,
  requester: ben.account.address.toLowerCase(), name: 'Ben', mode: 'stage',
  nonce: randomBytes(16).toString('hex'), ts: Date.now(),
}));
const benReq = await poll('dj sees ben\'s join request', async () => {
  await dj.client.conversations.sync();
  for (const conv of await dj.client.conversations.listDms()) {
    await conv.sync();
    for (const msg of await conv.messages()) {
      if (typeof msg.content !== 'string') continue;
      try {
        const body = JSON.parse(msg.content);
        if (body?._kind === 'group-join-request' && body.requester === ben.account.address.toLowerCase()) return body;
      } catch { /* plain text */ }
    }
  }
  return null;
});
expect(isAdmissible(invite, NOW, benReq.requester), 'second ticket use is admissible');
await group.addMembersByIdentifiers([{ identifier: benReq.requester, identifierKind: IdentifierKind.Ethereum }]);
invite = redeem(invite, NOW, benReq.requester);
expect(!isAdmissible(invite, NOW, '0x9999999999999999999999999999999999999999'),
  'door exhausted after maxUses redemptions');

// The latecomer protocol: on admit, the DJ re-sends config + a fresh beacon.
await sendEnv(buildWmStageConfig({ mode: 'listening-party', title: 'Smoke Party', performers: [dj.client.inboxId], seq: (seq += 1), ts: Date.now() }));
const beacon2 = buildWmPlaybackSync({ trackId: 'neon-tide', positionMs: 30_000, state: 'playing', atMs: Date.now(), seq: (seq += 1) });
await sendEnv(beacon2);

const benBeacons = await poll('ben hears the post-admit beacon', async () => {
  const bs = await roomEnvelopes(ben, group.id, 'wm-playback-sync');
  return bs.find((b) => b.seq === beacon2.seq) ? bs : null;
});
expect(Boolean(benBeacons.find((b) => b.seq === beacon2.seq)), 'latecomer lands mid-song off the fresh beacon');
expect(!benBeacons.find((b) => b.seq === beacon1.seq),
  'MLS forward secrecy: latecomer CANNOT read the pre-welcome beacon');

console.log('— encore cue rides the room —');
const niaGroup = (await nia.client.conversations.listGroups()).find((g) => g.id === group.id);
await sendText(niaGroup, JSON.stringify(buildWmStageCue({ cue: 'encore', ts: Date.now() })));
const djCue = await poll('dj strict-parses the encore cue', async () =>
  (await roomEnvelopes(dj, group.id, 'wm-stage-cue')).find((c) => c.cue === 'encore') ?? null);
expect(djCue.cue === 'encore', 'wm-stage-cue strict-parsed off the wire');

console.log('— eviction = cryptographic deafening —');
await group.removeMembers([nia.client.inboxId]);
const beacon3 = buildWmPlaybackSync({ trackId: 'neon-tide', positionMs: 60_000, state: 'playing', atMs: Date.now(), seq: (seq += 1) });
await sendEnv(beacon3);
await poll('ben still hears the next-epoch beacon', async () =>
  (await roomEnvelopes(ben, group.id, 'wm-playback-sync')).find((b) => b.seq === beacon3.seq) ?? null);
expect(true, 'remaining listener hears the next-epoch beacon');

const niaInactive = await poll('nia\'s client learns she was removed', async () => {
  await nia.client.conversations.sync();
  const g = (await nia.client.conversations.listGroups()).find((x) => x.id === group.id);
  if (!g) return true; // gone from her list entirely — also proof
  try { await g.sync(); } catch { /* expected once removed */ }
  const active = typeof g.isActive === 'function' ? await g.isActive() : g.isActive;
  return active === false ? true : null;
});
expect(niaInactive === true, 'removed listener\'s client reports the room inactive');
const niaLate = await roomEnvelopes(nia, group.id, 'wm-playback-sync');
expect(!niaLate.find((b) => b.seq === beacon3.seq),
  'removed listener NEVER receives the next-epoch beacon (deafened by MLS, not by politeness)');

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
