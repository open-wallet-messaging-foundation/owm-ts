// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OWM live smoke — real XMTP `dev` network, ephemeral identities.
// Proves: (1) our invite state machine gates admission to a real AdminOnly
// MLS group; (2) the m=call invite link round-trips with the token in the
// fragment; (3) wm-ping/wm-pong envelopes ride real DMs through @open-wallet-messaging/core
// strict parsing; (4) AdminOnly is protocol-enforced (non-admin cannot add).
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
  buildPing, buildPong, parseMessage,
} from '../packages/owm-core/src/index.js';

let pass = 0; let fail = 0;
function expect(cond, label) {
  if (cond) { pass += 1; console.log(`  ✔ ${label}`); }
  else { fail += 1; console.error(`  ✖ ${label}`); }
}

const { Client, IdentifierKind, GroupPermissionsOptions, encodeText } = sdk;
const sendText = (conv, str) => conv.send(encodeText(str));
const dbDir = mkdtempSync(join(tmpdir(), 'owm-smoke-'));

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

const NOW = Date.now();

console.log('— clients (ephemeral, dev network) —');
const admin = await makeClient('admin');
const trevor = await makeClient('trevor');
const mallory = await makeClient('mallory');

console.log('— room: AdminOnly MLS group + channel-drop invite —');
const group = await admin.client.conversations.createGroup([], {
  permissions: GroupPermissionsOptions.AdminOnly,
  groupName: 'OWM smoke room',
});
expect(Boolean(group?.id), 'admin created AdminOnly group');

let invite = createInvite({ roomId: group.id, now: NOW, maxUses: 2, label: 'team drop' });
const link = buildInviteLink({
  origin: 'https://example.org/', roomId: group.id, adminInboxId: admin.client.inboxId,
  name: 'OWM smoke', mode: 'call', token: invite.token,
});
const parsedLink = parseInviteLink(link);
expect(parsedLink.token === invite.token && parsedLink.mode === 'call'
  && parsedLink.roomId === group.id, 'm=call invite link round-trips, token in fragment');

console.log('— join request rides a real DM (invitee → admin) —');
const dmToAdmin = await trevor.client.conversations.createDmWithIdentifier({
  identifier: admin.account.address.toLowerCase(),
  identifierKind: IdentifierKind.Ethereum,
});
const joinReq = {
  _kind: 'group-join-request', v: 1, groupId: parsedLink.roomId,
  token: parsedLink.token, requester: trevor.account.address.toLowerCase(),
  nonce: randomBytes(16).toString('hex'), ts: NOW,
};
await sendText(dmToAdmin, JSON.stringify(joinReq));

const gotReq = await poll('admin sees join request', async () => {
  await admin.client.conversations.sync();
  for (const conv of await admin.client.conversations.listDms()) {
    await conv.sync();
    for (const msg of await conv.messages()) {
      if (typeof msg.content !== 'string') continue;
      try {
        const body = JSON.parse(msg.content);
        if (body?._kind === 'group-join-request') return body;
      } catch { /* plain text */ }
    }
  }
  return null;
});
expect(gotReq.token === invite.token, 'admin received the join request with the token');

console.log('— token gate + admit —');
expect(isAdmissible(invite, NOW, gotReq.requester), 'token admissible on first presentation');
await group.addMembersByIdentifiers([{ identifier: gotReq.requester, identifierKind: IdentifierKind.Ethereum }]);
invite = redeem(invite, NOW, gotReq.requester);
expect(invite.uses === 1, 'invite redeemed (1/2 uses)');

const trevorGroup = await poll('invitee sees the room', async () => {
  await trevor.client.conversations.sync();
  const groups = await trevor.client.conversations.listGroups();
  return groups.find((g) => g.id === group.id) ?? null;
});
expect(Boolean(trevorGroup), 'admitted member sees the room');

await sendText(trevorGroup, 'hello from trevor');
const heard = await poll('admin hears room message', async () => {
  await group.sync();
  const msgs = await group.messages();
  return msgs.find((m) => m.content === 'hello from trevor') ?? null;
});
expect(Boolean(heard), 'room chat flows both ways');

console.log('— wm-ping / wm-pong over the DM via @open-wallet-messaging/core —');
const ping = buildPing({ purpose: 'call', ts: Date.now() });
await sendText(dmToAdmin, JSON.stringify(ping));
const gotPing = await poll('admin parses wm-ping', async () => {
  await admin.client.conversations.sync();
  for (const conv of await admin.client.conversations.listDms()) {
    await conv.sync();
    for (const msg of await conv.messages()) {
      if (typeof msg.content !== 'string') continue;
      const parsed = parseMessage(msg.content);
      if (parsed.ok && parsed.kind === 'wm-ping') return parsed;
    }
  }
  return null;
});
expect(gotPing.body.purpose === 'call' && gotPing.body.nonce === ping.nonce,
  'wm-ping strict-parsed off the wire');

const adminDm = (await admin.client.conversations.listDms())[0];
await sendText(adminDm, JSON.stringify(buildPong({ nonce: gotPing.body.nonce, auto: true, ts: Date.now() })));
const gotPong = await poll('invitee parses wm-pong', async () => {
  await trevor.client.conversations.sync();
  await dmToAdmin.sync();
  for (const msg of await dmToAdmin.messages()) {
    if (typeof msg.content !== 'string') continue;
    const parsed = parseMessage(msg.content);
    if (parsed.ok && parsed.kind === 'wm-pong') return parsed;
  }
  return null;
});
expect(gotPong.body.nonce === ping.nonce, 'wm-pong round-trip completes the ping');

console.log('— negative: AdminOnly is protocol-enforced —');
let nonAdminAddFailed = false;
try {
  await trevorGroup.addMembersByIdentifiers([{
    identifier: mallory.account.address.toLowerCase(), identifierKind: IdentifierKind.Ethereum,
  }]);
} catch { nonAdminAddFailed = true; }
expect(nonAdminAddFailed, 'non-admin member CANNOT add members (MLS-enforced)');

console.log('— negative: exhausted invite is refused —');
invite = redeem(invite, NOW, mallory.account.address.toLowerCase());
expect(!isAdmissible(invite, NOW, '0x9999999999999999999999999999999999999999'),
  'invite exhausted after maxUses redemptions');

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
