// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// Rung 2, side B — you received the pairing code (SMS, or read out loud);
// enter it here to complete the secure contact exchange, then chat.
//
//   export OWM_RENDEZVOUS_URL=http://…      ← host.mjs printed this line
//   node join.mjs 7-panda-mocha-quilt [--key 0xPrivateKey]
//
// (Same machine: copy the export line from the host terminal. Two machines:
// run owm-rendezvous somewhere both sides can reach and set it on both.)

import { chatLoop } from './chat.mjs';
import {
  createWallet, takeKeyFlag, ask, driveScx, settleSas, pollFor, shortAddr,
  parseCode, claimMailbox, openMailboxTransport, createScxSession, verifyContactCard,
} from './wallet.mjs';

process.on('SIGINT', () => { console.log('\nbye 👋'); process.exit(0); });

const { key, argv } = takeKeyFlag(process.argv.slice(2));
const code = argv[0];
if (!code) {
  console.error('usage: node join.mjs <pairing-code>        e.g.  node join.mjs 7-panda-mocha-quilt');
  process.exit(1);
}
const parsed = parseCode(code);
if (!parsed.ok) {
  console.error(`that code doesn't parse: ${parsed.error}`);
  console.error('typos are caught right here — before they burn the ONE online guess the protocol allows.');
  process.exit(1);
}
const baseUrl = (process.env.OWM_RENDEZVOUS_URL ?? '').replace(/\/+$/, '');
if (baseUrl === '') {
  console.error('OWM_RENDEZVOUS_URL is not set — join.mjs must reach the same relay as the host.');
  console.error('same machine : copy the  export OWM_RENDEZVOUS_URL=…  line host.mjs printed.');
  console.error('two machines : run owm-rendezvous somewhere both can reach and set it on both sides.');
  process.exit(1);
}

const me = await createWallet({ key });

let seat;
try {
  seat = await claimMailbox({ baseUrl, id: parsed.mailboxId });
} catch (err) {
  if (err.code === 'already-claimed') {
    console.error('this code was already used — pairing codes are strictly one-shot (that IS the security model).');
    console.error('ask the host for a fresh one.');
  } else {
    console.error(`could not claim the mailbox: ${err.message}`);
    console.error('is the relay still up, and the code recent? mailboxes expire after ~15 minutes.');
  }
  process.exit(1);
}

console.log('code accepted — running the key exchange…');
const session = createScxSession({
  role: 'b',
  code,
  identity: { privateKey: me.privateKey, inboxId: me.inboxId, displayName: process.env.OWM_DISPLAY_NAME },
  now: Date.now(),
});
const transport = openMailboxTransport({ baseUrl, id: parsed.mailboxId, sideCap: seat.sideCap });
await driveScx(session, transport);
if (session.state === 'aborted') {
  console.error(`\nhandshake aborted: ${session.abortReason}`);
  if (session.abortReason === 'bad-confirmation') {
    console.error('code mismatch — a typo, or someone guessing. it fails loudly, never silently.');
    console.error('get a fresh code and try again.');
  }
  process.exit(1);
}

console.log(`\n${'═'.repeat(56)}`);
console.log('  SAS — both screens must show EXACTLY this:');
console.log(`\n      ${session.sas.display}\n`);
console.log('═'.repeat(56));
const answer = await ask('does the other screen show the same? [y/n] ');
if (!/^y/i.test(answer)) {
  for (const env of session.rejectSas().send) await transport.send(JSON.stringify(env));
  transport.close();
  console.error('\naborted: sas-mismatch — a mismatch means interference; never proceed.');
  console.error('get a fresh code and start over.');
  process.exit(1);
}
await settleSas(session, transport);
transport.close();
if (session.state !== 'confirmed') {
  console.error(`aborted: ${session.abortReason} (the other side did not confirm the SAS)`);
  process.exit(1);
}

const card = session.peerCard;
console.log(`\n✔ contact verified (card signature bound to this exchange: ${verifyContactCard(card, session.transcriptHash).ok})`);
console.log(`  address : ${card.address}`);
console.log(`  inboxId : ${card.inboxId}`);
if (card.displayName) console.log(`  name    : ${card.displayName}`);

console.log('\nwaiting for the host to open the chat…');
const dm = await pollFor("the host's DM", async () => {
  await me.client.conversations.sync();
  for (const d of await me.client.conversations.listDms()) {
    if (d.peerInboxId === card.inboxId) return d;
  }
  return null;
}, { tries: Infinity, delayMs: 1500 });
await chatLoop({ client: me.client, dm, peerLabel: card.displayName ?? shortAddr(card.address) });
