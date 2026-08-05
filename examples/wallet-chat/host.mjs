// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// Rung 2, side A — initiate secure contact with someone via SMS, then chat.
//
//   node host.mjs [+15551234567] [--key 0xPrivateKey]
//
// Flow: relay (OWM_RENDEZVOUS_URL, else spawn the local one) → blind mailbox
// → pairing code → SMS it (mock unless the TWILIO_* env vars are set) →
// SPAKE2 with whoever enters the code → compare the SAS out loud → verified,
// transcript-bound contact card → open the XMTP DM and chat. The ceremony is
// specified in spec/WM-3-scx.md.

import { chatLoop } from './chat.mjs';
import {
  createWallet, takeKeyFlag, connectRelay, sendSms, ask, driveScx, settleSas,
  sendText, shortAddr,
  createMailbox, generateCode, createScxSession, openMailboxTransport, verifyContactCard,
} from './wallet.mjs';

process.on('SIGINT', () => { console.log('\nbye 👋'); process.exit(0); });

const { key, argv } = takeKeyFlag(process.argv.slice(2));
const phone = argv[0]; // optional — without it (or without creds) the SMS is mocked

const me = await createWallet({ key });
const relay = await connectRelay();
if (relay.spawned) {
  console.log('\nfor join.mjs in another terminal on THIS machine, run first:');
  console.log(`\n  export OWM_RENDEZVOUS_URL=${relay.baseUrl}\n`);
}

const mailbox = await createMailbox({ baseUrl: relay.baseUrl });
const code = generateCode({ mailboxId: mailbox.id });
console.log('═'.repeat(56));
console.log(`  PAIRING CODE:   ${code}`);
console.log('═'.repeat(56));
await sendSms({ to: phone, body: `Reply-less secure contact setup: open your wallet and enter code ${code}` });

console.log(`\nwaiting for the other side to enter the code…   (they run:  node join.mjs ${code})`);
const session = createScxSession({
  role: 'a',
  code,
  identity: { privateKey: me.privateKey, inboxId: me.inboxId, displayName: process.env.OWM_DISPLAY_NAME },
  now: Date.now(),
});
const transport = openMailboxTransport({ baseUrl: relay.baseUrl, id: mailbox.id, sideCap: mailbox.sideCap });
await driveScx(session, transport);
if (session.state === 'aborted') {
  console.error(`\nhandshake aborted: ${session.abortReason}`);
  if (session.abortReason === 'bad-confirmation') {
    console.error('the other side had a different code — one wrong guess is all an attacker ever gets,');
    console.error('and it breaks loudly, exactly like this. start over with a fresh code.');
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

const dm = await me.client.conversations.createDm(card.inboxId);
await sendText(dm, '👋 secured via OWM');
await chatLoop({ client: me.client, dm, peerLabel: card.displayName ?? shortAddr(card.address) });
