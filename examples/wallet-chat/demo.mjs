// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// The self-checking version of the whole ladder in ONE process — run this
// first. The host side and the join side sit side by side so you can watch
// every step: relay → blind mailbox → pairing code → SMS (mock unless the
// TWILIO_* env vars are set) → SPAKE2 → identical SAS on both "screens" →
// transcript-bound verified cards → a real DM on the XMTP dev network →
// three chat messages each way, strict-parsed. Exits 0 when every check
// passed, 1 otherwise.
//
//   node demo.mjs [+15551234567]     # optional phone: really SMS the code

import { render } from './chat.mjs';
import {
  createWallet, connectRelay, sendSms, driveScx, settleSas, pollFor, sendText,
  createMailbox, claimMailbox, openMailboxTransport,
  generateCode, parseCode, createScxSession, verifyContactCard, parseMessage,
} from './wallet.mjs';

let pass = 0; let fail = 0;
function expect(cond, label) {
  if (cond) { pass += 1; console.log(`  ✔ ${label}`); }
  else { fail += 1; console.error(`  ✖ ${label}`); }
}

const phone = process.argv[2]; // real SMS needs this AND the TWILIO_* env vars

console.log('— relay —');
const relay = await connectRelay();

let exitCode = 1;
try {
  console.log('— two wallets (ephemeral, XMTP dev network) —');
  const host = await createWallet({ tag: 'host ', quiet: true });
  const guest = await createWallet({ tag: 'guest', quiet: true });

  console.log('— host side: blind mailbox, pairing code, SMS —');
  const mailbox = await createMailbox({ baseUrl: relay.baseUrl });
  const code = generateCode({ mailboxId: mailbox.id });
  console.log(`  · pairing code: ${code}`);
  await sendSms({ to: phone, body: `Reply-less secure contact setup: open your wallet and enter code ${code}` });

  console.log('— join side: parse the code, claim the mailbox —');
  const parsed = parseCode(code);
  expect(parsed.ok && parsed.mailboxId === mailbox.id, 'pairing code parses back to the mailbox id');
  const seat = await claimMailbox({ baseUrl: relay.baseUrl, id: parsed.mailboxId });

  console.log('— SCX: SPAKE2 over the relay, both sides —');
  const sHost = createScxSession({
    role: 'a', code, now: Date.now(),
    identity: { privateKey: host.privateKey, inboxId: host.inboxId, displayName: 'Host' },
  });
  const sGuest = createScxSession({
    role: 'b', code, now: Date.now(),
    identity: { privateKey: guest.privateKey, inboxId: guest.inboxId, displayName: 'Guest' },
  });
  const tHost = openMailboxTransport({ baseUrl: relay.baseUrl, id: mailbox.id, sideCap: mailbox.sideCap });
  const tGuest = openMailboxTransport({ baseUrl: relay.baseUrl, id: mailbox.id, sideCap: seat.sideCap });
  await Promise.all([driveScx(sHost, tHost), driveScx(sGuest, tGuest)]);
  expect(sHost.state === 'card-exchanged' && sGuest.state === 'card-exchanged',
    'both sides reach card-exchanged');
  expect(Boolean(sHost.sas) && sHost.sas.display === sGuest.sas.display,
    `IDENTICAL SAS on both screens: ${sHost.sas?.display}`);
  await Promise.all([settleSas(sHost, tHost), settleSas(sGuest, tGuest)]);
  expect(sHost.state === 'confirmed' && sGuest.state === 'confirmed',
    'both sides confirmed after the SAS match');
  expect(verifyContactCard(sHost.peerCard, sHost.transcriptHash).ok,
    "host verified the guest's transcript-bound card");
  expect(verifyContactCard(sGuest.peerCard, sGuest.transcriptHash).ok,
    "guest verified the host's transcript-bound card");
  expect(sHost.peerCard.inboxId === guest.inboxId
    && sHost.peerCard.address.toLowerCase() === guest.address.toLowerCase(),
  "the card asserts the guest's real address + inboxId");
  tHost.close(); tGuest.close();

  console.log('— XMTP: DM opened from the VERIFIED card, three messages each way —');
  const dm = await host.client.conversations.createDm(sHost.peerCard.inboxId);
  expect(Boolean(dm?.id), "the DM opens to the verified card's inboxId");
  const hostLines = [
    '👋 secured via OWM',
    'the code went over SMS — keys and addresses never did',
    'that is the whole trick',
  ];
  for (const line of hostLines) await sendText(dm, line);

  const guestSide = await pollFor('guest receives all three', async () => {
    await guest.client.conversations.sync();
    for (const conv of await guest.client.conversations.listDms()) {
      await conv.sync();
      const texts = (await conv.messages())
        .filter((m) => typeof m.content === 'string' && m.senderInboxId === host.inboxId)
        .map((m) => m.content);
      if (hostLines.every((l) => texts.includes(l))) return { conv, texts };
    }
    return null;
  });
  expect(hostLines.every((l) => guestSide.texts.includes(l)),
    `guest received ${hostLines.length}/3 host messages`);
  expect(guestSide.texts.every((t) => parseMessage(t).plain === true),
    'each one strict-parses as plain chat (render-or-fallback)');
  console.log(`  · guest screen: ${render(guestSide.texts[0])}`);

  const guestLines = [
    'hello host — the code checked out',
    'SAS matched on both screens',
    'chat away',
  ];
  for (const line of guestLines) await sendText(guestSide.conv, line);

  const hostTexts = await pollFor('host receives all three replies', async () => {
    await host.client.conversations.sync();
    await dm.sync();
    const texts = (await dm.messages())
      .filter((m) => typeof m.content === 'string' && m.senderInboxId === guest.inboxId)
      .map((m) => m.content);
    return guestLines.every((l) => texts.includes(l)) ? texts : null;
  });
  expect(guestLines.every((l) => hostTexts.includes(l)),
    `host received ${guestLines.length}/3 guest replies`);
  expect(hostTexts.every((t) => parseMessage(t).plain === true),
    'the replies strict-parse as plain chat too');

  console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
  exitCode = fail === 0 ? 0 : 1;
} catch (err) {
  console.error(`\n✖ UNCAUGHT: ${err?.stack ?? err}`);
  console.log(`\nRESULT: ${pass} passed, ${fail + 1} failed`);
  exitCode = 1;
} finally {
  relay.stop();
}
process.exit(exitCode);
