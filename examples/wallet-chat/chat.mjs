// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// Rung 1 — the hello-world: plain wallet-to-wallet chat on the XMTP dev
// network. No Twilio, no pairing ceremony, no relay. Two terminals:
//
//   terminal A:  node chat.mjs                → prints its address and waits
//   terminal B:  node chat.mjs 0x<address-A>  → opens the DM; both type away
//
// Every incoming message goes through @open-wallet-messaging/core's strict parser — render()
// below is the whole OWM message philosophy in five lines. Ctrl-C leaves.

import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';
import {
  createWallet, takeKeyFlag, pollFor, sendText, sleep, parseMessage,
  IdentifierKind, shortAddr,
} from './wallet.mjs';

// Strict-parse EVERYTHING: a valid envelope renders by kind name; an unknown
// kind falls back to readable text (surfaced, never dropped); an invalid
// payload of a known kind is refused loudly; everything else is plain chat.
export function render(raw) {
  const p = parseMessage(raw);
  if (p.ok) return `⟦${p.kind}⟧ ${JSON.stringify(p.body)}`; // known kind, strictly valid
  if (p.plain) return raw; // not an envelope — ordinary chat text
  if (p.unknown) return `⟦unknown kind: ${p.kind}⟧ ${raw}`; // never silently dropped
  return `⟦invalid ${p.kind}: ${p.error}⟧`; // known kind, bad payload — refused
}

// The interactive loop every rung hands off to: type a line → send; poll the
// DM → strict-parse and print whatever arrives. Ctrl-C exits cleanly.
export async function chatLoop({ client, dm, peerLabel = 'them' }) {
  console.log('\nchat is live — type a line and press enter; Ctrl-C to leave.\n');
  const rl = createInterface({ input: process.stdin, output: process.stdout, prompt: 'you › ' });
  rl.on('line', (line) => {
    const text = line.trim();
    if (text !== '') sendText(dm, text).catch((err) => console.error(`send failed: ${err.message}`));
    rl.prompt();
  });
  rl.on('SIGINT', () => rl.close());
  rl.on('close', () => { console.log('\nbye 👋'); process.exit(0); });
  rl.prompt();
  const seen = new Set();
  for (;;) {
    try {
      await dm.sync();
      for (const msg of await dm.messages()) {
        if (seen.has(msg.id)) continue;
        seen.add(msg.id);
        if (typeof msg.content !== 'string') continue; // not text (receipts, etc.)
        if (msg.senderInboxId === client.inboxId) continue; // ours — already on screen
        process.stdout.write('\r\x1b[K'); // clear the prompt line
        console.log(`${peerLabel} › ${render(msg.content)}`);
        rl.prompt(true);
      }
    } catch { /* transient network hiccup — keep polling */ }
    await sleep(1200);
  }
}

// --- main (only when run directly — host.mjs/join.mjs import from here) -----

const isMain = process.argv[1] !== undefined
  && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMain) {
  process.on('SIGINT', () => { console.log('\nbye 👋'); process.exit(0); });

  const { key, argv } = takeKeyFlag(process.argv.slice(2));
  const peer = argv[0];
  if (peer !== undefined && !/^0x[0-9a-fA-F]{40}$/.test(peer)) {
    console.error('usage: node chat.mjs [0xPeerAddress] [--key 0xPrivateKey]');
    process.exit(1);
  }

  const me = await createWallet({ key });

  if (peer) {
    let dm;
    try {
      dm = await me.client.conversations.createDmWithIdentifier({
        identifier: peer.toLowerCase(),
        identifierKind: IdentifierKind.Ethereum,
      });
    } catch (err) {
      console.error(`could not open a DM to ${peer}: ${err.message}`);
      console.error('is that wallet on XMTP yet? start `node chat.mjs` on the other side first.');
      process.exit(1);
    }
    console.log(`DM open with ${peer} — say hi.`);
    await chatLoop({ client: me.client, dm, peerLabel: shortAddr(peer) });
  } else {
    console.log('waiting for messages — in another terminal (or on a friend\'s machine):');
    console.log(`\n  node chat.mjs ${me.address}\n`);
    const dm = await pollFor('someone to open a DM', async () => {
      await me.client.conversations.sync();
      const dms = await me.client.conversations.listDms();
      return dms[0] ?? null;
    }, { tries: Infinity, delayMs: 1500 });
    console.log(`incoming DM (peer inbox ${dm.peerInboxId})`);
    await chatLoop({ client: me.client, dm });
  }
}
