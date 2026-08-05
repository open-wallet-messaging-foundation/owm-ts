// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// SCX ceremony demo — both sides in one process, a real owm-rendezvous
// relay in between. Shows the whole SCX flow with no XMTP: pairing code →
// mailbox claim → SPAKE2 → transcript-bound cards → matching SAS on both
// "screens" → confirmed. Run: node demo.mjs   (needs cargo for the relay).

import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  generateCode, parseCode, createScxSession, verifyContactCard,
  createMailbox, claimMailbox, openMailboxTransport,
} from '../../packages/owm-core/src/index.js';

const RUST_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'rust');
const dec = new TextDecoder();

if (spawnSync('cargo', ['--version'], { stdio: 'ignore' }).error) {
  console.error('ERROR: this demo builds the owm-rendezvous relay and needs cargo on PATH.');
  console.error('Install Rust (https://rustup.rs) and re-run: node demo.mjs');
  process.exit(1);
}

console.log('building owm-rendezvous (debug, first run may take a minute)…');
if (spawnSync('cargo', ['build', '-p', 'owm-rendezvous'], { cwd: RUST_DIR, stdio: 'inherit' }).status !== 0) {
  console.error('ERROR: cargo build -p owm-rendezvous failed');
  process.exit(1);
}

const relay = spawn(join(RUST_DIR, 'target', 'debug', 'owm-rendezvous'), [], {
  env: { ...process.env, OWM_RENDEZVOUS_ADDR: '127.0.0.1:0' },
  stdio: ['ignore', 'pipe', 'ignore'],
});
const baseUrl = await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error('relay did not start')), 10_000);
  let buf = '';
  relay.stdout.on('data', (d) => {
    buf += d;
    const m = buf.match(/^owm-rendezvous listening on (\S+)$/m);
    if (m) { clearTimeout(timer); resolve(`http://${m[1]}`); }
  });
});
console.log(`relay up at ${baseUrl}\n`);

async function drive(session, transport, stopStates) {
  let res = session.start();
  for (const env of res.send) await transport.send(JSON.stringify(env));
  while (!stopStates.includes(session.state)) {
    res = session.receive(dec.decode(await transport.recv()));
    for (const env of res.send) await transport.send(JSON.stringify(env));
  }
}

try {
  // Demo identities: throwaway secp256k1 keys, placeholder inbox ids.
  const alice = { privateKey: randomBytes(32).toString('hex'), inboxId: 'alice-demo-inbox', displayName: 'Alice' };
  const bob = { privateKey: randomBytes(32).toString('hex'), inboxId: 'bob-demo-inbox', displayName: 'Bob' };

  // Alice creates the mailbox and reads the code to Bob over the phone.
  const mailbox = await createMailbox({ baseUrl });
  const code = generateCode({ mailboxId: mailbox.id });
  console.log(`[Alice's screen]  pairing code to read out loud:  ${code}\n`);

  // Bob types it in; the mailbox id routes him, the words feed the PAKE.
  const seat = await claimMailbox({ baseUrl, id: parseCode(code).mailboxId });

  const sa = createScxSession({ role: 'a', code, identity: alice, now: Date.now() });
  const sb = createScxSession({ role: 'b', code, identity: bob, now: Date.now() });
  const ta = openMailboxTransport({ baseUrl, id: mailbox.id, sideCap: mailbox.sideCap });
  const tb = openMailboxTransport({ baseUrl, id: mailbox.id, sideCap: seat.sideCap });

  await Promise.all([
    drive(sa, ta, ['card-exchanged', 'aborted']),
    drive(sb, tb, ['card-exchanged', 'aborted']),
  ]);
  if (sa.state !== 'card-exchanged' || sb.state !== 'card-exchanged') {
    throw new Error(`handshake failed: alice=${sa.state}/${sa.abortReason} bob=${sb.state}/${sb.abortReason}`);
  }

  console.log(`[Alice's screen]  SAS:  ${sa.sas.display}`);
  console.log(`[Bob's screen]    SAS:  ${sb.sas.display}`);
  console.log('humans compare out loud… match! both tap ✓\n');

  for (const env of sa.acceptSas().send) await ta.send(JSON.stringify(env));
  for (const env of sb.acceptSas().send) await tb.send(JSON.stringify(env));
  sa.receive(dec.decode(await ta.recv()));
  sb.receive(dec.decode(await tb.recv()));
  ta.close(); tb.close();

  console.log(`state: alice=${sa.state}, bob=${sb.state}`);
  console.log(`Alice verified Bob's card   (sig bound to this transcript: ${verifyContactCard(sa.peerCard, sa.transcriptHash).ok}):`, sa.peerCard);
  console.log(`Bob verified Alice's card   (sig bound to this transcript: ${verifyContactCard(sb.peerCard, sb.transcriptHash).ok}):`, sb.peerCard);
} finally {
  relay.kill();
}
