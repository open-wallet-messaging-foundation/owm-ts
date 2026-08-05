// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OWM SCX live smoke — secure contact exchange end-to-end over a real
// owm-rendezvous relay, then reaching the exchanged contact on the real
// XMTP `dev` network. Proves:
//   (1) pairing code → mailbox claim → SPAKE2 over relay frames → identical
//       SAS → transcript-bound cards verified on both sides;
//   (2) a DM opened with the inboxId from the VERIFIED card carries
//       wm-ping(purpose=call)/wm-pong through @open-wallet-messaging/core strict parsing;
//   (3) wrong code aborts with bad-confirmation — no key, no card, ever;
//   (4) a parallel-session MITM cut-and-pasting a genuine signed card is
//       killed by the transcript binding (bad-card-signature);
//   (5) a second mailbox claim surfaces as a clean 409 through the client.
//
// Run via ./run.sh (stage 2). Needs cargo for the relay: if cargo is absent
// this sub-stage prints a loud SKIP and exits 0. Exit code != 0 on failure.

import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { toBytes } from 'viem';
import * as sdk from '@xmtp/node-sdk';
import {
  generateCode, parseCode, createScxSession, verifyContactCard,
  buildWmContactCard, buildPing, buildPong, parseMessage,
  createMailbox, claimMailbox, openMailboxTransport,
} from '../packages/owm-core/src/index.js';

const RUST_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'rust');

// --- toolchain gate: this sub-stage alone is skippable ------------------------
if (spawnSync('cargo', ['--version'], { stdio: 'ignore' }).error) {
  console.log('SKIP: cargo not on PATH — SCX rendezvous smoke not run (sub-stage exits 0)');
  process.exit(0);
}

let pass = 0; let fail = 0;
function expect(cond, label) {
  if (cond) { pass += 1; console.log(`  ✔ ${label}`); }
  else { fail += 1; console.error(`  ✖ ${label}`); }
}

const { Client, IdentifierKind, encodeText } = sdk;
const sendText = (conv, str) => conv.send(encodeText(str));
const dbDir = mkdtempSync(join(tmpdir(), 'owm-scx-smoke-'));
const enc = new TextDecoder();

function makeSigner(account) {
  return {
    type: 'EOA',
    getIdentifier: () => ({ identifier: account.address.toLowerCase(), identifierKind: IdentifierKind.Ethereum }),
    signMessage: async (message) => toBytes(await account.signMessage({ message })),
  };
}

async function makeClient(tag) {
  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  const client = await Client.create(makeSigner(account), {
    env: 'dev',
    dbPath: join(dbDir, `${tag}.db3`),
    dbEncryptionKey: new Uint8Array(randomBytes(32)),
  });
  console.log(`  · ${tag}: ${account.address} inbox=${client.inboxId}`);
  return { client, account, privateKey };
}

async function poll(label, fn, { tries = 30, delayMs = 1000 } = {}) {
  for (let i = 0; i < tries; i += 1) {
    const out = await fn();
    if (out) return out;
    await new Promise((r) => setTimeout(r, delayMs));
  }
  throw new Error(`poll timeout: ${label}`);
}

// Drive one SCX session over a mailbox transport until it reaches a stop
// state. `mapOutbound` lets the MITM scenario tamper with outbound envelopes
// (the honest default is identity).
async function drive(session, transport, stopStates, mapOutbound = (e) => e) {
  let res = session.start();
  for (const env of res.send) await transport.send(JSON.stringify(mapOutbound(env)));
  while (!stopStates.includes(session.state)) {
    const bytes = await transport.recv();
    if (bytes === null) throw new Error('transport closed mid-handshake');
    res = session.receive(enc.decode(bytes));
    for (const env of res.send) await transport.send(JSON.stringify(mapOutbound(env)));
  }
  return session.state;
}

// --- relay: build once, spawn once, fresh mailboxes per scenario ---------------
console.log('— relay: cargo build (debug) + spawn on an ephemeral port —');
const build = spawnSync('cargo', ['build', '-p', 'owm-rendezvous'], { cwd: RUST_DIR, stdio: 'inherit' });
if (build.status !== 0) {
  console.error('✖ cargo build -p owm-rendezvous failed');
  process.exit(1);
}

const relay = spawn(join(RUST_DIR, 'target', 'debug', 'owm-rendezvous'), [], {
  env: { ...process.env, OWM_RENDEZVOUS_ADDR: '127.0.0.1:0' },
  stdio: ['ignore', 'pipe', 'inherit'],
});
const baseUrl = await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error('relay did not print its address within 10s')), 10_000);
  let buf = '';
  relay.stdout.on('data', (d) => {
    buf += d;
    const m = buf.match(/^owm-rendezvous listening on (\S+)$/m);
    if (m) { clearTimeout(timer); resolve(`http://${m[1]}`); }
  });
  relay.on('exit', (code) => { clearTimeout(timer); reject(new Error(`relay exited early (code ${code})`)); });
});
console.log(`  · relay up at ${baseUrl}`);

let exitCode = 1;
try {
  console.log('— XMTP clients (ephemeral, dev network) —');
  const alice = await makeClient('alice');
  const bob = await makeClient('bob');
  const aliceIdentity = { privateKey: alice.privateKey, inboxId: alice.client.inboxId, displayName: 'Alice' };
  const bobIdentity = { privateKey: bob.privateKey, inboxId: bob.client.inboxId, displayName: 'Bob' };

  // ── SCX happy path ───────────────────────────────────────────────────────────
  console.log('— SCX happy path: pairing code → PAKE → cards → SAS —');
  const mb = await createMailbox({ baseUrl });
  const code = generateCode({ mailboxId: mb.id });
  console.log(`  · pairing code (the read-it-over-a-phone-call artifact): ${code}`);
  const parsedCode = parseCode(code);
  expect(parsedCode.ok && parsedCode.mailboxId === mb.id, 'Bob parses the pairing code back to the mailbox id');
  const bobSeat = await claimMailbox({ baseUrl, id: parsedCode.mailboxId });
  const ta = openMailboxTransport({ baseUrl, id: mb.id, sideCap: mb.sideCap });
  const tb = openMailboxTransport({ baseUrl, id: mb.id, sideCap: bobSeat.sideCap });
  const sa = createScxSession({ role: 'a', code, identity: aliceIdentity, now: Date.now() });
  const sb = createScxSession({ role: 'b', code, identity: bobIdentity, now: Date.now() });
  await Promise.all([
    drive(sa, ta, ['card-exchanged', 'aborted']),
    drive(sb, tb, ['card-exchanged', 'aborted']),
  ]);
  expect(sa.state === 'card-exchanged' && sb.state === 'card-exchanged', 'both sides reach card-exchanged (sas-pending gate)');
  expect(Boolean(sa.sas) && Boolean(sb.sas) && sa.sas.display === sb.sas.display, 'IDENTICAL SAS on both screens');
  console.log(`  · SAS on both screens: ${sa.sas.display}`);
  for (const env of sa.acceptSas().send) await ta.send(JSON.stringify(env));
  const rbSas = sb.acceptSas();
  expect(rbSas.state === 'sas-pending' || rbSas.state === 'confirmed', "Bob's SAS accept enters sas-pending");
  for (const env of rbSas.send) await tb.send(JSON.stringify(env));
  sa.receive(enc.decode(await ta.recv()));
  sb.receive(enc.decode(await tb.recv()));
  expect(sa.state === 'confirmed' && sb.state === 'confirmed', 'both sides confirmed after SAS match');
  expect(verifyContactCard(sa.peerCard, sa.transcriptHash).ok, "Bob's card verifies against Alice's transcript");
  expect(verifyContactCard(sb.peerCard, sb.transcriptHash).ok, "Alice's card verifies against Bob's transcript");
  expect(sa.peerCard.inboxId === bob.client.inboxId
    && sa.peerCard.address.toLowerCase() === bob.account.address.toLowerCase(),
  "the verified card asserts Bob's real address + inboxId");
  ta.close(); tb.close();

  // ── the DM rides the SCX-established contact ────────────────────────────────
  console.log('— DM to the inboxId from the VERIFIED card —');
  const dm = await alice.client.conversations.createDm(sa.peerCard.inboxId);
  const ping = buildPing({ purpose: 'call', ts: Date.now() });
  await sendText(dm, JSON.stringify(ping));
  const gotPing = await poll('bob parses wm-ping', async () => {
    await bob.client.conversations.sync();
    for (const conv of await bob.client.conversations.listDms()) {
      await conv.sync();
      for (const msg of await conv.messages()) {
        if (typeof msg.content !== 'string') continue;
        const parsed = parseMessage(msg.content);
        if (parsed.ok && parsed.kind === 'wm-ping') return { parsed, conv };
      }
    }
    return null;
  });
  expect(gotPing.parsed.body.purpose === 'call' && gotPing.parsed.body.nonce === ping.nonce,
    'wm-ping(purpose=call) strict-parsed off the wire');
  await sendText(gotPing.conv, JSON.stringify(buildPong({ nonce: gotPing.parsed.body.nonce, auto: true, ts: Date.now() })));
  const gotPong = await poll('alice parses wm-pong', async () => {
    await alice.client.conversations.sync();
    await dm.sync();
    for (const msg of await dm.messages()) {
      if (typeof msg.content !== 'string') continue;
      const parsed = parseMessage(msg.content);
      if (parsed.ok && parsed.kind === 'wm-pong') return parsed;
    }
    return null;
  });
  expect(gotPong.body.nonce === ping.nonce, 'wm-pong completes the ping over the SCX-established contact');

  // ── wrong code fails safe ────────────────────────────────────────────────────
  console.log('— negative: wrong code aborts with bad-confirmation, no key, no card —');
  const mbW = await createMailbox({ baseUrl });
  const codeW = generateCode({ mailboxId: mbW.id });
  let wrongWords = 'acid-acorn-acre';
  if (codeW.endsWith(`-${wrongWords}`)) wrongWords = 'acid-acorn-aged'; // 1-in-2^31 guard
  const wrongCode = `${mbW.id}-${wrongWords}`;
  const seatW = await claimMailbox({ baseUrl, id: mbW.id });
  const taW = openMailboxTransport({ baseUrl, id: mbW.id, sideCap: mbW.sideCap });
  const tbW = openMailboxTransport({ baseUrl, id: mbW.id, sideCap: seatW.sideCap });
  const saW = createScxSession({ role: 'a', code: codeW, identity: aliceIdentity, now: Date.now() });
  const sbW = createScxSession({ role: 'b', code: wrongCode, identity: bobIdentity, now: Date.now() });
  await Promise.all([
    drive(saW, taW, ['card-exchanged', 'aborted']),
    drive(sbW, tbW, ['card-exchanged', 'aborted']),
  ]);
  expect(sbW.state === 'aborted' && sbW.abortReason === 'bad-confirmation',
    "Bob's session aborts with bad-confirmation on the wrong code");
  expect(saW.state === 'aborted' && saW.abortReason === 'bad-confirmation',
    "Alice's side aborts cleanly too (mutual MAC mismatch)");
  expect(saW.sessionKey === null && sbW.sessionKey === null, 'NO session key ever exposed on either side');
  expect(saW.peerCard === null && sbW.peerCard === null, 'no card accepted anywhere');
  taW.close(); tbW.close();

  // ── parallel-session MITM fails safe ─────────────────────────────────────────
  console.log('— negative: parallel-session MITM cut-and-paste of a genuine card —');
  // Mallory knows BOTH codes (she is a party to both sessions). Session 2:
  // Mallory ↔ Bob, honest, yields Bob's genuine card signed over transcript 2.
  const malloryIdentity = { privateKey: generatePrivateKey(), inboxId: 'mallory-mitm-inbox', displayName: 'Mallory' };
  const mb2 = await createMailbox({ baseUrl }); // Mallory's mailbox with Bob
  const code2 = generateCode({ mailboxId: mb2.id });
  const seat2 = await claimMailbox({ baseUrl, id: mb2.id });
  const tMal2 = openMailboxTransport({ baseUrl, id: mb2.id, sideCap: mb2.sideCap });
  const tBob2 = openMailboxTransport({ baseUrl, id: mb2.id, sideCap: seat2.sideCap });
  const sMal2 = createScxSession({ role: 'a', code: code2, identity: malloryIdentity, now: Date.now() });
  const sBob2 = createScxSession({ role: 'b', code: code2, identity: bobIdentity, now: Date.now() });
  await Promise.all([
    drive(sMal2, tMal2, ['card-exchanged', 'aborted']),
    drive(sBob2, tBob2, ['card-exchanged', 'aborted']),
  ]);
  expect(sMal2.state === 'card-exchanged', 'session 2 (Mallory↔Bob) yields Bob\'s genuine signed card');
  const bobGenuineCardEnv = buildWmContactCard(sMal2.peerCard); // signed over transcript 2
  tMal2.close(); tBob2.close();
  // Session 1: Alice ↔ Mallory. Mallory completes the PAKE honestly (she has
  // the code) but pastes Bob's genuine card in place of her own.
  const mb1 = await createMailbox({ baseUrl }); // Alice's mailbox
  const code1 = generateCode({ mailboxId: mb1.id });
  const seat1 = await claimMailbox({ baseUrl, id: mb1.id });
  const tAli1 = openMailboxTransport({ baseUrl, id: mb1.id, sideCap: mb1.sideCap });
  const tMal1 = openMailboxTransport({ baseUrl, id: mb1.id, sideCap: seat1.sideCap });
  const sAli1 = createScxSession({ role: 'a', code: code1, identity: aliceIdentity, now: Date.now() });
  const sMal1 = createScxSession({ role: 'b', code: code1, identity: malloryIdentity, now: Date.now() });
  const pasteBobsCard = (env) => (env._kind === 'wm-contact-card' ? bobGenuineCardEnv : env);
  await Promise.all([
    drive(sAli1, tAli1, ['card-exchanged', 'aborted']),
    drive(sMal1, tMal1, ['card-exchanged', 'aborted'], pasteBobsCard),
  ]);
  expect(sAli1.state === 'aborted' && sAli1.abortReason === 'bad-card-signature',
    "Alice aborts with bad-card-signature — transcript binding kills the cut-and-paste");
  expect(sAli1.peerCard === null, "Bob's card never lands verified in Alice's session");
  expect(sAli1.sessionKey === null, 'aborted session exposes no key material');
  expect(!verifyContactCard(sMal2.peerCard, sAli1.transcriptHash).ok,
    "direct check: Bob's genuine card fails verification against session-1's transcript");
  tAli1.close(); tMal1.close();

  // ── exhausted mailbox: second claim is a clean 409 ───────────────────────────
  console.log('— negative: a mailbox seats exactly one claimant —');
  const mbX = await createMailbox({ baseUrl });
  await claimMailbox({ baseUrl, id: mbX.id });
  let secondClaim = null;
  try {
    await claimMailbox({ baseUrl, id: mbX.id });
  } catch (err) { secondClaim = err; }
  expect(secondClaim?.status === 409 && secondClaim?.code === 'already-claimed',
    'second claim surfaces as a clean 409 already-claimed through the JS client');

  console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
  exitCode = fail === 0 ? 0 : 1;
} catch (err) {
  console.error(`\n✖ UNCAUGHT: ${err?.stack ?? err}`);
  console.log(`\nRESULT: ${pass} passed, ${fail + 1} failed`);
  exitCode = 1;
} finally {
  relay.kill();
}
process.exit(exitCode);
