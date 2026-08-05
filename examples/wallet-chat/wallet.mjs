// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// Shared plumbing for the wallet-chat ladder — the one file every rung
// imports. It gives you:
//
//   createWallet()   an XMTP client on the dev network from a private key
//                    (persistent via --key / OWM_WALLET_KEY, else ephemeral)
//   sendSms()        a real Twilio SMS when the TWILIO_* env vars are set,
//                    a clearly-marked mock line otherwise
//   connectRelay()   OWM_RENDEZVOUS_URL if set, else build + spawn the local
//                    owm-rendezvous relay on an ephemeral port
//   driveScx() / settleSas() / pollFor() / ask() / sendText()   small helpers
//
// plus flat re-exports of the @open-wallet-messaging/core functions the scripts use — loaded
// AFTER the friendly install check below (static imports would hoist past it).

import { existsSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');

// --- .env: drop your TWILIO_* credentials into .env next to this file -------
// (real environment variables win over .env values; missing file is fine)
try {
  process.loadEnvFile(join(HERE, '.env'));
} catch {
  /* no .env yet — everything falls back to mock SMS */
}

// --- preflight: a friendly sentence beats a module-resolution stack trace ----

if (!existsSync(join(HERE, 'node_modules'))) {
  console.error('This example has its own dependencies (@xmtp/node-sdk, viem).');
  console.error('Run npm install in this folder first:');
  console.error(`\n  cd ${HERE}`);
  console.error('  npm install\n');
  process.exit(1);
}
if (!existsSync(join(ROOT, 'node_modules'))) {
  console.error("The repo root hasn't been installed yet (@open-wallet-messaging/core pulls @noble/* from there).");
  console.error(`\n  cd ${ROOT}`);
  console.error('  npm install\n');
  process.exit(1);
}

const { Client, IdentifierKind, encodeText } = await import('@xmtp/node-sdk');
const { privateKeyToAccount, generatePrivateKey } = await import('viem/accounts');
const { toBytes } = await import('viem');
const core = await import('../../packages/owm-core/src/index.js');

export const {
  generateCode, parseCode, createScxSession, verifyContactCard,
  createMailbox, claimMailbox, openMailboxTransport,
  parseMessage, buildPing, buildPong,
} = core;
export { IdentifierKind };

// --- tiny conveniences --------------------------------------------------------

// node-sdk v6: bare conv.send(string) throws MissingContentTypeError.
export const sendText = (conv, str) => conv.send(encodeText(str));
export const shortAddr = (a) => `${a.slice(0, 6)}…${a.slice(-4)}`;
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function pollFor(label, fn, { tries = 30, delayMs = 1000 } = {}) {
  for (let i = 0; i < tries; i += 1) {
    const out = await fn();
    if (out) return out;
    await sleep(delayMs);
  }
  throw new Error(`timed out waiting for ${label}`);
}

// One question, one trimmed answer. Ctrl-C during the prompt exits cleanly.
export function ask(question) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  rl.on('SIGINT', () => { rl.close(); console.log('\nbye 👋'); process.exit(0); });
  return new Promise((resolve) => rl.question(question, (answer) => {
    rl.close();
    resolve(answer.trim());
  }));
}

// --key 0x… on the command line, or OWM_WALLET_KEY in the env. Returns the
// normalized key (or null → ephemeral) plus the remaining args.
export function takeKeyFlag(argv) {
  const rest = [...argv];
  let key = process.env.OWM_WALLET_KEY ?? null;
  const at = rest.indexOf('--key');
  if (at !== -1) {
    key = rest[at + 1];
    if (key === undefined) {
      console.error('--key needs a value (a 32-byte hex private key)');
      process.exit(1);
    }
    rest.splice(at, 2);
  }
  if (key !== null) {
    if (!/^(0x)?[0-9a-fA-F]{64}$/.test(key)) {
      console.error('--key / OWM_WALLET_KEY must be 32 bytes of hex (64 hex chars, 0x optional)');
      process.exit(1);
    }
    if (!key.startsWith('0x')) key = `0x${key}`;
  }
  return { key, argv: rest };
}

// --- the wallet ----------------------------------------------------------------

// An XMTP client on the dev network (XMTP_ENV overrides). Pass a key to keep
// a stable identity; without one we generate a throwaway key and PRINT it so
// you can pin it next run. The local message db lives under the OS temp dir,
// keyed by address, encrypted with a key derived from the wallet key —
// convenient for an example; use real key storage in a product.
export async function createWallet({ tag = 'your wallet', key = null, quiet = false } = {}) {
  const generated = key === null;
  const privateKey = generated ? generatePrivateKey() : key;
  const account = privateKeyToAccount(privateKey);
  const env = process.env.XMTP_ENV ?? 'dev';
  const dataDir = join(tmpdir(), 'owm-wallet-chat');
  mkdirSync(dataDir, { recursive: true });
  const signer = {
    type: 'EOA',
    getIdentifier: () => ({ identifier: account.address.toLowerCase(), identifierKind: IdentifierKind.Ethereum }),
    signMessage: async (message) => toBytes(await account.signMessage({ message })),
  };
  const client = await Client.create(signer, {
    env,
    dbPath: join(dataDir, `${env}-${account.address.toLowerCase()}.db3`),
    dbEncryptionKey: new Uint8Array(createHash('sha256').update(`owm-wallet-chat-db|${privateKey}`).digest()),
  });
  if (quiet) {
    console.log(`  · ${tag}: ${account.address} inbox=${client.inboxId}`);
  } else {
    console.log('─'.repeat(64));
    console.log(`  ${tag}`);
    console.log(`  address : ${account.address}`);
    console.log(`  inboxId : ${client.inboxId}`);
    console.log(`  network : XMTP ${env}`);
    console.log('─'.repeat(64));
    if (generated) {
      console.log('  tip: this key is ephemeral — reuse it to keep this address stable:');
      console.log(`       --key ${privateKey}`);
      console.log(`       (or  OWM_WALLET_KEY=${privateKey})`);
      console.log('─'.repeat(64));
    }
  }
  return { client, account, address: account.address, inboxId: client.inboxId, privateKey };
}

// --- SMS -------------------------------------------------------------------------

// One SMS via Twilio's REST API — plain fetch, form-encoded, no SDK — when
// TWILIO_ACCOUNT_SID + TWILIO_AUTH_TOKEN + TWILIO_FROM are all set AND a
// recipient was given; otherwise a clearly-marked mock so everything runs
// with zero setup. The auth token rides basic auth and is never printed.
export async function sendSms({ to, body }) {
  const sid = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  const from = process.env.TWILIO_FROM;
  if (sid && token && from && to) {
    const res = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
      method: 'POST',
      headers: {
        authorization: `Basic ${Buffer.from(`${sid}:${token}`).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ To: to, From: from, Body: body }).toString(),
    });
    const out = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(`Twilio send failed: HTTP ${res.status}${out.message ? ` — ${out.message}` : ''}`);
    }
    console.log(`📨 SMS sent via Twilio → ${to} (message SID ${out.sid})`);
    return { sent: true, sid: out.sid };
  }
  console.log(`📱 SMS (mock — set TWILIO_* env vars to really send) → ${to ?? '+1555…'}: ${body}`);
  return { sent: false };
}

// --- rendezvous relay --------------------------------------------------------------

// OWM_RENDEZVOUS_URL if set; otherwise build + spawn the repo's own
// owm-rendezvous on an ephemeral local port (needs cargo). The spawned relay
// binds 127.0.0.1 — same-machine demos only; stop() (also wired to process
// exit) kills it.
export async function connectRelay() {
  const envUrl = process.env.OWM_RENDEZVOUS_URL;
  if (envUrl) {
    const baseUrl = envUrl.replace(/\/+$/, '');
    console.log(`relay: using ${baseUrl} (OWM_RENDEZVOUS_URL)`);
    return { baseUrl, spawned: false, stop() {} };
  }
  const rustDir = join(ROOT, 'rust');
  if (spawnSync('cargo', ['--version'], { stdio: 'ignore' }).error) {
    console.error('No OWM_RENDEZVOUS_URL set and no cargo on PATH to build the local relay.');
    console.error('Install Rust (https://rustup.rs), or point OWM_RENDEZVOUS_URL at a running owm-rendezvous.');
    process.exit(1);
  }
  console.log('relay: building owm-rendezvous (debug — the first run may take a minute)…');
  if (spawnSync('cargo', ['build', '-p', 'owm-rendezvous'], { cwd: rustDir, stdio: 'inherit' }).status !== 0) {
    console.error('cargo build -p owm-rendezvous failed');
    process.exit(1);
  }
  const child = spawn(join(rustDir, 'target', 'debug', 'owm-rendezvous'), [], {
    env: { ...process.env, OWM_RENDEZVOUS_ADDR: '127.0.0.1:0' },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  const baseUrl = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('relay did not print its address within 10s')), 10_000);
    let buf = '';
    child.stdout.on('data', (d) => {
      buf += d;
      const m = buf.match(/^owm-rendezvous listening on (\S+)$/m);
      if (m) { clearTimeout(timer); resolve(`http://${m[1]}`); }
    });
    child.on('exit', (code) => { clearTimeout(timer); reject(new Error(`relay exited early (code ${code})`)); });
  });
  console.log(`relay: up at ${baseUrl} (spawned locally)`);
  const stop = () => { try { child.kill(); } catch { /* already gone */ } };
  process.on('exit', stop);
  return { baseUrl, spawned: true, stop };
}

// --- SCX driving -----------------------------------------------------------------

const dec = new TextDecoder();

// Pump one SCX session over a mailbox transport until it reaches a stop
// state: post whatever `send` arrays come back, feed every inbound frame in.
export async function driveScx(session, transport, stopStates = ['card-exchanged', 'aborted']) {
  let res = session.start();
  for (const env of res.send) await transport.send(JSON.stringify(env));
  while (!stopStates.includes(session.state)) {
    const bytes = await transport.recv();
    if (bytes === null) throw new Error('transport closed mid-handshake');
    res = session.receive(dec.decode(bytes));
    for (const env of res.send) await transport.send(JSON.stringify(env));
  }
  return session.state;
}

// After the human said "yes, same SAS": send our confirmation and wait for
// the peer's. Ends 'confirmed' (both matched) or 'aborted' (they rejected).
export async function settleSas(session, transport) {
  for (const env of session.acceptSas().send) await transport.send(JSON.stringify(env));
  while (session.state !== 'confirmed' && session.state !== 'aborted') {
    const bytes = await transport.recv();
    if (bytes === null) throw new Error('transport closed before the SAS was confirmed');
    session.receive(dec.decode(bytes));
  }
  return session.state;
}
