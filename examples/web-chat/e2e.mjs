#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// End-to-end proof that this page really chats over the XMTP dev network:
// drives TWO copies of the app in the system Chrome (puppeteer-core, no
// bundled browser), both on burner wallets, and exchanges real messages.
//
//   node e2e.mjs          # needs Google Chrome installed + network access
//
// What it asserts:
//   · both pages create XMTP identities in-browser (wasm + worker + OPFS)
//   · A opens a DM to B's address; two texts each way are delivered
//   · a wm-ping OWM envelope renders as a chip on the other side
//   · an unknown-kind envelope is surfaced, not dropped
// Screenshots land in a fresh temp dir (path printed at the end).

import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const PORT = 5199;
const URL_ = `https://127.0.0.1:${PORT}/`;
const WAIT = 120_000; // dev-network round trips can be slow

if (!existsSync(join(HERE, 'node_modules'))) {
  console.error(`run npm install in ${HERE} first`);
  process.exit(1);
}
const puppeteer = (await import('puppeteer-core')).default;

// --- 1. vite dev server (https via basic-ssl) --------------------------------
const vite = spawn(join(HERE, 'node_modules', '.bin', 'vite'), [
  '--port', String(PORT), '--strictPort', '--host', '127.0.0.1',
], { cwd: HERE, stdio: ['ignore', 'pipe', 'inherit'] });
vite.stdout.on('data', () => {}); // keep the pipe drained
const stopVite = () => { try { vite.kill(); } catch { /* gone */ } };
process.on('exit', stopVite);

// --- 2. two isolated pages in the system Chrome ------------------------------
const browser = await puppeteer.launch({
  channel: 'chrome',
  headless: true,
  acceptInsecureCerts: true, // basic-ssl's self-signed cert
  args: ['--ignore-certificate-errors'],
});
const ctxB = await browser.createBrowserContext(); // separate storage for B
const pageA = await browser.newPage();
const pageB = await ctxB.newPage();
for (const [name, page] of [['A', pageA], ['B', pageB]]) {
  page.on('pageerror', (e) => console.log(`  [${name} pageerror] ${e.message}`));
  page.on('console', (m) => { if (m.type() === 'error') console.log(`  [${name} console] ${m.text()}`); });
}

let passed = 0;
let failed = 0;
const ok = (label) => { passed += 1; console.log(`  ✔ ${label}`); };
const fail = (label, err) => { failed += 1; console.log(`  ✘ ${label}: ${err?.message ?? err}`); };

const gotoWithRetry = async (page) => {
  for (let i = 0; i < 30; i += 1) {
    try { await page.goto(URL_, { waitUntil: 'load', timeout: 5000 }); return; } catch { /* vite still booting */ }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`vite dev server never answered at ${URL_}`);
};

const connected = (page) => page.waitForFunction(
  () => !document.getElementById('banner').hidden && document.getElementById('me-address').dataset.full,
  { timeout: WAIT },
);

const seesText = (page, text) => page.waitForFunction(
  (t) => document.getElementById('messages')?.innerText.includes(t),
  { timeout: WAIT },
  text,
);

const typeAndSend = async (page, text) => {
  await page.click('#draft');
  await page.type('#draft', text);
  await page.keyboard.press('Enter');
};

const shots = mkdtempSync(join(tmpdir(), 'owm-web-chat-e2e-'));

try {
  console.log('web-chat e2e — two burner wallets, real XMTP dev network\n');

  await gotoWithRetry(pageA);
  await gotoWithRetry(pageB);
  ok('page loads over https (self-signed accepted)');

  // Both sides: burner identity → XMTP client in-browser.
  await pageA.click('#btn-burner');
  await pageB.click('#btn-burner');
  await connected(pageA);
  await connected(pageB);
  const addrA = await pageA.evaluate(() => document.getElementById('me-address').dataset.full);
  const addrB = await pageB.evaluate(() => document.getElementById('me-address').dataset.full);
  const inboxA = await pageA.evaluate(() => document.getElementById('me-inbox').dataset.full);
  const inboxB = await pageB.evaluate(() => document.getElementById('me-inbox').dataset.full);
  ok(`A connected in-browser: ${addrA} inbox=${inboxA.slice(0, 8)}…`);
  ok(`B connected in-browser: ${addrB} inbox=${inboxB.slice(0, 8)}…`);

  // A opens the DM to B by address.
  await pageA.click('#peer');
  await pageA.type('#peer', addrB);
  await pageA.click('#btn-open');
  await pageA.waitForFunction(() => !document.getElementById('chat').hidden, { timeout: WAIT });
  ok('A opened a DM to B via createDmWithIdentifier');

  // Two messages each way, alternating.
  await typeAndSend(pageA, 'hello from A — one');
  await seesText(pageB, 'hello from A — one');
  ok('B received A #1 (chat auto-opened on first contact)');

  await typeAndSend(pageB, 'hi from B — one');
  await seesText(pageA, 'hi from B — one');
  ok('A received B #1');

  await typeAndSend(pageA, 'second from A — two');
  await seesText(pageB, 'second from A — two');
  ok('B received A #2');

  await typeAndSend(pageB, 'second from B — two');
  await seesText(pageA, 'second from B — two');
  ok('A received B #2');

  // OWM envelope → labeled chip on the far side.
  await pageA.click('#btn-ping');
  await seesText(pageB, 'OWM wm-ping');
  ok('wm-ping envelope rendered as an OWM chip on B');

  // Unknown kind → surfaced visibly, never dropped.
  await typeAndSend(pageB, '{"_kind":"vnd.example.custom","v":1}');
  await seesText(pageA, 'unknown OWM kind');
  ok('unknown-kind envelope surfaced on A (render-or-fallback)');

  // --- 3. the 3-way room (Phase 1 reference-messenger slice) -----------------
  // Fresh contexts: H hosts a room, G1 and G2 arrive via the invite link,
  // knock, are token-gated in by H's client, and all three exchange messages.
  console.log('\nroom stage — three browsers, one admin-only MLS room\n');
  const ctxH = await browser.createBrowserContext();
  const ctxG1 = await browser.createBrowserContext();
  const ctxG2 = await browser.createBrowserContext();
  const pageH = await ctxH.newPage();
  const pageG1 = await ctxG1.newPage();
  const pageG2 = await ctxG2.newPage();
  for (const [name, page] of [['H', pageH], ['G1', pageG1], ['G2', pageG2]]) {
    page.on('pageerror', (e) => console.log(`  [${name} pageerror] ${e.message}`));
    page.on('console', (m) => { if (m.type() === 'error') console.log(`  [${name} console] ${m.text()}`); });
  }

  await gotoWithRetry(pageH);
  await pageH.click('#btn-burner');
  await connected(pageH);
  await pageH.waitForFunction(() => !document.getElementById('newchat').hidden, { timeout: WAIT });
  ok('H connected (fresh burner)');

  await pageH.click('#room-name');
  await pageH.type('#room-name', 'Founders');
  await pageH.click('#btn-room');
  await pageH.waitForFunction(
    () => !document.getElementById('room-share').hidden
      && document.getElementById('room-link').textContent.includes('#'),
    { timeout: WAIT },
  );
  const inviteLink = await pageH.evaluate(() => document.getElementById('room-link').textContent);
  if (!/[#].*t=/.test(inviteLink) || /\?[^#]*t=/.test(inviteLink)) {
    throw new Error(`invite token must ride the fragment only — got ${inviteLink}`);
  }
  ok('H opened room “Founders” — invite token rides the URL fragment only');

  const joinViaLink = async (page, label) => {
    await page.goto(inviteLink.replace(/^https:\/\/[^/]+/, URL_.replace(/\/$/, '')), { waitUntil: 'load', timeout: 30_000 });
    await page.click('#btn-burner');
    await connected(page);
    await page.waitForFunction(() => !document.getElementById('knock').hidden, { timeout: WAIT });
    await page.click('#btn-knock');
    await page.waitForFunction(
      () => !document.getElementById('chat').hidden
        && document.getElementById('peer-line').textContent.includes('room'),
      { timeout: WAIT },
    );
    ok(`${label} knocked and was token-gated into the room`);
  };
  await joinViaLink(pageG1, 'G1');
  await joinViaLink(pageG2, 'G2');

  await typeAndSend(pageH, 'welcome both — host here');
  await seesText(pageG1, 'welcome both — host here');
  await seesText(pageG2, 'welcome both — host here');
  ok('host message reached BOTH guests (one MLS room, not two DMs)');

  await typeAndSend(pageG1, 'g1 checking in');
  await seesText(pageH, 'g1 checking in');
  await seesText(pageG2, 'g1 checking in');
  ok('G1 message reached H and G2');

  await typeAndSend(pageG2, 'g2 sees everyone');
  await seesText(pageH, 'g2 sees everyone');
  await seesText(pageG1, 'g2 sees everyone');
  ok('G2 message reached H and G1 — 3-way room proven');

  await pageA.screenshot({ path: join(shots, 'page-a.png'), fullPage: true });
  await pageB.screenshot({ path: join(shots, 'page-b.png'), fullPage: true });
  await pageH.screenshot({ path: join(shots, 'room-host.png'), fullPage: true });
  await pageG1.screenshot({ path: join(shots, 'room-g1.png'), fullPage: true });
  await pageG2.screenshot({ path: join(shots, 'room-g2.png'), fullPage: true });
  console.log(`\nscreenshots: ${shots}`);
} catch (err) {
  fail('e2e run', err);
  try {
    await pageA.screenshot({ path: join(shots, 'page-a-FAIL.png'), fullPage: true });
    await pageB.screenshot({ path: join(shots, 'page-b-FAIL.png'), fullPage: true });
    console.log(`failure screenshots: ${shots}`);
  } catch { /* page already gone */ }
} finally {
  await browser.close().catch(() => {});
  stopVite();
}

console.log(`\nRESULT: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
