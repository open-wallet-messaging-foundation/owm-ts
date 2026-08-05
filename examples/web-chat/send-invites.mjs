#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// Text the chat link to one or more phones. Zero dependencies — one
// form-encoded fetch against Twilio's REST API, exactly like
// examples/wallet-chat does it. Without TWILIO_* credentials it prints a
// clearly-marked mock line instead, so it always runs.
//
//   node send-invites.mjs <url> <phone1> [phone2] …
//   node send-invites.mjs "https://192.168.1.20:5173/#peer=0xABC…" +15551234567
//
// Phone numbers come ONLY from the command line — never hardcode one here.
// The Twilio auth token rides basic auth and is never printed or logged.

import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

// .env in this folder wins; ../wallet-chat/.env is the fallback (you likely
// already put your Twilio credentials there). Real env vars beat both, and
// values loaded first are not overwritten by later files.
for (const envFile of [join(HERE, '.env'), join(HERE, '..', 'wallet-chat', '.env')]) {
  try {
    process.loadEnvFile(envFile);
  } catch {
    /* missing file is fine — mock mode still works */
  }
}

const [url, ...phones] = process.argv.slice(2);

if (!url || phones.length === 0) {
  console.error('usage: node send-invites.mjs <url> <phone1> [phone2] …');
  console.error('   eg: node send-invites.mjs "https://192.168.1.20:5173/#peer=0xABC…" +15551234567');
  process.exit(1);
}
if (!/^https?:\/\//.test(url)) {
  console.error(`that does not look like a URL: ${url}`);
  process.exit(1);
}
// OWM rule: anything sensitive rides the URL *fragment* (#…), never the
// query string. Warn if the link smells like it breaks that.
if (/\?[^#]*(t|token|key|secret)=/i.test(url)) {
  console.error('refusing: the URL carries a token-like value in its QUERY STRING.');
  console.error('Move it to a fragment (#…) — query strings end up in server logs.');
  process.exit(1);
}

const body = `OWM chat: open in your MetaMask app's browser: ${url}`;

async function sendSms(to) {
  const sid = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  const from = process.env.TWILIO_FROM;
  if (sid && token && from) {
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
    return;
  }
  console.log(`📱 SMS (mock — set TWILIO_* env vars to really send) → ${to}: ${body}`);
}

let failed = 0;
for (const phone of phones) {
  if (!/^\+[0-9]{6,15}$/.test(phone)) {
    console.error(`skipping "${phone}" — use E.164 format like +15551234567`);
    failed += 1;
    continue;
  }
  try {
    await sendSms(phone);
  } catch (err) {
    console.error(String(err.message ?? err));
    failed += 1;
  }
}
process.exit(failed === 0 ? 0 : 1);
