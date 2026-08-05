// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OWM-AUTH / OWM-GRANT live smoke — wallet 2FA + capability grants over a
// REAL DM on the real XMTP `dev` network. Two ephemeral
// identities ("service" = relying party, "wallet-user" = authenticator);
// every envelope in every ceremony actually rides the DM as JSON text and
// is strict-parsed with @open-wallet-messaging/core parseMessage on receipt. Proves:
//   (1) enrollment over the wire: challenge → signed 531 → the service pins
//       exactly the authenticator's address;
//   (2) 2FA happy path: 530 rides out WITHOUT the match code (number-entry),
//       the user types the code into the wallet, 531 rides back, verifies;
//   (3) step-up WYSIWYS: the verified response is bound to the exact
//       wire-release action string — an action-tampered copy fails;
//   (4) a wrong match code fails match-mismatch AND burns the nonce: a
//       corrected replay for the same challenge is unknown-challenge;
//   (5) repeated failures hit the lockout threshold: the 5th failure locks,
//       onSecurityAlert fires once, a correctly-signed response then
//       verifies as 'locked', and no new challenge can be issued;
//   (6) grants: 532 request → wallet-approved 533 → acceptGrant + verifyGrant
//       → wallet's 534 revoke → verifyGrant fails 'revoked';
//   (7) domain separation on the wire: a valid 531 sig cannot verify as a
//       grant, and a valid 533 sig cannot verify as an auth response.
//
// Run via ./run.sh (stage 3). Pure XMTP + JS — no cargo, never skips.
// Exit code != 0 on any failure.

import { randomBytes } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { toBytes } from 'viem';
import * as sdk from '@xmtp/node-sdk';
import {
  parseMessage, buildWmGrant, buildWmAuthResponse, randomNonce, computeGrantId,
} from '../packages/owm-core/src/index.js';
import {
  OwmAuthServer, GrantServer, OwmAuthenticator, MemoryGrantRegistry,
  DEFAULT_MAX_FAILURES,
} from '../packages/owm-auth/src/index.js';

let pass = 0; let fail = 0;
function expect(cond, label) {
  if (cond) { pass += 1; console.log(`  ✔ ${label}`); }
  else { fail += 1; console.error(`  ✖ ${label}`); }
}

const { Client, IdentifierKind, encodeText } = sdk;
const sendText = (conv, str) => conv.send(encodeText(str));
const dbDir = mkdtempSync(join(tmpdir(), 'owm-auth-smoke-'));

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

// Every envelope rides the DM as JSON text …
const sendEnvelope = (conv, env) => sendText(conv, JSON.stringify(env));

// … and comes back off the wire through STRICT parsing only. `pred` keys on
// a unique field (challenge / nonce / grantId / sig) so re-scans of the
// growing DM history always land on the right message.
function recvEnvelope(client, conv, kind, pred, label) {
  return poll(label ?? `receive ${kind}`, async () => {
    await client.conversations.sync();
    await conv.sync();
    for (const msg of await conv.messages()) {
      if (typeof msg.content !== 'string') continue;
      const parsed = parseMessage(msg.content);
      if (parsed.ok && parsed.kind === kind && pred(parsed.body)) return parsed.body;
    }
    return null;
  });
}

const RP = 'accounts.example.org';
const AUD = 'https://api.example.org';
const USER = 'alice@example.org';
// A user "types" the code they read off the initiating screen; the wrong
// arm types a plausible-but-wrong one (same digit count, guaranteed ≠).
const wrongOf = (code) => String((Number(code) + 1) % 10 ** code.length).padStart(code.length, '0');

let exitCode = 1;
try {
  console.log('— clients (ephemeral, dev network) —');
  const service = await makeClient('service');
  const walletUser = await makeClient('wallet-user');

  // The wallet's OWM-AUTH signing key is its own secret — deliberately NOT
  // the XMTP identity key (a real wallet holds many keys behind one inbox).
  const authenticator = new OwmAuthenticator({ privateKey: generatePrivateKey() });
  const walletAddr = authenticator.addressFor(RP);
  console.log(`  · wallet-user auth address (never pasted, only proven): ${walletAddr}`);

  const alerts = [];
  const server = new OwmAuthServer({ rp: RP, onSecurityAlert: (a) => alerts.push(a) });

  console.log('— the DM: service ↔ wallet-user (the only conversation in this smoke) —');
  const dmService = await service.client.conversations.createDmWithIdentifier({
    identifier: walletUser.account.address.toLowerCase(),
    identifierKind: IdentifierKind.Ethereum,
  });
  let dmWallet = null; // assigned once the first envelope lands (scenario a)

  // One complete 2FA ceremony over the real DM: 530 rides service→wallet,
  // the wallet renders it (optionally through `mutateChallenge`, the MITM
  // hook), the user types mutateCode(matchCode), the 531 rides back
  // wallet→service, the service verifies. Both envelopes cross the wire,
  // both strict-parsed.
  async function authRoundTrip({ phase = 'auth', action, mutateChallenge = (e) => e, mutateCode = (c) => c }) {
    const issued = phase === 'enroll'
      ? await server.createEnrollmentChallenge({ userId: USER })
      : await server.createChallenge({ userId: USER, action });
    await sendEnvelope(dmService, issued.envelope);
    const challengeOnWire = await recvEnvelope(walletUser.client, dmWallet, 'wm-auth-challenge',
      (b) => b.challenge === issued.challengeId, `wallet receives 530 (${phase})`);
    const response = authenticator.handleAuthChallenge(mutateChallenge(challengeOnWire), {
      matchCode: mutateCode(issued.matchCode),
    });
    await sendEnvelope(dmWallet, response);
    const responseOnWire = await recvEnvelope(service.client, dmService, 'wm-auth-response',
      (b) => b.challenge === issued.challengeId && b.sig === response.sig, `service receives 531 (${phase})`);
    const result = phase === 'enroll'
      ? await server.verifyEnrollmentProof(responseOnWire)
      : await server.verifyResponse(responseOnWire);
    return { issued, challengeOnWire, responseOnWire, result };
  }

  // ── a. enrollment over the wire ────────────────────────────────────────────
  console.log('— a. enrollment: challenge rides out, signed proof rides back —');
  const enrollIssued = await server.createEnrollmentChallenge({ userId: USER });
  await sendEnvelope(dmService, enrollIssued.envelope);
  dmWallet = await poll('wallet-user sees the DM', async () => {
    await walletUser.client.conversations.sync();
    return (await walletUser.client.conversations.listDms())[0] ?? null;
  });
  const enrollCh = await recvEnvelope(walletUser.client, dmWallet, 'wm-auth-challenge',
    (b) => b.challenge === enrollIssued.challengeId, 'wallet receives 530 (enroll)');
  const enrollResp = authenticator.handleAuthChallenge(enrollCh, { matchCode: enrollIssued.matchCode });
  await sendEnvelope(dmWallet, enrollResp);
  const enrollRespWire = await recvEnvelope(service.client, dmService, 'wm-auth-response',
    (b) => b.challenge === enrollIssued.challengeId, 'service receives 531 (enroll)');
  const enrolled = await server.verifyEnrollmentProof(enrollRespWire);
  expect(enrolled.ok === true, 'enrollment proof verifies — both envelopes rode the real DM');
  expect((await server.getEnrollment(USER))?.address?.toLowerCase() === walletAddr.toLowerCase(),
    "pinned address equals the authenticator's (proof-of-possession, never pasted)");

  // ── b. 2FA happy path ──────────────────────────────────────────────────────
  console.log('— b. happy path: log in with the user-typed match code —');
  const b = await authRoundTrip({ action: 'log in' });
  expect(b.result.ok === true && b.result.userId === USER && b.result.action === 'log in',
    'verifyResponse ok — the user typed the code off the login screen');
  expect(!('match' in b.challengeOnWire) && !('matchCode' in b.challengeOnWire),
    'the match code did NOT ride the challenge (number-entry, strict SPEC)');
  expect(b.challengeOnWire._kind === 'wm-auth-challenge' && b.responseOnWire._kind === 'wm-auth-response',
    '530 and 531 strict-parsed off the wire in both directions');

  // ── c. step-up WYSIWYS ─────────────────────────────────────────────────────
  const WIRE_ACTION = 'Release wire transfer #4821: $25,000.00 USD to Acme Corp, acct ****1234';
  console.log('— c. step-up WYSIWYS: the action string IS what gets signed —');
  const c1 = await authRoundTrip({ action: WIRE_ACTION });
  expect(c1.result.ok === true && c1.result.action === WIRE_ACTION,
    'verified response is bound to exactly the wire-release action string');
  const c2 = await authRoundTrip({
    action: WIRE_ACTION,
    // MITM bumps the amount on the wallet's copy: the wallet signs what it
    // shows the user, so the service's verification MUST fail.
    mutateChallenge: (env) => ({ ...env, action: env.action.replace('$25,000.00', '$925,000.00') }),
  });
  expect(c2.result.ok === false && c2.result.reason === 'bad-signature',
    'action-tampered copy fails verification (WYSIWYS binding holds)');

  // ── d. wrong match code + burned nonce ─────────────────────────────────────
  console.log('— d. wrong match code fails, and the nonce is burned by the attempt —');
  const dIssued = await server.createChallenge({ userId: USER, action: 'log in' });
  await sendEnvelope(dmService, dIssued.envelope);
  const dCh = await recvEnvelope(walletUser.client, dmWallet, 'wm-auth-challenge',
    (b2) => b2.challenge === dIssued.challengeId, 'wallet receives 530 (d)');
  const dWrong = authenticator.handleAuthChallenge(dCh, { matchCode: wrongOf(dIssued.matchCode) });
  await sendEnvelope(dmWallet, dWrong);
  const dWrongWire = await recvEnvelope(service.client, dmService, 'wm-auth-response',
    (b2) => b2.challenge === dIssued.challengeId && b2.sig === dWrong.sig, 'service receives wrong-code 531');
  const dRes1 = await server.verifyResponse(dWrongWire);
  expect(dRes1.ok === false && dRes1.reason === 'match-mismatch',
    'wrong 2-digit code → match-mismatch');
  const dFixed = authenticator.handleAuthChallenge(dCh, { matchCode: dIssued.matchCode });
  await sendEnvelope(dmWallet, dFixed);
  const dFixedWire = await recvEnvelope(service.client, dmService, 'wm-auth-response',
    (b2) => b2.challenge === dIssued.challengeId && b2.sig === dFixed.sig, 'service receives corrected 531');
  const dRes2 = await server.verifyResponse(dFixedWire);
  expect(dRes2.ok === false && dRes2.reason === 'unknown-challenge',
    'corrected replay for the SAME challenge → unknown-challenge (nonce burned)');

  // ── e. lockout + security alert ────────────────────────────────────────────
  console.log(`— e. lockout: ${DEFAULT_MAX_FAILURES} failures lock the user, alert fires once —`);
  await server.unlockUser(USER); // zero the ledger c/d left behind — e must hit the threshold from a clean slate
  // A challenge issued (and correctly signed) BEFORE the lock, held back
  // like a delayed message — it must verify as 'locked', not succeed.
  const spare = await server.createChallenge({ userId: USER, action: 'log in' });
  await sendEnvelope(dmService, spare.envelope);
  const spareCh = await recvEnvelope(walletUser.client, dmWallet, 'wm-auth-challenge',
    (b2) => b2.challenge === spare.challengeId, 'wallet receives 530 (spare)');
  const spareResp = authenticator.handleAuthChallenge(spareCh, { matchCode: spare.matchCode });
  let lockedAt = 0; let lastE = null;
  for (let i = 1; i <= DEFAULT_MAX_FAILURES; i += 1) {
    lastE = await authRoundTrip({ action: 'log in', mutateCode: wrongOf });
    console.log(`  · failure ${i}/${DEFAULT_MAX_FAILURES}: ${lastE.result.reason}${lastE.result.locked ? ' → LOCKED' : ''}`);
    if (lastE.result.locked) { lockedAt = i; break; }
  }
  expect(lockedAt === DEFAULT_MAX_FAILURES && lastE.result.locked === true,
    `verifyResponse reports locked on exactly the ${DEFAULT_MAX_FAILURES}th failure`);
  expect(alerts.length === 1 && alerts[0].reason === 'lockout' && alerts[0].userId === USER
    && alerts[0].failures === DEFAULT_MAX_FAILURES,
  'onSecurityAlert fired exactly once (reason lockout, right user)');
  await sendEnvelope(dmWallet, spareResp);
  const spareWire = await recvEnvelope(service.client, dmService, 'wm-auth-response',
    (b2) => b2.challenge === spare.challengeId, 'service receives held-back 531');
  const spareRes = await server.verifyResponse(spareWire);
  expect(spareRes.ok === false && spareRes.reason === 'locked',
    'post-lock verifyResponse returns locked even for a correctly-signed response');
  let lockedChallengeRefused = false;
  try { await server.createChallenge({ userId: USER, action: 'log in' }); }
  catch { lockedChallengeRefused = true; }
  expect(lockedChallengeRefused, 'a locked user cannot even be issued a new challenge');

  // ── f. grant lifecycle over the wire ───────────────────────────────────────
  console.log('— f. grant: 532 → 533 → accept/verify → 534 revoke → revoked —');
  const grants = new GrantServer({ rp: RP, aud: AUD, registry: new MemoryGrantRegistry() });
  const grantReq = grants.buildGrantRequest({ client: 'krypty-web', scope: 'payments:read history:read' });
  await sendEnvelope(dmService, grantReq);
  const gotReq = await recvEnvelope(walletUser.client, dmWallet, 'wm-grant-request',
    (b2) => b2.nonce === grantReq.nonce, 'wallet receives 532');
  expect(gotReq._kind === 'wm-grant-request' && gotReq.scope === 'payments:read history:read',
    '532 grant request strict-parsed off the wire (WYSIWYS consent screen input)');
  const grantEnv = authenticator.approveGrantRequest(gotReq);
  await sendEnvelope(dmWallet, grantEnv);
  const gotGrant = await recvEnvelope(service.client, dmService, 'wm-grant',
    (b2) => b2.nonce === grantReq.nonce, 'service receives 533');
  const accepted = await grants.acceptGrant(gotGrant, { expectedAddress: walletAddr });
  expect(accepted.ok === true, '533 accepted at issuance (answers OUR nonce, signature chain verifies)');
  expect(accepted.grantId === computeGrantId(gotReq),
    'grantId is deterministic — wallet and service compute the same id from the fields');
  const presented = await grants.verifyGrant(gotGrant, { expectedAddress: walletAddr });
  expect(presented.ok === true && presented.scope === gotReq.scope && presented.client === 'krypty-web',
    'presentation-time verifyGrant ok (offline, no token endpoint)');
  const revokeEnv = authenticator.revokeGrant(accepted.grantId);
  await sendEnvelope(dmWallet, revokeEnv);
  const gotRevoke = await recvEnvelope(service.client, dmService, 'wm-grant-revoke',
    (b2) => b2.grantId === accepted.grantId, 'service receives 534');
  const revoked = await grants.revoke(gotRevoke);
  expect(revoked.ok === true, '534 revoke strict-parsed + accepted (signed by the granting key)');
  const afterRevoke = await grants.verifyGrant(gotGrant, { expectedAddress: walletAddr });
  expect(afterRevoke.ok === false && afterRevoke.reason === 'revoked',
    'verifyGrant now fails revoked — revocation wins over everything');

  // ── g. cross-domain separation on the wire ─────────────────────────────────
  console.log('— g. domain separation: auth sigs are not grant sigs and vice versa —');
  await server.unlockUser(USER); // release the e-lock: g needs live challenges
  // Arm 1: dress scenario b's VALID 531 signature up as a grant.
  const gIat = Math.floor(Date.now() / 1000);
  const forgedGrant = buildWmGrant({
    rp: RP, client: 'krypty-web', scope: 'payments:read', aud: AUD,
    nonce: randomNonce(32), iat: gIat, exp: gIat + 900,
    addr: b.responseOnWire.addr, sig: b.responseOnWire.sig,
  });
  await sendEnvelope(dmWallet, forgedGrant);
  const gotForgedGrant = await recvEnvelope(service.client, dmService, 'wm-grant',
    (b2) => b2.nonce === forgedGrant.nonce, 'service receives forged 533');
  const forgedGrantRes = await grants.verifyGrant(gotForgedGrant, { expectedAddress: walletAddr });
  expect(forgedGrantRes.ok === false && forgedGrantRes.reason === 'bad-signature',
    "a valid 531 auth signature can NOT verify as a grant (domain tag 'owm-grant-v1')");
  // Arm 2: dress scenario f's VALID 533 signature up as an auth response.
  const g2 = await server.createChallenge({ userId: USER, action: 'log in' });
  await sendEnvelope(dmService, g2.envelope);
  await recvEnvelope(walletUser.client, dmWallet, 'wm-auth-challenge',
    (b2) => b2.challenge === g2.challengeId, 'wallet receives 530 (g)');
  const forgedResp = buildWmAuthResponse({
    challenge: g2.challengeId, match: g2.matchCode, addr: gotGrant.addr, sig: gotGrant.sig,
  });
  await sendEnvelope(dmWallet, forgedResp);
  const gotForgedResp = await recvEnvelope(service.client, dmService, 'wm-auth-response',
    (b2) => b2.challenge === g2.challengeId, 'service receives forged 531');
  const forgedRespRes = await server.verifyResponse(gotForgedResp);
  expect(forgedRespRes.ok === false && forgedRespRes.reason === 'bad-signature',
    "a valid 533 grant signature can NOT verify as an auth response (domain tag 'owm-auth-v1')");

  console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
  exitCode = fail === 0 ? 0 : 1;
} catch (err) {
  console.error(`\n✖ UNCAUGHT: ${err?.stack ?? err}`);
  console.log(`\nRESULT: ${pass} passed, ${fail + 1} failed`);
  exitCode = 1;
}
process.exit(exitCode);
