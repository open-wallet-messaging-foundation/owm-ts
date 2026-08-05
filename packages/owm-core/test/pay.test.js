// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OWM-PAY (WM-4, 543-546): strict envelope SPECS + signing chains.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildWmSettlementCard, buildWmTxIntent, buildWmTxReference, buildWmBroadcastRequest,
  parseMessage, randomNonce,
} from '../src/envelope.js';
import {
  createSettlementCard, verifySettlementCard,
  createBroadcastRequest, verifyBroadcastRequest,
} from '../src/pay.js';
import { addressFromPrivateKey } from '../src/eth-sign.js';
import { KIND, wireName, kindCode, SETTLEMENT_METHODS, BROADCAST_PURPOSES } from '../src/kinds.js';

const TS = 1770000000000;
const KEY = '33'.repeat(32);
const KEY_M = '44'.repeat(32);
const SIG = 'ab'.repeat(65);
const ADDR = '0x1111111111111111111111111111111111111111';
const EVM_ACCT = 'eip155:1:0x1111111111111111111111111111111111111111';
const SOL_ACCT = 'solana:mainnet:6VvDLKNiE8cQpfyGyEDGrM4Z6JU3T2H1CY6ihMSAdvSo';

test('new pay/presence kinds are registered both ways', () => {
  assert.equal(wireName(KIND.WmSettlementCard), 'wm-settlement-card');
  assert.equal(kindCode('wm-tx-intent'), 544);
  assert.equal(wireName(545), 'wm-tx-reference');
  assert.equal(kindCode('wm-broadcast-request'), 546);
  assert.equal(wireName(KIND.WmCallAttestation), 'wm-call-attestation');
});

// --- wm-settlement-card (543) -----------------------------------------------

const goodAccounts = () => [
  { account: EVM_ACCT, methods: ['transfer', 'token-transfer', 'contract-call'], assets: ['eip155:1/erc20:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'] },
  { account: SOL_ACCT, methods: ['transfer'], memoRequired: true, minConfirmations: 32, proof: 'base58sig-opaque-until-verified' },
];

test('a signed settlement card builds, round-trips, and verifies', () => {
  const card = createSettlementCard({ privateKey: KEY, accounts: goodAccounts(), ts: TS, exp: TS + 86400_000 });
  assert.ok(parseMessage(JSON.stringify(card)).ok);
  const v = verifySettlementCard(card, TS + 1);
  assert.ok(v.ok);
  assert.equal(v.addr, addressFromPrivateKey(KEY));
});

test('settlement card rejects bad accounts: CAIP shape, unknown method, extra key, bad conf', () => {
  const base = { addr: ADDR, ts: TS, sig: SIG };
  assert.throws(() => buildWmSettlementCard({ ...base, accounts: [] }));
  assert.throws(() => buildWmSettlementCard({ ...base, accounts: [{ account: '0xnotcaip', methods: ['transfer'] }] }));
  assert.throws(() => buildWmSettlementCard({ ...base, accounts: [{ account: EVM_ACCT, methods: ['teleport'] }] }));
  assert.throws(() => buildWmSettlementCard({ ...base, accounts: [{ account: EVM_ACCT, methods: ['transfer'], smuggled: 1 }] }));
  assert.throws(() => buildWmSettlementCard({ ...base, accounts: [{ account: EVM_ACCT, methods: ['transfer'], minConfirmations: 1.5 }] }));
});

test('tampering a settlement card account kills the signature; expiry enforced', () => {
  const card = createSettlementCard({ privateKey: KEY, accounts: goodAccounts(), ts: TS, exp: TS + 1000 });
  const swapped = { ...card, accounts: [{ ...card.accounts[0], account: 'eip155:1:0x2222222222222222222222222222222222222222' }, card.accounts[1]] };
  assert.ok(!verifySettlementCard(swapped, TS + 1).ok, 'redirected account must not verify');
  assert.equal(verifySettlementCard(card, TS + 1000).error, 'expired');
});

// --- wm-tx-intent (544) / wm-tx-reference (545) ------------------------------

test('tx intent round-trips for every core method; payload must be an object', () => {
  for (const method of SETTLEMENT_METHODS) {
    const env = buildWmTxIntent({
      intentId: 'ab'.repeat(32), chain: 'eip155:8453', method,
      payload: { calls: [{ to: ADDR, value: '0x0' }] }, note: 'dinner', ts: TS,
    });
    assert.ok(parseMessage(JSON.stringify(env)).ok);
  }
  assert.throws(() => buildWmTxIntent({ intentId: 'ab'.repeat(32), chain: 'eip155:1', method: 'transfer', payload: [1, 2], ts: TS }));
  assert.throws(() => buildWmTxIntent({ intentId: 'ab'.repeat(32), chain: 'EIP155:1', method: 'transfer', payload: {}, ts: TS }));
  assert.throws(() => buildWmTxIntent({ intentId: 'short', chain: 'eip155:1', method: 'transfer', payload: {}, ts: TS }));
});

test('tx reference round-trips with and without intent correlation', () => {
  const solid = buildWmTxReference({ intentId: 'cd'.repeat(32), chain: 'eip155:1', txHash: `0x${'ef'.repeat(32)}`, ts: TS });
  assert.ok(parseMessage(JSON.stringify(solid)).ok);
  const unsolicited = buildWmTxReference({ chain: 'solana:mainnet', txHash: '5wHu1qwD4kV1DPa6oNSd8H3PYuKVnKGYnqYJxLxyz111', ts: TS });
  assert.ok(parseMessage(JSON.stringify(unsolicited)).ok);
  assert.throws(() => buildWmTxReference({ chain: 'nochain', txHash: '0xab', ts: TS }));
});

// --- wm-broadcast-request (546) ----------------------------------------------

test('a signed tip jar builds, round-trips, verifies, and expires', () => {
  const jar = createBroadcastRequest({
    privateKey: KEY, nonce: randomNonce(), purpose: 'donation',
    asset: 'USDC', targets: [EVM_ACCT, SOL_ACCT], memo: 'encore fund',
    ts: TS, exp: TS + 7200_000,
  });
  assert.ok(parseMessage(JSON.stringify(jar)).ok);
  assert.ok(!('amount' in jar), 'donation = open amount');
  const v = verifyBroadcastRequest(jar, TS + 1);
  assert.ok(v.ok);
  assert.equal(v.requester, addressFromPrivateKey(KEY));
  assert.equal(verifyBroadcastRequest(jar, TS + 7200_000).error, 'expired');
});

test('the poisoning arm: redirected targets or a re-signing impostor must not verify as the requester', () => {
  const jar = createBroadcastRequest({
    privateKey: KEY, nonce: randomNonce(), purpose: 'ticket', amount: '25',
    asset: 'USDC', targets: [EVM_ACCT], ts: TS, exp: TS + 1000,
  });
  const redirected = { ...jar, targets: ['eip155:1:0x9999999999999999999999999999999999999999'] };
  assert.ok(!verifyBroadcastRequest(redirected, TS + 1).ok, 'swapped receive target kills the signature');
  const mallory = createBroadcastRequest({
    privateKey: KEY_M, nonce: jar.nonce, purpose: 'ticket', amount: '25',
    asset: 'USDC', targets: ['eip155:1:0x9999999999999999999999999999999999999999'], ts: TS, exp: TS + 1000,
  });
  const forged = { ...mallory, requester: jar.requester };
  assert.match(verifyBroadcastRequest(forged, TS + 1).error, /not the requester/);
});

test('broadcast request rejects float-ish amounts, bad purpose, exp <= ts', () => {
  const base = { privateKey: KEY, nonce: randomNonce(), targets: [EVM_ACCT], ts: TS, exp: TS + 1 };
  assert.throws(() => createBroadcastRequest({ ...base, purpose: 'donation', amount: '1e5' }));
  assert.throws(() => createBroadcastRequest({ ...base, purpose: 'donation', amount: '-3' }));
  assert.throws(() => createBroadcastRequest({ ...base, purpose: 'begging' }));
  assert.throws(() => createBroadcastRequest({ ...base, purpose: 'donation', exp: TS }));
  assert.deepEqual(BROADCAST_PURPOSES, ['donation', 'ticket', 'payment']);
});
