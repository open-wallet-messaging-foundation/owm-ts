// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OWM-APPROVAL (WM-7 §9, 535-537): the M-of-N ceremony end-to-end, offline.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildApprovalRequest, signApproval, verifyApprovalSig,
  aggregateApprovalResult, verifyApprovalResult, actionHash,
} from '../src/approval.js';
import { buildWmApprovalRequest, parseMessage } from '../src/envelope.js';
import { addressFromPrivateKey } from '../src/eth-sign.js';
import { KIND, wireName, kindCode } from '../src/kinds.js';

const NOW = 1770000000; // unix SECONDS (WM-7 convention for 53x kinds)
const KEYS = ['aa'.repeat(32), 'bb'.repeat(32), 'cc'.repeat(32)];
const OUTSIDER = 'dd'.repeat(32);
const SIGNERS = KEYS.map(addressFromPrivateKey);

const wireRelease = () => buildApprovalRequest({
  rp: 'ops.cryptodeposit.org',
  action: 'Release wire #114\n$250,000 to Meridian Trading LLC\nsafeTxHash: 0x' + '12'.repeat(32),
  policy: { m: 2, signers: SIGNERS, exp: NOW + 86400 },
  now: NOW,
});

test('approval kinds are registered; request builds strictly valid', () => {
  assert.equal(wireName(KIND.WmApprovalRequest), 'wm-approval-request');
  assert.equal(kindCode('wm-approval-sig'), 536);
  assert.equal(wireName(537), 'wm-approval-result');
  const req = wireRelease();
  assert.ok(parseMessage(JSON.stringify(req)).ok);
});

test('policy validation: quorum above roster, duplicate roster, empty roster all reject', () => {
  const base = { approvalId: 'ab'.repeat(32), rp: 'rp', action: 'do it', iat: NOW, exp: NOW + 60 };
  assert.throws(() => buildWmApprovalRequest({ ...base, policy: { m: 4, signers: SIGNERS, exp: NOW + 60 } }));
  assert.throws(() => buildWmApprovalRequest({ ...base, policy: { m: 1, signers: [SIGNERS[0], SIGNERS[0].toUpperCase().replace('0X', '0x')], exp: NOW + 60 } }));
  assert.throws(() => buildWmApprovalRequest({ ...base, policy: { m: 1, signers: [], exp: NOW + 60 } }));
  assert.throws(() => buildWmApprovalRequest({ ...base, policy: { m: 1, signers: SIGNERS, exp: NOW + 60, extra: 1 } }));
});

test('the 2-of-3 ceremony: sign, aggregate, verify offline', () => {
  const req = wireRelease();
  const sig0 = signApproval({ privateKey: KEYS[0], request: req });
  const sig2 = signApproval({ privateKey: KEYS[2], request: req });
  assert.ok(parseMessage(JSON.stringify(sig0)).ok);
  assert.ok(verifyApprovalSig(sig0, req, { now: NOW + 10 }).ok);

  const result = aggregateApprovalResult({ request: req, sigs: [sig0, sig2], ts: NOW + 20, now: NOW + 20 });
  assert.ok(parseMessage(JSON.stringify(result)).ok);
  const v = verifyApprovalResult(result, req, { now: NOW + 30 });
  assert.ok(v.ok);
  assert.equal(v.signers.length, 2);
});

test('below quorum never becomes a result; duplicates do not inflate it', () => {
  const req = wireRelease();
  const sig0 = signApproval({ privateKey: KEYS[0], request: req });
  assert.throws(() => aggregateApprovalResult({ request: req, sigs: [sig0], ts: NOW, now: NOW }),
    /quorum not met/);
  assert.throws(() => aggregateApprovalResult({ request: req, sigs: [sig0, sig0], ts: NOW, now: NOW }),
    /quorum not met/);
});

test('an outsider signature is rejected even though it recovers correctly', () => {
  const req = wireRelease();
  const rogue = signApproval({ privateKey: OUTSIDER, request: req });
  assert.match(verifyApprovalSig(rogue, req, { now: NOW }).error, /not in policy/);
});

test('WYSIWYS binding: a signature never transfers to a different action or approval', () => {
  const req = wireRelease();
  const sig0 = signApproval({ privateKey: KEYS[0], request: req });
  const swapped = { ...req, action: req.action.replace('$250,000', '$2,500,000') };
  assert.match(verifyApprovalSig(sig0, swapped, { now: NOW }).error, /action mismatch/);
  const other = buildApprovalRequest({ rp: req.rp, action: req.action, policy: req.policy, now: NOW });
  assert.match(verifyApprovalSig(sig0, other, { now: NOW }).error, /wrong approval/);
});

test('a forged result entry and a tampered aggregate are refused', () => {
  const req = wireRelease();
  const sigs = [KEYS[0], KEYS[1]].map((privateKey) => signApproval({ privateKey, request: req }));
  const result = aggregateApprovalResult({ request: req, sigs, ts: NOW, now: NOW });
  const forged = { ...result, sigs: [result.sigs[0], { ...result.sigs[1], signer: SIGNERS[2] }] };
  assert.ok(!verifyApprovalResult(forged, req, { now: NOW }).ok);
  const padded = { ...result, sigs: [result.sigs[0], result.sigs[0]] };
  assert.match(verifyApprovalResult(padded, req, { now: NOW }).error, /duplicate/);
});

test('expiry closes the signing window; historical audit still verifies without now', () => {
  const req = wireRelease();
  const sigs = [KEYS[0], KEYS[1]].map((privateKey) => signApproval({ privateKey, request: req }));
  const result = aggregateApprovalResult({ request: req, sigs, ts: NOW, now: NOW });
  assert.match(verifyApprovalSig(sigs[0], req, { now: req.exp }).error, /expired/);
  assert.ok(!verifyApprovalResult(result, req, { now: req.exp }).ok, 'acceptance after exp refused');
  assert.ok(verifyApprovalResult(result, req).ok, 'audit without now still verifies the quorum');
  assert.equal(result.actionHash, actionHash(req.action));
});
