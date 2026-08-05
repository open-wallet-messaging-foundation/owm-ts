// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  signBinding, verifyBinding, computeBindingId, canonicalBindingPayload,
  signBindingAttest, verifyBindingAttest, addressFromPrivateKey,
} from '../src/index.js';

test('WM-9 vector: signBinding reproduces the canonical, id, and signature', () => {
  const V = JSON.parse(readFileSync(new URL('../../../api/vectors/bindings.json', import.meta.url)));
  const b = signBinding({ privateKey: V.testPrivateKey, ...V.input });
  assert.equal(b.address, V.expected.address);
  assert.equal(b.subjectRef, V.expected.subjectRef);
  assert.equal(canonicalBindingPayload(b), V.expected.canonicalPayload);
  assert.equal(b.bindingId, V.expected.bindingId);
  assert.equal(b.sig, V.expected.sig);
  assert.equal(verifyBinding(b, { now: V.input.now + 1 }).ok, true);
});

const OWNER = 'a'.repeat(64);
const BANK = 'b'.repeat(64);

test('signBinding → verifyBinding round-trips and recovers the owner', () => {
  const b = signBinding({ privateKey: OWNER, subjectType: 'sms', subjectValue: '+61491570006', direction: 'sink', capabilities: ['notify'], accept: 'secure', now: 1000 });
  const r = verifyBinding(b, { now: 1000 });
  assert.equal(r.ok, true);
  assert.equal(r.address.toLowerCase(), addressFromPrivateKey(OWNER).toLowerCase());
});

test('capability order does not change the binding id (canonical is sorted)', () => {
  const base = { address: '0xabc', subjectType: 'card', subjectRef: 'ref', direction: 'source', accept: 'verified', exp: 9 };
  assert.equal(computeBindingId({ ...base, capabilities: ['notify', 'approve:mandatory'] }), computeBindingId({ ...base, capabilities: ['approve:mandatory', 'notify'] }));
});

test('tampering with capabilities or accept breaks the signature', () => {
  const b = signBinding({ privateKey: OWNER, subjectType: 'card', subjectValue: 'tok_x', direction: 'source', capabilities: ['approve:mandatory'], accept: 'verified', now: 1000 });
  assert.equal(verifyBinding({ ...b, capabilities: ['notify'] }, { now: 1000 }).ok, false);
  assert.equal(verifyBinding({ ...b, accept: 'everything' }, { now: 1000 }).ok, false);
});

test('expired binding is refused', () => {
  const b = signBinding({ privateKey: OWNER, subjectType: 'email', subjectValue: 'a@b.com', direction: 'sink', capabilities: ['notify'], ttlS: 100, now: 1000 });
  assert.equal(verifyBinding(b, { now: 1000 + 101 }).ok, false);
});

test('invalid direction / accept are rejected at signing', () => {
  assert.throws(() => signBinding({ privateKey: OWNER, subjectType: 'sms', subjectValue: 'x', direction: 'nope', capabilities: [] }), /direction/);
  assert.throws(() => signBinding({ privateKey: OWNER, subjectType: 'sms', subjectValue: 'x', direction: 'sink', capabilities: [], accept: 'loose' }), /accept/);
});

test('mutual attestation: the bank countersigns the bindingId + its domain', () => {
  const b = signBinding({ privateKey: OWNER, subjectType: 'bank-account', subjectValue: 'BSB 000-000 12345678', direction: 'source', capabilities: ['approve:mandatory', 'verify', 'exclusive'], accept: 'verified', now: 1000 });
  const att = signBindingAttest({ privateKey: BANK, bindingId: b.bindingId, domain: 'bank.example', now: 1000 });
  const v = verifyBindingAttest(att);
  assert.equal(v.ok, true);
  assert.equal(v.attester.toLowerCase(), addressFromPrivateKey(BANK).toLowerCase());
  assert.equal(v.domain, 'bank.example');
  assert.equal(v.bindingId, b.bindingId);
});
