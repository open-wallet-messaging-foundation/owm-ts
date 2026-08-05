// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  signAttestation, verifyAttestation, canonicalAttestation, computeAttestationId,
} from '../src/index.js';

const ID = JSON.parse(readFileSync(new URL('../../../api/test-identities.json', import.meta.url))).identities;
const issuer = ID.issuer; const alice = ID.alice; const bob = ID.bob;

test('WM-13 vector: signAttestation reproduces canonical, id, and signature', () => {
  const V = JSON.parse(readFileSync(new URL('../../../api/vectors/attestation.json', import.meta.url)));
  const a = signAttestation({ privateKey: V.privateKey, ...V.input });
  assert.equal(canonicalAttestation(a), V.expected.canonicalPayload);
  assert.equal(a.attestationId, V.expected.attestationId);
  assert.equal(a.sig, V.expected.sig);
  assert.equal(verifyAttestation(a, { now: V.input.now + 1 }).issuer, V.expected.issuer);
});

test('third-party attestation recovers the ISSUER, not the subject', () => {
  const a = signAttestation({ privateKey: issuer.privateKey, subject: alice.address, claimType: 'kyc-tier', claim: { tier: 2 }, anchor: 'bank.example', now: 1000 });
  const r = verifyAttestation(a, { now: 1000 });
  assert.equal(r.ok, true);
  assert.equal(r.issuer, issuer.address);
  assert.equal(r.subject.toLowerCase(), alice.address.toLowerCase());
});

test('self-attestation (issuer == subject) verifies', () => {
  const a = signAttestation({ privateKey: alice.privateKey, subject: alice.address, claimType: 'credential', claim: { handle: 'sax' }, now: 1000 });
  assert.equal(verifyAttestation(a, { now: 1000 }).ok, true);
});

test('non-tamper: mutating the claim breaks verification', () => {
  const a = signAttestation({ privateKey: issuer.privateKey, subject: alice.address, claimType: 'kyc-tier', claim: { tier: 2 }, now: 1000 });
  assert.equal(verifyAttestation({ ...a, claim: { tier: 9 } }, { now: 1000 }).ok, false);
  assert.equal(computeAttestationId({ ...a, claim: { tier: 9 } }) === a.attestationId, false);
});

test('expired attestation refused; wrong expected issuer/subject refused', () => {
  const a = signAttestation({ privateKey: issuer.privateKey, subject: alice.address, claimType: 'x', claim: {}, ttlS: 100, now: 1000 });
  assert.equal(verifyAttestation(a, { now: 1101 }).ok, false);
  assert.equal(verifyAttestation(a, { now: 1000, expectedIssuer: bob.address }).ok, false);
  assert.equal(verifyAttestation(a, { now: 1000, expectedSubject: bob.address }).ok, false);
});
