// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  deriveOwmKeypair, sealTo, openSealed, encryptMessageTo, decryptMessage, signPersonalMessage,
} from '../src/index.js';

const bobSign = async (m) => signPersonalMessage(m, 'b'.repeat(64));
const eveSign = async (m) => signPersonalMessage(m, 'e'.repeat(64));

test('deriveOwmKeypair is deterministic per wallet', async () => {
  const a = await deriveOwmKeypair(bobSign);
  const b = await deriveOwmKeypair(bobSign);
  assert.equal(a.publicKeyHex, b.publicKeyHex);
  assert.equal(a.publicKey.length, 32);
  const e = await deriveOwmKeypair(eveSign);
  assert.notEqual(a.publicKeyHex, e.publicKeyHex);
});

test('deriveOwmKeypair tolerates a 0x-prefixed wallet signature (regression: wagmi returns 0x…)', async () => {
  const prefixed = async (m) => `0x${await bobSign(m)}`;
  const a = await deriveOwmKeypair(bobSign);
  const b = await deriveOwmKeypair(prefixed);
  assert.equal(a.publicKeyHex, b.publicKeyHex); // same key whether the sig has 0x or not
});

test('seal to Bob → only Bob opens it', async () => {
  const bob = await deriveOwmKeypair(bobSign);
  const sealed = await sealTo({ recipientPublicKey: bob.publicKeyHex, data: new Uint8Array([1, 2, 3, 4, 5]) });
  const out = await openSealed({ sealed, signMessage: bobSign });
  assert.deepEqual(Array.from(out), [1, 2, 3, 4, 5]);
  await assert.rejects(openSealed({ sealed, signMessage: eveSign }), /decryption failed/);
});

test('tampered sealed blob fails', async () => {
  const bob = await deriveOwmKeypair(bobSign);
  const sealed = await sealTo({ recipientPublicKey: bob.publicKey, data: new Uint8Array([9, 9, 9]) });
  const bad = sealed.slice(); bad[bad.length - 1] ^= 1;
  await assert.rejects(openSealed({ sealed: bad, signMessage: bobSign }), /decryption failed/);
});

test('message over an insecure channel: base64 round-trips only for the recipient', async () => {
  const bob = await deriveOwmKeypair(bobSign);
  const blob = await encryptMessageTo({ recipientPublicKey: bob.publicKeyHex, text: 'meet at 8, code is 4417' });
  assert.match(blob, /^owm1:/);
  const read = await decryptMessage({ blob, signMessage: bobSign });
  assert.equal(read, 'meet at 8, code is 4417');
  await assert.rejects(decryptMessage({ blob, signMessage: eveSign }), /decryption failed/);
});
