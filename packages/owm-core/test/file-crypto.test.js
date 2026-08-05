// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  encryptFile, decryptFile, inspect, signPersonalMessage,
} from '../src/index.js';

const KEY = 'c'.repeat(64);
const signMessage = async (msg) => signPersonalMessage(msg, KEY);

function bytes(n) {
  const u = new Uint8Array(n);
  for (let i = 0; i < n; i += 1) u[i] = (i * 7 + 3) % 251;
  return u;
}

test('round-trip: encrypt → decrypt restores bytes, name, and type', async () => {
  const data = bytes(1000);
  const blob = await encryptFile({ data, name: 'cat.jpg', type: 'image/jpeg', signMessage });
  const info = inspect(blob);
  assert.equal(info.ok, true);
  assert.equal(info.schemeName, 'AES-256-GCM');
  assert.equal(info.mode, 1);
  const out = await decryptFile({ blob, signMessage });
  assert.equal(out.name, 'cat.jpg');
  assert.equal(out.type, 'image/jpeg');
  assert.deepEqual(Array.from(out.data), Array.from(data));
});

test('tamper-proof: flip a ciphertext byte → tag fails', async () => {
  const blob = await encryptFile({ data: bytes(64), name: 'x', signMessage });
  const bad = blob.slice(); bad[blob.length - 1] ^= 0x01;
  await assert.rejects(decryptFile({ blob: bad, signMessage }), /decryption failed/);
});

test('tamper-proof: the header is authenticated too (flip a salt byte)', async () => {
  const blob = await encryptFile({ data: bytes(64), name: 'x', signMessage });
  const bad = blob.slice(); bad[8] ^= 0x01; // salt lives at offset 8
  await assert.rejects(decryptFile({ blob: bad, signMessage }), /decryption failed/);
});

test('wrong wallet cannot decrypt', async () => {
  const blob = await encryptFile({ data: bytes(64), name: 'x', signMessage });
  const other = async (msg) => signPersonalMessage(msg, 'd'.repeat(64));
  await assert.rejects(decryptFile({ blob, signMessage: other }), /decryption failed/);
});

test('inspect auto-detects without the key; rejects non-OWMF input', () => {
  assert.equal(inspect(new Uint8Array([1, 2, 3])).ok, false);
});

test('password: round-trips with the right password, fails with the wrong one', async () => {
  const data = bytes(64);
  const blob = await encryptFile({ data, name: 'x', signMessage, password: 'hunter2' });
  assert.equal(inspect(blob).passwordProtected, true);
  const ok = await decryptFile({ blob, signMessage, password: 'hunter2' });
  assert.deepEqual(Array.from(ok.data), Array.from(data));
  await assert.rejects(decryptFile({ blob, signMessage, password: 'wrong' }), /decryption failed/);
});

test('password: seized wallet is not enough — decrypt without it is refused', async () => {
  const blob = await encryptFile({ data: bytes(16), name: 'x', signMessage, password: 'pw' });
  await assert.rejects(decryptFile({ blob, signMessage }), /password required/);
});

test('no password: wallet alone still decrypts (backward compatible)', async () => {
  const blob = await encryptFile({ data: bytes(16), name: 'x', signMessage });
  assert.equal(inspect(blob).passwordProtected, false);
  const out = await decryptFile({ blob, signMessage });
  assert.equal(out.data.length, 16);
});

test('deterministic keying: the same file decrypts twice', async () => {
  const blob = await encryptFile({ data: bytes(32), name: 'x', signMessage });
  const a = await decryptFile({ blob, signMessage });
  const b = await decryptFile({ blob, signMessage });
  assert.deepEqual(Array.from(a.data), Array.from(b.data));
});
