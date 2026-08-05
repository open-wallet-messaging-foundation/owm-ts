// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hexToBytes } from '@noble/hashes/utils.js';
import {
  signPersonalMessage, deriveOwmKeypair, decryptFile, decryptMessage,
} from '../src/index.js';

// The normative WM-8 conformance vectors. Any implementation MUST reproduce
// these; this test proves the reference does.
const V = JSON.parse(readFileSync(new URL('../../../api/vectors/owmf.json', import.meta.url)));
const sign = async (m) => signPersonalMessage(m, V.testPrivateKey);
const dec = new TextDecoder();

test('WM-8 vector: the OWM identity public key derives deterministically', async () => {
  const kp = await deriveOwmKeypair(sign);
  assert.equal(kp.publicKeyHex, V.identity.owmIdentityPublicKey);
});

test('WM-8 vector: the OWMF file decrypts to the expected plaintext + name', async () => {
  const out = await decryptFile({ blob: hexToBytes(V.file.owmfHex), signMessage: sign });
  assert.equal(dec.decode(out.data), V.file.expectedPlaintextUtf8);
  assert.equal(out.name, V.file.expectedName);
  assert.equal(out.type, V.file.expectedType);
});

test('WM-8 vector: the owm1 message opens to the expected text', async () => {
  assert.equal(await decryptMessage({ blob: V.message.owm1, signMessage: sign }), V.message.expectedPlaintextUtf8);
});
