// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import test from 'node:test';
import assert from 'node:assert/strict';
import { addressFromPrivateKey, toChecksumAddress, signPersonalMessage } from '@open-wallet-messaging/core';
import { OwmSiweMessage, SiweErrorType, generateNonce } from '../src/siwe.js';

const KEY = `0x${'11'.repeat(32)}`;
const ADDR55 = toChecksumAddress(addressFromPrivateKey(KEY)); // 0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A

const FIELDS = {
  domain: 'app.example.org',
  address: ADDR55,
  statement: 'Sign in to Example',
  uri: 'https://app.example.org/login',
  version: '1',
  chainId: 1,
  nonce: '32891756',
  issuedAt: '2026-07-13T00:00:00.000Z',
  expirationTime: '2026-07-13T00:10:00.000Z',
};

// The golden vector: byte-exact EIP-4361 output for FIELDS above.
const GOLDEN = [
  'app.example.org wants you to sign in with your Ethereum account:',
  '0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A',
  '',
  'Sign in to Example',
  '',
  'URI: https://app.example.org/login',
  'Version: 1',
  'Chain ID: 1',
  'Nonce: 32891756',
  'Issued At: 2026-07-13T00:00:00.000Z',
  'Expiration Time: 2026-07-13T00:10:00.000Z',
].join('\n');

test('golden vector: prepareMessage emits the exact EIP-4361 string', () => {
  assert.equal(new OwmSiweMessage(FIELDS).prepareMessage(), GOLDEN);
  assert.equal(ADDR55, '0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A');
});

test('parse ↔ format round-trips byte-for-byte (with and without optional fields)', () => {
  const parsed = new OwmSiweMessage(GOLDEN);
  assert.equal(parsed.domain, 'app.example.org');
  assert.equal(parsed.address, ADDR55);
  assert.equal(parsed.statement, 'Sign in to Example');
  assert.equal(parsed.chainId, 1);
  assert.equal(parsed.nonce, '32891756');
  assert.equal(parsed.expirationTime, '2026-07-13T00:10:00.000Z');
  assert.equal(parsed.prepareMessage(), GOLDEN);
  // no statement → EIP-4361's double blank line; still round-trips
  const bare = new OwmSiweMessage({ ...FIELDS, statement: undefined });
  const msg = bare.prepareMessage();
  assert.ok(msg.includes(':\n0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A\n\n\nURI: '));
  assert.equal(new OwmSiweMessage(msg).prepareMessage(), msg);
  // full optional set round-trips
  const full = new OwmSiweMessage({
    ...FIELDS,
    scheme: 'https',
    notBefore: '2026-07-12T00:00:00.000Z',
    requestId: 'req-123',
    resources: ['https://app.example.org/r/1', 'ipfs://bafy123'],
  });
  const fullMsg = full.prepareMessage();
  assert.ok(fullMsg.startsWith('https://app.example.org wants you to sign in'));
  assert.ok(fullMsg.endsWith('Resources:\n- https://app.example.org/r/1\n- ipfs://bafy123'));
  const reparsed = new OwmSiweMessage(fullMsg);
  assert.equal(reparsed.scheme, 'https');
  assert.deepEqual(reparsed.resources, ['https://app.example.org/r/1', 'ipfs://bafy123']);
  assert.equal(reparsed.prepareMessage(), fullMsg);
});

test('a signed golden message verifies; the siwe response shape is preserved', async () => {
  const msg = new OwmSiweMessage(GOLDEN);
  const signature = `0x${signPersonalMessage(GOLDEN, KEY)}`;
  const res = await msg.verify({ signature, domain: 'app.example.org', nonce: '32891756', time: '2026-07-13T00:05:00.000Z' });
  assert.equal(res.success, true);
  assert.equal(res.data, msg);
});

test('tampered signature and wrong signer are INVALID_SIGNATURE', async () => {
  const msg = new OwmSiweMessage(GOLDEN);
  const sig = signPersonalMessage(GOLDEN, KEY);
  const flipped = `0x${sig.startsWith('00') ? '11' : '00'}${sig.slice(2)}`;
  await assert.rejects(
    msg.verify({ signature: flipped, time: FIELDS.issuedAt }),
    (r) => r.success === false && r.error.type === SiweErrorType.INVALID_SIGNATURE,
  );
  const otherSig = `0x${signPersonalMessage(GOLDEN, `0x${'22'.repeat(32)}`)}`;
  const res = await msg.verify({ signature: otherSig, time: FIELDS.issuedAt }, { suppressExceptions: true });
  assert.equal(res.success, false);
  assert.equal(res.error.type, SiweErrorType.INVALID_SIGNATURE);
});

test('domain, nonce, and time-window checks fail with siwe-compatible error types', async () => {
  const msg = new OwmSiweMessage(GOLDEN);
  const signature = `0x${signPersonalMessage(GOLDEN, KEY)}`;
  const cases = [
    [{ signature, domain: 'evil.example', time: FIELDS.issuedAt }, SiweErrorType.DOMAIN_MISMATCH],
    [{ signature, nonce: 'different1', time: FIELDS.issuedAt }, SiweErrorType.NONCE_MISMATCH],
    [{ signature, time: '2026-07-13T00:10:00.000Z' }, SiweErrorType.EXPIRED_MESSAGE], // >= expirationTime
  ];
  for (const [params, type] of cases) {
    const res = await msg.verify(params, { suppressExceptions: true });
    assert.equal(res.success, false);
    assert.equal(res.error.type, type);
  }
  // notBefore
  const nb = new OwmSiweMessage({ ...FIELDS, notBefore: '2026-07-13T00:05:00.000Z' });
  const nbText = nb.prepareMessage();
  const nbSig = `0x${signPersonalMessage(nbText, KEY)}`;
  const early = await nb.verify({ signature: nbSig, time: '2026-07-13T00:01:00.000Z' }, { suppressExceptions: true });
  assert.equal(early.error.type, SiweErrorType.NOT_YET_VALID_MESSAGE);
  const onTime = await nb.verify({ signature: nbSig, time: '2026-07-13T00:06:00.000Z' });
  assert.equal(onTime.success, true);
});

test('malformed messages and fields are refused at construction', () => {
  assert.throws(() => new OwmSiweMessage('not a siwe message'));
  assert.throws(() => new OwmSiweMessage(GOLDEN.replace('URI: ', 'URL: ')));
  assert.throws(() => new OwmSiweMessage(`${GOLDEN}\ntrailing junk`));
  assert.throws(() => new OwmSiweMessage(GOLDEN.replace(ADDR55, '0xnotanaddress')));
  // bad EIP-55 checksum (mixed case, wrong pattern)
  const badChecksum = ADDR55.replace(/[a-f]/, (c) => c.toUpperCase());
  assert.throws(() => new OwmSiweMessage({ ...FIELDS, address: badChecksum }).prepareMessage());
  assert.throws(() => new OwmSiweMessage({ ...FIELDS, version: '2' }).prepareMessage());
  assert.throws(() => new OwmSiweMessage({ ...FIELDS, nonce: 'short' }).prepareMessage());
  assert.throws(() => new OwmSiweMessage({ ...FIELDS, issuedAt: 'yesterday' }).prepareMessage());
});

test('generateNonce: >= 8 alphanumeric chars, unique', () => {
  const a = generateNonce();
  const b = generateNonce();
  assert.match(a, /^[a-zA-Z0-9]{17}$/);
  assert.notEqual(a, b);
});
