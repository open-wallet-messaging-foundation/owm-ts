// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import {
  pubkeyFromSolanaAddress, evmTxSigningHash, recoverPubkeyFromEvmTx, addressFromPrivateKey,
} from '../src/index.js';

test('Solana address decodes to a 32-byte ed25519 public key', () => {
  const r = pubkeyFromSolanaAddress('3xWHAyUtMWHqSiHt1EXVSpM9ewoaExoyvfMKB6ANLUCf');
  assert.equal(r.curve, 'ed25519');
  assert.equal(r.publicKey.length, 32);
  assert.throws(() => pubkeyFromSolanaAddress('0x1234'), /invalid base58|not a 32-byte/);
});

function signTx(tx, privHex, { legacy, chainId }) {
  // real signed txs always carry `v`; force EIP-155 hashing at sign time to match.
  const txForHash = legacy ? { ...tx, v: `0x${(35 + 2 * chainId).toString(16)}` } : tx;
  const hash = evmTxSigningHash(txForHash);
  const rec = secp256k1.sign(hash, hexToBytes(privHex), { prehash: false, format: 'recovered' });
  const bit = rec[0];
  const r = `0x${bytesToHex(rec.slice(1, 33))}`;
  const s = `0x${bytesToHex(rec.slice(33, 65))}`;
  if (legacy) return { ...tx, r, s, v: `0x${(35 + 2 * chainId + bit).toString(16)}` };
  return { ...tx, r, s, yParity: `0x${bit}` };
}

test('EVM legacy (EIP-155) tx → recovers the signer pubkey + address', () => {
  const priv = 'a'.repeat(64);
  const addr = addressFromPrivateKey(priv).toLowerCase();
  const tx = { type: '0x0', chainId: '0x1', nonce: '0x2', gasPrice: '0x3b9aca00', gas: '0x5208', to: '0x1111111111111111111111111111111111111111', value: '0xde0b6b3a7640000', input: '0x' };
  const out = recoverPubkeyFromEvmTx(signTx(tx, priv, { legacy: true, chainId: 1 }));
  assert.equal(out.address.toLowerCase(), addr);
  assert.equal(out.publicKey.length, 65);
});

test('EVM 1559 (type 2) tx → recovers the signer', () => {
  const priv = 'a'.repeat(64);
  const addr = addressFromPrivateKey(priv).toLowerCase();
  const tx = { type: '0x2', chainId: '0x1', nonce: '0x1', maxPriorityFeePerGas: '0x3b9aca00', maxFeePerGas: '0x77359400', gas: '0x5208', to: '0x2222222222222222222222222222222222222222', value: '0x0', input: '0x', accessList: [] };
  const out = recoverPubkeyFromEvmTx(signTx(tx, priv, { legacy: false }));
  assert.equal(out.address.toLowerCase(), addr);
});
