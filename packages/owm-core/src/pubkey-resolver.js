// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// Resolve a wallet's PUBLIC KEY from its address.
//
//  • Solana — the address IS the ed25519 public key (base58-decode). Instant.
//  • EVM / Tron (secp256k1) — the address is hash(pubkey), so you need ONE tx the
//    address signed. Given that transaction's fields + signature, we rebuild the
//    signing hash and `ecrecover` the public key, then verify it hashes back to
//    the address. (The demo fetches the tx from Etherscan/Tronscan.)
//
// Honest ceiling: recovering a pubkey lets you *encrypt to* someone and *verify*
// them — but standard wallets can't ECDH-*decrypt*, so OWM's round-tripping
// recipient encryption uses the sign-to-derive OWM key (recipient-crypto.js).

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils.js';

// ── base58 (Solana) ──────────────────────────────────────────────────────────
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function base58decode(str) {
  const map = {};
  for (let i = 0; i < B58.length; i += 1) map[B58[i]] = i;
  const bytes = [0];
  for (const ch of str) {
    if (!(ch in map)) throw new Error(`invalid base58 char: ${ch}`);
    let carry = map[ch];
    for (let j = 0; j < bytes.length; j += 1) { carry += bytes[j] * 58; bytes[j] = carry & 0xff; carry >>= 8; }
    while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  for (let k = 0; k < str.length && str[k] === '1'; k += 1) bytes.push(0);
  return Uint8Array.from(bytes.reverse());
}

// Solana address → its 32-byte ed25519 public key (the address decoded).
export function pubkeyFromSolanaAddress(address) {
  const raw = base58decode(address.trim());
  if (raw.length !== 32) throw new Error('not a 32-byte Solana address');
  return { chain: 'solana', curve: 'ed25519', publicKey: raw, publicKeyHex: bytesToHex(raw), address: address.trim() };
}

// ── EVM / Tron secp256k1 recovery ────────────────────────────────────────────
function qty(hex) { // hex quantity → minimal big-endian bytes (RLP integer)
  let h = (hex || '0x').replace(/^0x/, '');
  if (h.length % 2) h = `0${h}`;
  let b = h.length ? hexToBytes(h) : new Uint8Array(0);
  let i = 0;
  while (i < b.length && b[i] === 0) i += 1;
  b = b.slice(i);
  return b;
}
function raw(hex) { const h = (hex || '0x').replace(/^0x/, ''); return h ? hexToBytes(h.length % 2 ? `0${h}` : h) : new Uint8Array(0); }
function intBytes(n) { const a = []; let x = n; while (x > 0) { a.unshift(x & 0xff); x = Math.floor(x / 256); } return Uint8Array.from(a); }

function rlpLen(len, offset) {
  if (len < 56) return Uint8Array.of(offset + len);
  const lb = intBytes(len);
  return concatBytes(Uint8Array.of(offset + 55 + lb.length), lb);
}
function rlp(item) {
  if (item instanceof Uint8Array) {
    if (item.length === 1 && item[0] < 0x80) return item;
    return concatBytes(rlpLen(item.length, 0x80), item);
  }
  const body = item.length ? concatBytes(...item.map(rlp)) : new Uint8Array(0);
  return concatBytes(rlpLen(body.length, 0xc0), body);
}
function accessList(list) {
  if (!list || !list.length) return [];
  return list.map((e) => [raw(e.address), (e.storageKeys || []).map(raw)]);
}
function padded(hex) { const b = raw(hex); const out = new Uint8Array(32); out.set(b, 32 - b.length); return out; }

// The keccak signing hash of an unsigned tx (Etherscan getTransactionByHash shape).
export function evmTxSigningHash(tx) {
  const type = tx.type ? Number(BigInt(tx.type)) : 0;
  const cid = tx.chainId != null ? Number(BigInt(tx.chainId)) : 1;
  const to = raw(tx.to);
  const data = raw(tx.input != null ? tx.input : tx.data);
  if (type === 2) {
    const body = rlp([intBytes(cid), qty(tx.nonce), qty(tx.maxPriorityFeePerGas), qty(tx.maxFeePerGas), qty(tx.gas || tx.gasLimit), to, qty(tx.value), data, accessList(tx.accessList)]);
    return keccak_256(concatBytes(Uint8Array.of(2), body));
  }
  if (type === 1) {
    const body = rlp([intBytes(cid), qty(tx.nonce), qty(tx.gasPrice), qty(tx.gas || tx.gasLimit), to, qty(tx.value), data, accessList(tx.accessList)]);
    return keccak_256(concatBytes(Uint8Array.of(1), body));
  }
  // legacy (EIP-155 if chainId present, else pre-155)
  const base = [qty(tx.nonce), qty(tx.gasPrice), qty(tx.gas || tx.gasLimit), to, qty(tx.value), data];
  const v = tx.v != null ? Number(BigInt(tx.v)) : 27;
  const eip155 = v >= 35;
  const fields = eip155 ? [...base, intBytes(cid), new Uint8Array(0), new Uint8Array(0)] : base;
  return keccak_256(rlp(fields));
}

function recoveryBit(tx) {
  if (tx.yParity != null) return Number(BigInt(tx.yParity)) & 1;
  const type = tx.type ? Number(BigInt(tx.type)) : 0;
  const v = Number(BigInt(tx.v));
  if (type !== 0) return v & 1;
  if (v === 27 || v === 28) return v - 27;
  const cid = tx.chainId != null ? Number(BigInt(tx.chainId)) : Math.floor((v - 35) / 2);
  return v - 35 - 2 * cid; // EIP-155
}

// Recover the uncompressed secp256k1 public key + address from a signed tx.
export function recoverPubkeyFromEvmTx(tx) {
  const hash = evmTxSigningHash(tx);
  const sig = secp256k1.Signature.fromBytes(concatBytes(Uint8Array.of(recoveryBit(tx)), padded(tx.r), padded(tx.s)), 'recovered');
  const pub = sig.recoverPublicKey(hash).toBytes(false); // 65 bytes, 0x04‖X‖Y
  const address = `0x${bytesToHex(keccak_256(pub.slice(1)).slice(12))}`;
  return { chain: 'evm', curve: 'secp256k1', publicKey: pub, publicKeyHex: bytesToHex(pub), address };
}

// Convenience: resolve by chain family.
export function pubkeyFromAddress({ chain, address, tx }) {
  if (chain === 'solana') return pubkeyFromSolanaAddress(address);
  const r = recoverPubkeyFromEvmTx(tx);
  if (address && r.address.toLowerCase() !== address.toLowerCase()) {
    throw new Error('recovered key does not match the address — wrong txid for this address');
  }
  return r;
}
