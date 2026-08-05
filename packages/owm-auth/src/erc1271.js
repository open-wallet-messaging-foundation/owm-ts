// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// erc1271.js — OPTIONAL smart-contract-wallet signature verification for
// @open-wallet-messaging/auth (WM-7 §8): ERC-1271 `isValidSignature(bytes32,bytes)` over a
// read-only JSON-RPC endpoint, with ERC-6492 wrapper detection for
// signatures produced by not-yet-deployed (counterfactual) accounts.
//
// Design rules (all firm):
//  - EOA FIRST, RPC NEVER: a signature that recovers to the expected
//    address verifies purely in-process — the RPC transport is not touched.
//    With no verifier configured anywhere, @open-wallet-messaging/auth behaviour is
//    bit-for-bit the EOA-only behaviour it always had.
//  - FAIL CLOSED: any RPC error, timeout, malformed response, wrong magic
//    value, or missing contract code is a verification failure with a
//    distinct machine-readable reason. There is no fail-open path.
//  - TRUST SHIFT, STATED: ERC-1271 verification trusts the RPC endpoint to
//    report contract code and execute `isValidSignature` honestly. A
//    malicious endpoint can forge acceptance. Run your own node (or a
//    quorum of independent endpoints via a custom `rpcCall`) for anything
//    high-value. EOA-only deployments keep zero RPC trust.
//  - ZERO NEW DEPENDENCIES: the built-in transport uses global fetch; the
//    two ABI shapes needed are hand-encoded/decoded below.
//
// Counterfactual status (ERC-6492 wrapper + no code at the address): the
// reference FAILS CLOSED with reason 'counterfactual-unsupported'. The
// EIP's deploy-and-validate "universal validator" pattern requires
// embedding contract bytecode, and the EIP text publishes only Solidity
// source — there is no normative bytecode to byte-verify an embedded blob
// against — so it is deliberately not shipped. 6492-wrapped signatures
// for ALREADY-deployed accounts unwrap and verify normally.
//
// Never log the failure reasons together with signatures or addresses at
// error level; the reasons are designed to be safe to log alone.

import { eip191Digest, recoverPersonalMessage } from '@open-wallet-messaging/core';

/** ERC-1271 magic value: bytes4(keccak256("isValidSignature(bytes32,bytes)")). */
export const ERC1271_MAGIC = '0x1626ba7e';

/** ERC-6492 detection suffix: 32 bytes of 0x6492…6492 (bare hex, no 0x). */
export const ERC6492_MAGIC_SUFFIX = '6492'.repeat(16);

const SELECTOR = ERC1271_MAGIC.slice(2);
const DEFAULT_TIMEOUT_MS = 5000;

const word = (n) => n.toString(16).padStart(64, '0');
const padHex = (hex) => (hex.length % 64 === 0 ? hex : hex + '0'.repeat(64 - (hex.length % 64)));

/**
 * ABI-encode the calldata for `isValidSignature(bytes32 hash, bytes sig)`:
 * 4-byte selector, the 32-byte hash, the offset word (always 0x40 — the
 * dynamic `bytes` head starts right after the two argument words), the
 * length word, then the signature bytes right-padded to a 32-byte multiple.
 * @param {Uint8Array|string} hash 32 bytes (Uint8Array or 64-hex, 0x optional).
 * @param {string} signatureHex Signature bytes as hex (0x optional, may be empty).
 * @returns {string} 0x-prefixed calldata.
 * @throws {Error} On a hash that is not 32 bytes or non-hex signature input.
 */
export function encodeIsValidSignatureCall(hash, signatureHex) {
  const hashHex = hash instanceof Uint8Array
    ? Buffer.from(hash).toString('hex')
    : String(hash).replace(/^0x/, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hashHex)) throw new Error('hash must be exactly 32 bytes of hex');
  const sig = String(signatureHex).replace(/^0x/, '').toLowerCase();
  if (!/^(?:[0-9a-f]{2})*$/.test(sig)) throw new Error('signature must be even-length hex');
  return `0x${SELECTOR}${hashHex}${word(0x40)}${word(sig.length / 2)}${padHex(sig)}`;
}

// One 32-byte word at byte offset `byteOff` of a bare-hex blob, or null.
function readWord(hex, byteOff) {
  const start = byteOff * 2;
  if (start < 0 || start + 64 > hex.length) return null;
  return hex.slice(start, start + 64);
}

// A word interpreted as a small unsigned integer (offsets/lengths). Real
// wrappers stay tiny; anything above 2^48 is treated as malformed.
function wordToInt(w) {
  if (w === null || !/^0{52}[0-9a-f]{12}$/.test(w)) return null;
  return parseInt(w.slice(52), 16);
}

/**
 * Decode an ERC-6492 wrapped signature. Wrapper layout (per the EIP):
 * `abi.encode(create2Factory address, factoryCalldata bytes, originalSig
 * bytes)` followed by the 32-byte magic suffix.
 * @param {string} sigHex Bare lowercase hex INCLUDING the magic suffix.
 * @returns {?{factory: string, factoryCalldata: string, originalSig: string}}
 *   Bare-hex parts, or null when the wrapper is malformed (fail closed).
 */
export function decodeErc6492(sigHex) {
  if (typeof sigHex !== 'string' || !sigHex.endsWith(ERC6492_MAGIC_SUFFIX)) return null;
  const body = sigHex.slice(0, -ERC6492_MAGIC_SUFFIX.length);
  const w0 = readWord(body, 0);
  if (w0 === null || !/^0{24}[0-9a-f]{40}$/.test(w0)) return null;
  const offCalldata = wordToInt(readWord(body, 32));
  const offSig = wordToInt(readWord(body, 64));
  // Standard abi.encode places both tails after the 3-word head; anything
  // pointing into (or before) the head is malformed — fail closed.
  if (offCalldata === null || offSig === null || offCalldata < 96 || offSig < 96) return null;
  const readBytes = (off) => {
    const len = wordToInt(readWord(body, off));
    if (len === null) return null;
    const start = (off + 32) * 2;
    if (start + len * 2 > body.length) return null;
    return body.slice(start, start + len * 2);
  };
  const factoryCalldata = readBytes(offCalldata);
  const originalSig = readBytes(offSig);
  // An empty inner signature can never verify — reject at decode.
  if (factoryCalldata === null || originalSig === null || originalSig.length === 0) return null;
  return { factory: `0x${w0.slice(24)}`, factoryCalldata, originalSig };
}

// Accept 0/1/27/28 recovery ids on a 65-byte sig; emit the 130-hex
// r||s||v (v: 27/28) that @open-wallet-messaging/core recovery expects, or null.
function normalize65(hex) {
  if (!/^[0-9a-f]{130}$/.test(hex)) return null;
  const v = parseInt(hex.slice(128), 16);
  if (v === 0 || v === 1) return hex.slice(0, 128) + (27 + v).toString(16);
  if (v === 27 || v === 28) return hex;
  return null;
}

// Strict magic-return check: the ABI-encoded bytes4 return is the 4 magic
// bytes right-padded with zeros to one word; a bare 4-byte return is also
// accepted. Anything else — including a magic prefix with nonzero padding
// — is rejected.
function isMagicReturn(ret) {
  if (typeof ret !== 'string') return false;
  const hex = ret.replace(/^0x/, '').toLowerCase();
  if (hex === SELECTOR) return true;
  return hex.length === 64 && hex.startsWith(SELECTOR) && /^0+$/.test(hex.slice(8));
}

// Built-in JSON-RPC transport over global fetch. Errors carry status /
// error codes only — never request payloads (no signatures or addresses
// end up in logs via thrown messages).
function makeFetchRpc(rpcUrl, timeoutMs) {
  if (!/^https?:\/\//.test(rpcUrl)) throw new Error('rpcUrl must be an http(s) URL');
  let nextId = 1;
  return async (method, params) => {
    const res = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: nextId++, method, params }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`rpc http ${res.status}`);
    const body = await res.json();
    if (body.error) throw new Error(`rpc error ${body.error.code ?? 'unknown'}`);
    return body.result;
  };
}

/**
 * Create the optional chain verifier used by the `verifier` option of
 * OwmAuthServer, GrantServer, createWalletSession, and OwmSiweMessage
 * .verify. Read-only: only `eth_getCode` and `eth_call` are ever issued.
 *
 * @param {object} opts
 * @param {string} [opts.rpcUrl] JSON-RPC endpoint; builds a transport over
 *   global fetch. YOU TRUST THIS ENDPOINT (see the trust note above).
 * @param {Function} [opts.rpcCall] `async (method, params) => result` —
 *   injectable transport (tests, quorum wrappers). Wins over rpcUrl.
 * @param {number} [opts.timeoutMs=5000] Per-call ceiling; a timeout fails
 *   closed with reason 'rpc-error'.
 * @returns {{verifySignature: Function}}
 * @throws {Error} When neither rpcUrl nor rpcCall is given, or timeoutMs
 *   is not a positive integer.
 *
 * @example
 * const verifier = createChainVerifier({ rpcUrl: 'https://your-own-node.example' });
 * const server = new OwmAuthServer({ rp: 'example.org', verifier });
 */
export function createChainVerifier({ rpcUrl, rpcCall, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  if (typeof rpcCall !== 'function' && typeof rpcUrl !== 'string') {
    throw new Error('createChainVerifier: rpcUrl or rpcCall required');
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1) throw new Error('timeoutMs must be a positive integer');
  const transport = typeof rpcCall === 'function' ? rpcCall : makeFetchRpc(rpcUrl, timeoutMs);

  // Every call races the transport against the timeout — an injected
  // rpcCall that hangs still fails closed.
  function rpc(method, params) {
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('rpc timeout')), timeoutMs);
    });
    return Promise.race([
      Promise.resolve().then(() => transport(method, params)),
      timeout,
    ]).finally(() => clearTimeout(timer));
  }

  /**
   * Verify a signature over a canonical payload string for `address`.
   * Order: (1) EOA secp256k1 recovery — pure, no RPC; (2) ERC-6492 unwrap
   * when the magic suffix is present; (3) ERC-1271 `isValidSignature`
   * eth_call with hash = the EIP-191 digest of `payload`, accepting ONLY
   * the exact magic value 0x1626ba7e. Everything else fails closed.
   *
   * @param {object} opts
   * @param {string} opts.address Expected signer (0x + 40 hex, any case).
   * @param {string} opts.payload The canonical string that was signed.
   * @param {string} opts.signature Signature hex (0x optional): 65-byte
   *   EOA, arbitrary-length ERC-1271, or ERC-6492 wrapped.
   * @returns {Promise<{ok: true, method: 'eoa'|'erc1271'|'erc6492'}
   *   | {ok: false, method: string, reason: string}>}
   *   Failure reasons: 'bad-signature' (malformed input/wrapper),
   *   'no-code' (plain sig, no contract at address),
   *   'counterfactual-unsupported' (6492 wrapper, no contract yet),
   *   'bad-magic' (contract answered, wrong value), 'rpc-error'
   *   (transport error or timeout).
   */
  async function verifySignature({ address, payload, signature } = {}) {
    if (typeof address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(address)
        || typeof payload !== 'string' || typeof signature !== 'string') {
      return { ok: false, method: 'erc1271', reason: 'bad-signature' };
    }
    const want = address.toLowerCase();
    let sigHex = signature.replace(/^0x/, '').toLowerCase();
    if (sigHex.length === 0 || !/^(?:[0-9a-f]{2})*$/.test(sigHex)) {
      return { ok: false, method: 'erc1271', reason: 'bad-signature' };
    }

    // (1) EOA fast path — the RPC transport is NOT touched.
    const eoaSig = normalize65(sigHex);
    if (eoaSig !== null && recoverPersonalMessage(payload, eoaSig) === want) {
      return { ok: true, method: 'eoa' };
    }

    // (2) ERC-6492 wrapper?
    let method = 'erc1271';
    if (sigHex.endsWith(ERC6492_MAGIC_SUFFIX)) {
      method = 'erc6492';
      const unwrapped = decodeErc6492(sigHex);
      if (unwrapped === null) return { ok: false, method, reason: 'bad-signature' };
      sigHex = unwrapped.originalSig;
    }

    // (3) Deployed contract wallet? Fail closed on anything unexpected.
    let code;
    try {
      code = await rpc('eth_getCode', [want, 'latest']);
    } catch {
      return { ok: false, method, reason: 'rpc-error' };
    }
    if (typeof code !== 'string' || !/^0x(?:[0-9a-fA-F]{2})*$/.test(code)) {
      return { ok: false, method, reason: 'rpc-error' };
    }
    if (code === '0x') {
      // 6492 + no code = counterfactual: see the header note — fails
      // closed until a byte-verifiable universal-validator path exists.
      return { ok: false, method, reason: method === 'erc6492' ? 'counterfactual-unsupported' : 'no-code' };
    }

    // (4) ERC-1271: staticcall isValidSignature(eip191Digest(payload), sig).
    let ret;
    try {
      ret = await rpc('eth_call', [
        { to: want, data: encodeIsValidSignatureCall(eip191Digest(payload), sigHex) },
        'latest',
      ]);
    } catch {
      return { ok: false, method, reason: 'rpc-error' };
    }
    if (isMagicReturn(ret)) return { ok: true, method };
    return { ok: false, method, reason: 'bad-magic' };
  }

  return { verifySignature };
}
