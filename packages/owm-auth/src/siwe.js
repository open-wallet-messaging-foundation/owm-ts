// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OwmSiweMessage — a drop-in replacement for the `siwe` npm package's
// SiweMessage (EIP-4361 "Sign-In with Ethereum"). Mirrors the public API:
//
//   new OwmSiweMessage(stringOrFields)   — full EIP-4361 ABNF parse
//   msg.prepareMessage() / toMessage()   — exact EIP-4361 formatting
//   await msg.verify({ signature, domain?, nonce?, time? }, opts?)
//       → resolves { success: true, data } or rejects { success: false,
//         error, data } (resolve instead with opts.suppressExceptions)
//   generateNonce()
//
// Call-sites change only the import. Differences from `siwe` v2, stated
// honestly: EOA verification is synchronous crypto under the hood and
// carries zero dependencies. EIP-1271/6492 contract-wallet signatures are
// OFF by default — pass `{ verifier }` (from createChainVerifier) in the
// verify() opts to opt in to the read-only-RPC path (the analogue of
// siwe's `provider` escape hatch). Without a verifier, behaviour is
// exactly the EOA-only behaviour.

import { recoverPersonalMessage, toChecksumAddress } from '@open-wallet-messaging/core';
import { randomInt } from 'node:crypto';

const HEADER_SUFFIX = ' wants you to sign in with your Ethereum account:';

/**
 * Error strings mirroring the `siwe` package's SiweErrorType so migrated
 * call-sites keep matching on them.
 */
export const SiweErrorType = Object.freeze({
  EXPIRED_MESSAGE: 'Expired message.',
  NOT_YET_VALID_MESSAGE: 'Message is not valid yet.',
  INVALID_SIGNATURE: 'Signature does not match address of the message.',
  DOMAIN_MISMATCH: 'Domain does not match provided domain for verification.',
  NONCE_MISMATCH: 'Nonce does not match provided nonce for verification.',
  UNABLE_TO_PARSE: 'Unable to parse the message.',
});

/** Verification failure detail: `{ type, expected, received }` (siwe-compatible). */
export class SiweError {
  /**
   * @param {string} type One of SiweErrorType.
   * @param {string} [expected]
   * @param {string} [received]
   */
  constructor(type, expected, received) {
    this.type = type;
    this.expected = expected;
    this.received = received;
  }
}

const ISO8601 = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/**
 * siwe-compatible CSPRNG nonce: >= 8 alphanumeric chars (we emit 17, ~96 bits).
 * @returns {string}
 */
export function generateNonce() {
  let out = '';
  for (let i = 0; i < 17; i++) out += ALNUM[randomInt(ALNUM.length)];
  return out;
}

function parse(text) {
  if (typeof text !== 'string') throw new Error('siwe parse: not a string');
  const lines = text.split('\n');
  if (lines.length < 7) throw new Error('siwe parse: too few lines');
  const header = lines[0];
  if (!header.endsWith(HEADER_SUFFIX)) throw new Error('siwe parse: bad header line');
  const authority = header.slice(0, -HEADER_SUFFIX.length);
  let scheme;
  let domain = authority;
  const schemed = authority.match(/^([a-zA-Z][a-zA-Z0-9+\-.]*):\/\/(.+)$/);
  if (schemed) { [, scheme, domain] = schemed; }
  if (domain.length === 0 || /\s/.test(domain)) throw new Error('siwe parse: bad domain');
  const address = lines[1];
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) throw new Error('siwe parse: bad address');
  if (lines[2] !== '') throw new Error('siwe parse: missing blank line after address');
  let statement;
  let i;
  if (lines[3] === '') {
    i = 4;
  } else {
    statement = lines[3];
    if (lines[4] !== '') throw new Error('siwe parse: missing blank line after statement');
    i = 5;
  }
  const take = (label, required) => {
    if (i < lines.length && lines[i].startsWith(`${label}: `)) {
      const v = lines[i].slice(label.length + 2);
      i += 1;
      return v;
    }
    if (required) throw new Error(`siwe parse: missing "${label}"`);
    return undefined;
  };
  const uri = take('URI', true);
  const version = take('Version', true);
  const chainIdStr = take('Chain ID', true);
  if (!/^\d+$/.test(chainIdStr)) throw new Error('siwe parse: bad chain id');
  const nonce = take('Nonce', true);
  const issuedAt = take('Issued At', true);
  const expirationTime = take('Expiration Time', false);
  const notBefore = take('Not Before', false);
  const requestId = take('Request ID', false);
  let resources;
  if (i < lines.length && lines[i] === 'Resources:') {
    i += 1;
    resources = [];
    while (i < lines.length) {
      if (!lines[i].startsWith('- ')) throw new Error('siwe parse: bad resource line');
      resources.push(lines[i].slice(2));
      i += 1;
    }
  }
  if (i !== lines.length) throw new Error('siwe parse: unexpected trailing content');
  return {
    scheme, domain, address, statement, uri, version,
    chainId: Number(chainIdStr), nonce, issuedAt, expirationTime, notBefore, requestId, resources,
  };
}

/**
 * Drop-in replacement for the `siwe` package's SiweMessage (EIP-4361).
 * Construct from a fields object or parse a full message string; format
 * with prepareMessage()/toMessage(); check with verify().
 *
 * @example
 * // before: import { SiweMessage } from 'siwe';
 * import { OwmSiweMessage as SiweMessage } from '@open-wallet-messaging/auth';
 * const msg = new SiweMessage({ domain, address, uri, version: '1', chainId: 1, nonce });
 * const text = msg.prepareMessage();          // user signs this
 * await msg.verify({ signature, domain, nonce });
 */
export class OwmSiweMessage {
  /**
   * @param {string|object} param EIP-4361 message string (parsed + validated)
   *   or a fields object `{ domain, address, statement?, uri, version, chainId,
   *   nonce, issuedAt?, expirationTime?, notBefore?, requestId?, resources?, scheme? }`.
   * @throws {Error} When a message string fails the EIP-4361 ABNF parse.
   */
  constructor(param) {
    const fields = typeof param === 'string' ? parse(param) : { ...param };
    this.scheme = fields.scheme;
    this.domain = fields.domain;
    this.address = fields.address;
    this.statement = fields.statement;
    this.uri = fields.uri;
    this.version = fields.version !== undefined ? String(fields.version) : undefined;
    this.chainId = typeof fields.chainId === 'string' ? Number(fields.chainId) : fields.chainId;
    this.nonce = fields.nonce;
    this.issuedAt = fields.issuedAt;
    this.expirationTime = fields.expirationTime;
    this.notBefore = fields.notBefore;
    this.requestId = fields.requestId;
    this.resources = fields.resources;
    if (typeof param === 'string') this.#validate();
  }

  #validate() {
    if (typeof this.domain !== 'string' || this.domain.length === 0 || /\s/.test(this.domain)) {
      throw new Error('siwe: domain required (authority, no spaces)');
    }
    if (typeof this.address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(this.address)) {
      throw new Error('siwe: address must be 0x + 40 hex chars');
    }
    // EIP-55: a mixed-case address must carry a valid checksum.
    if (/[a-f]/.test(this.address.slice(2)) && /[A-F]/.test(this.address.slice(2))
        && this.address !== toChecksumAddress(this.address)) {
      throw new Error('siwe: address is not EIP-55 checksummed');
    }
    if (typeof this.uri !== 'string' || this.uri.length === 0) throw new Error('siwe: uri required');
    if (this.version !== '1') throw new Error('siwe: version must be "1"');
    if (!Number.isInteger(this.chainId) || this.chainId < 1) throw new Error('siwe: chainId must be a positive integer');
    if (typeof this.nonce !== 'string' || !/^[a-zA-Z0-9]{8,}$/.test(this.nonce)) {
      throw new Error('siwe: nonce must be >= 8 alphanumeric chars');
    }
    for (const [name, val] of [['issuedAt', this.issuedAt], ['expirationTime', this.expirationTime], ['notBefore', this.notBefore]]) {
      if (val !== undefined && !ISO8601.test(val)) throw new Error(`siwe: ${name} must be ISO 8601`);
    }
    if (this.statement !== undefined && /[\n\r]/.test(this.statement)) {
      throw new Error('siwe: statement must be a single line');
    }
  }

  /**
   * Exact EIP-4361 serialisation (byte-for-byte compatible with the `siwe`
   * package, including the double blank line when no statement is present).
   * Sets issuedAt to now when absent; validates all fields.
   * @returns {string}
   * @throws {Error} On invalid fields.
   */
  toMessage() {
    this.issuedAt = this.issuedAt ?? new Date().toISOString();
    this.#validate();
    const headerPrefix = this.scheme ? `${this.scheme}://${this.domain}` : this.domain;
    const header = `${headerPrefix}${HEADER_SUFFIX}`;
    let prefix = [header, this.address].join('\n');
    const suffixArray = [
      `URI: ${this.uri}`,
      `Version: ${this.version}`,
      `Chain ID: ${this.chainId}`,
      `Nonce: ${this.nonce}`,
      `Issued At: ${this.issuedAt}`,
    ];
    if (this.expirationTime) suffixArray.push(`Expiration Time: ${this.expirationTime}`);
    if (this.notBefore) suffixArray.push(`Not Before: ${this.notBefore}`);
    if (this.requestId) suffixArray.push(`Request ID: ${this.requestId}`);
    if (this.resources) suffixArray.push(['Resources:', ...this.resources.map((x) => `- ${x}`)].join('\n'));
    prefix = [prefix, this.statement].join('\n\n');
    if (this.statement !== undefined) prefix += '\n';
    return [prefix, suffixArray.join('\n')].join('\n');
  }

  /** Alias of toMessage() (siwe API compatibility). @returns {string} */
  prepareMessage() {
    return this.toMessage();
  }

  /**
   * Mirrors siwe's SiweMessage.verify: resolves `{ success: true, data }` or
   * (by default) REJECTS with `{ success: false, error, data }`. Pass
   * `{ suppressExceptions: true }` to always resolve.
   * @param {object} params
   * @param {string} params.signature 65-byte r||s||v hex (0x-prefixed or bare; v in {0,1,27,28}).
   * @param {string} [params.domain] Expected domain (checked when given).
   * @param {string} [params.nonce] Expected nonce (checked when given).
   * @param {string|number|Date} [params.time] Verification time (default: now).
   * @param {object} [opts]
   * @param {boolean} [opts.suppressExceptions=false]
   * @param {?object} [opts.verifier] Optional chain verifier from
   *   `createChainVerifier` — enables ERC-1271/6492 contract-wallet
   *   signatures (siwe's `provider`-style escape hatch). Consulted ONLY
   *   after EOA recovery fails; fail closed.
   * @returns {Promise<{success: boolean, data: OwmSiweMessage, error?: SiweError}>}
   */
  async verify({ signature, domain, nonce, time } = {}, { suppressExceptions = false, verifier = null } = {}) {
    const fail = (error) => {
      const res = { success: false, error, data: this };
      if (suppressExceptions) return res;
      throw res;
    };
    if (domain !== undefined && domain !== this.domain) {
      return fail(new SiweError(SiweErrorType.DOMAIN_MISMATCH, domain, this.domain));
    }
    if (nonce !== undefined && nonce !== this.nonce) {
      return fail(new SiweError(SiweErrorType.NONCE_MISMATCH, nonce, this.nonce));
    }
    const checkTime = new Date(time ?? Date.now());
    if (this.expirationTime !== undefined && checkTime.getTime() >= new Date(this.expirationTime).getTime()) {
      return fail(new SiweError(SiweErrorType.EXPIRED_MESSAGE, `< ${this.expirationTime}`, checkTime.toISOString()));
    }
    if (this.notBefore !== undefined && checkTime.getTime() < new Date(this.notBefore).getTime()) {
      return fail(new SiweError(SiweErrorType.NOT_YET_VALID_MESSAGE, `>= ${this.notBefore}`, checkTime.toISOString()));
    }
    let message;
    try {
      message = this.toMessage();
    } catch (e) {
      return fail(new SiweError(SiweErrorType.UNABLE_TO_PARSE, undefined, String(e?.message ?? e)));
    }
    const sig = normalizeSignature(signature);
    const recovered = sig === null ? null : recoverPersonalMessage(message, sig);
    if (recovered !== null && recovered === this.address.toLowerCase()) {
      return { success: true, data: this };
    }
    // ERC-1271/6492 fallback (WM-7 §8): opt-in, EOA-first, fail closed.
    // The 1271 hash is the EIP-191 digest of the exact message text.
    if (verifier) {
      let v = null;
      try {
        v = await verifier.verifySignature({ address: this.address, payload: message, signature });
      } catch { /* fail closed */ }
      if (v?.ok === true) return { success: true, data: this };
    }
    return fail(new SiweError(SiweErrorType.INVALID_SIGNATURE, this.address, recovered ?? 'unrecoverable'));
  }
}

// Accept 0x-prefixed or bare, any case, v in {0,1,27,28}; emit the
// 130-lowercase-hex r||s||v (v: 27/28) format @open-wallet-messaging/core recovery expects.
function normalizeSignature(signature) {
  if (typeof signature !== 'string') return null;
  const hex = signature.replace(/^0x/, '').toLowerCase();
  if (!/^[0-9a-f]{130}$/.test(hex)) return null;
  const v = parseInt(hex.slice(128), 16);
  if (v === 0 || v === 1) return hex.slice(0, 128) + (27 + v).toString(16);
  if (v === 27 || v === 28) return hex;
  return null;
}
