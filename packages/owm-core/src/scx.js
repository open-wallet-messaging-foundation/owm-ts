// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// SCX — Secure Contact Exchange (WM-3), the layer above the SPAKE2 PAKE:
// transcript hash, SAS derivation, transcript-bound contact cards, and a
// transport-agnostic session driver. The insecure channel carries only the
// short pairing code; addresses ride the PAKE-protected rendezvous, each
// card signed over THIS exchange's transcript so a genuine card cannot be
// cut-and-pasted between parallel sessions, and the SAS closes the residual
// one-guess MITM window. Any failure aborts loudly — never silently.

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';
import { deriveW, spake2Start, spake2Finish, constantTimeEqual } from './spake2.js';
import { parseCode } from './scx-code.js';
import {
  normalizePrivateKey, addressFromPrivateKey, signPersonalMessage, recoverPersonalMessage,
} from './eth-sign.js';
import {
  parseMessage, buildScxPakeA, buildScxPakeB, buildWmContactCard,
  buildScxConfirm, buildScxAbort, SCX_ABORT_REASONS,
} from './envelope.js';

// Fixed party identities for the SPAKE2 transcript (RFC 9382 §3.3): SCX
// parties are otherwise anonymous, so identity is the protocol role itself.
export const SCX_ID_A = 'owm-scx-a';
export const SCX_ID_B = 'owm-scx-b';

// Public transcript hash. Deliberately DOMAIN-SEPARATED from the raw
// SHA-256(TT): RFC 9382 §4 defines Hash(TT) = Ke || Ka, so publishing the
// bare digest would disclose the session keys. The tag makes this hash safe
// to embed in signed cards and UI.
const TRANSCRIPT_TAG = 'owm-scx-transcript-v1';

export function computeTranscriptHash(transcript) {
  return bytesToHex(sha256(concatBytes(utf8ToBytes(TRANSCRIPT_TAG), transcript)));
}

// SAS emoji table — 64 entries, ORDER IS NORMATIVE (WM-3 §5). All are
// single-codepoint, visually distinct, and nameable out loud on a call.
export const SAS_EMOJI = Object.freeze([
  '🐶', '🐱', '🦁', '🐴', '🦄', '🐮', '🐷', '🐸',
  '🐙', '🐵', '🦅', '🦆', '🦉', '🐝', '🦋', '🐌',
  '🐞', '🐠', '🐬', '🐳', '🦈', '🐢', '🦀', '🐘',
  '🌵', '🌲', '🌴', '🍀', '🍁', '🍄', '🌷', '🌻',
  '🌙', '⭐', '🌈', '🔥', '💧', '⚡', '🌊', '🍇',
  '🍎', '🍋', '🍉', '🍓', '🍒', '🥕', '🌽', '🍞',
  '🧀', '🥚', '🚀', '🚂', '🚗', '🚲', '⛵', '🚁',
  '🎈', '🎁', '🎨', '🎵', '🔑', '🔔', '⚽', '🎲',
]);

// SAS: 2 emoji + 4 decimal digits, derived deterministically from the
// transcript hash — both sides compute it independently and compare by
// human channel. bytes[0], bytes[1] index the emoji table (64 | 256, no
// bias); bytes[2..5] as big-endian u32 mod 10000 give the digits.
export function deriveSas(transcriptHash) {
  if (typeof transcriptHash !== 'string' || !/^[0-9a-f]{64}$/.test(transcriptHash)) {
    throw new Error('transcriptHash must be 64 hex chars');
  }
  const th = hexToBytes(transcriptHash);
  const emoji = [SAS_EMOJI[th[0] % 64], SAS_EMOJI[th[1] % 64]];
  const num = (((th[2] << 24) | (th[3] << 16) | (th[4] << 8) | th[5]) >>> 0) % 10000;
  const digits = String(num).padStart(4, '0');
  return { emoji, digits, display: `${emoji[0]} ${emoji[1]} ${digits}` };
}

// ---------------------------------------------------------------------------
// Contact cards: { v:1, address, inboxId, displayName?, guest?, ts, sig }.
// sig is an EIP-191 personal-message secp256k1 signature (eth-sign.js) over
// a canonical payload that INCLUDES the transcript hash — the anti
// cut-and-paste MITM binding. Verifying with a different transcript hash
// MUST fail.

export { addressFromPrivateKey };

// Canonical signing payload. Field values are newline-delimited; newlines
// are banned in inboxId/displayName by the envelope spec, so the encoding
// is unambiguous. The address is lowercased before signing.
export function canonicalCardPayload({ address, inboxId, displayName, guest, ts, transcriptHash }) {
  return [
    'owm-scx-card-v1',
    `address:${address.toLowerCase()}`,
    `inboxId:${inboxId}`,
    `displayName:${displayName ?? ''}`,
    `guest:${guest ? 1 : 0}`,
    `ts:${ts}`,
    `transcript:${transcriptHash}`,
  ].join('\n');
}

export function buildContactCard({ privateKey, inboxId, displayName, guest, ts, transcriptHash }) {
  const priv = normalizePrivateKey(privateKey);
  if (typeof inboxId !== 'string' || inboxId.length < 1 || inboxId.length > 128 || /[\r\n]/.test(inboxId)) {
    throw new Error('inboxId must be 1–128 chars without newlines');
  }
  if (displayName !== undefined && (typeof displayName !== 'string' || displayName.length > 64 || /[\r\n]/.test(displayName))) {
    throw new Error('displayName must be ≤64 chars without newlines');
  }
  if (typeof ts !== 'number') throw new Error('ts (unix ms) required');
  if (typeof transcriptHash !== 'string' || !/^[0-9a-f]{64}$/.test(transcriptHash)) {
    throw new Error('transcriptHash must be 64 hex chars');
  }
  const address = addressFromPrivateKey(priv);
  const payload = canonicalCardPayload({ address, inboxId, displayName, guest, ts, transcriptHash });
  const sig = signPersonalMessage(payload, priv);
  const card = { v: 1, address, inboxId, ts, sig };
  if (displayName !== undefined) card.displayName = displayName;
  if (guest !== undefined) card.guest = guest;
  return card;
}

// Verify a card against OUR transcript hash: recover the signer from the
// EIP-191 signature over the canonical payload (rebuilt with the LOCAL
// transcript hash) and require it to equal card.address. A card signed in
// any other exchange recovers a different signer and fails.
export function verifyContactCard(card, transcriptHash) {
  if (typeof card !== 'object' || card === null) return { ok: false, error: 'not a card' };
  if (card.v !== 1) return { ok: false, error: 'bad version' };
  if (typeof card.address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(card.address)) {
    return { ok: false, error: 'bad address' };
  }
  if (typeof card.inboxId !== 'string' || typeof card.ts !== 'number') {
    return { ok: false, error: 'bad card fields' };
  }
  if (typeof card.sig !== 'string' || !/^[0-9a-f]{130}$/.test(card.sig)) {
    return { ok: false, error: 'bad signature encoding' };
  }
  if (typeof transcriptHash !== 'string' || !/^[0-9a-f]{64}$/.test(transcriptHash)) {
    return { ok: false, error: 'bad transcript hash' };
  }
  const payload = canonicalCardPayload({
    address: card.address,
    inboxId: card.inboxId,
    displayName: card.displayName,
    guest: card.guest,
    ts: card.ts,
    transcriptHash,
  });
  const signer = recoverPersonalMessage(payload, card.sig);
  if (signer === null) return { ok: false, error: 'signature recovery failed' };
  if (signer !== card.address.toLowerCase()) {
    return { ok: false, error: 'signer does not match address (or wrong transcript)' };
  }
  return { ok: true, address: signer };
}

// ---------------------------------------------------------------------------
// Session driver — pure state machine, transport-agnostic: feed inbound
// envelopes with receive(), post whatever `send` arrays come back. States:
//   init → pake-sent → key-confirmed → card-exchanged → sas-pending
//        → confirmed | aborted
// ANY failure aborts with a reason and hard-stops; a wrong code shows up as
// scx-abort('bad-confirmation'), never as a silently different key.

export const SCX_STATES = Object.freeze([
  'init', 'pake-sent', 'key-confirmed', 'card-exchanged', 'sas-pending', 'confirmed', 'aborted',
]);

export function createScxSession({ role, code, password, identity, now, aad = '' }) {
  if (role !== 'a' && role !== 'b') throw new Error(`bad role: ${role}`);
  let mailboxId = null;
  let pass = password;
  if (code !== undefined) {
    const parsed = parseCode(code);
    if (!parsed.ok) throw new Error(`bad code: ${parsed.error}`);
    mailboxId = parsed.mailboxId;
    pass = parsed.password;
  }
  if (typeof pass !== 'string' || pass === '') throw new Error('code or password required');
  if (typeof identity !== 'object' || identity === null) throw new Error('identity required');
  if (typeof now !== 'number') throw new Error('now (unix ms) required');

  const w = deriveW(pass);
  const myPakeKind = role === 'a' ? 'scx-pake-a' : 'scx-pake-b';
  const peerPakeKind = role === 'a' ? 'scx-pake-b' : 'scx-pake-a';

  let state = 'init';
  let pake = null;
  let keys = null; // spake2Finish result; wiped on abort
  let transcriptHash = null;
  let macVerified = false;
  let myCard = null;
  let peerCard = null;
  let sas = null;
  let localSasOk = false;
  let peerSasOk = false;
  let abortReason = null;

  function doAbort(reason) {
    keys = null; // never expose key material from a failed exchange
    sas = null;
    state = 'aborted';
    abortReason = reason;
    return { ok: false, state, reason, send: [buildScxAbort({ reason })] };
  }

  function start() {
    if (state !== 'init') throw new Error(`start() in state ${state}`);
    pake = spake2Start({ role, w });
    const share = bytesToHex(pake.share);
    const env = role === 'a' ? buildScxPakeA({ share }) : buildScxPakeB({ share });
    state = 'pake-sent';
    return { ok: true, state, send: [env] };
  }

  function onPeerShare(body) {
    if (keys !== null) return doAbort('protocol'); // duplicate share
    const fin = spake2Finish({
      state: pake,
      peerShare: hexToBytes(body.share),
      idA: SCX_ID_A,
      idB: SCX_ID_B,
      aad,
    });
    if (!fin.ok) return doAbort('protocol'); // off-curve / identity element
    keys = fin;
    transcriptHash = computeTranscriptHash(fin.transcript);
    return { ok: true, state, send: [buildScxConfirm({ phase: 'mac', mac: bytesToHex(fin.confirm) })] };
  }

  function onConfirmMac(body) {
    if (keys === null || macVerified) return doAbort('protocol');
    if (body.mac === undefined) return doAbort('protocol');
    if (!constantTimeEqual(hexToBytes(body.mac), keys.expectedPeerConfirm)) {
      return doAbort('bad-confirmation'); // wrong code — the ONE online guess
    }
    macVerified = true;
    state = 'key-confirmed';
    myCard = buildContactCard({
      privateKey: identity.privateKey,
      inboxId: identity.inboxId,
      displayName: identity.displayName,
      guest: identity.guest,
      ts: now,
      transcriptHash,
    });
    return { ok: true, state, send: [buildWmContactCard(myCard)] };
  }

  function onPeerCard(body) {
    const res = verifyContactCard(body, transcriptHash);
    if (!res.ok) return doAbort('bad-card-signature');
    const { _kind: _k, ...card } = body;
    peerCard = card;
    sas = deriveSas(transcriptHash);
    state = 'card-exchanged';
    return { ok: true, state, send: [] };
  }

  function onConfirmSas() {
    if (state !== 'card-exchanged' && state !== 'sas-pending') return doAbort('protocol');
    peerSasOk = true;
    if (localSasOk) state = 'confirmed';
    return { ok: true, state, send: [] };
  }

  function receive(env) {
    if (state === 'aborted') return { ok: false, state, reason: abortReason, send: [] };
    if (state === 'confirmed') return { ok: true, state, send: [] };
    const parsed = parseMessage(typeof env === 'string' ? env : JSON.stringify(env));
    if (!parsed.ok) return doAbort('protocol'); // malformed = hostile, fail closed
    const { kind, body } = parsed;
    if (kind === 'scx-abort') {
      keys = null;
      sas = null;
      state = 'aborted';
      abortReason = body.reason;
      return { ok: false, state, reason: body.reason, send: [] };
    }
    if (kind === peerPakeKind) {
      if (state !== 'pake-sent') return doAbort('protocol');
      return onPeerShare(body);
    }
    if (kind === myPakeKind) return doAbort('protocol'); // reflection
    if (kind === 'scx-confirm') {
      if (body.phase === 'mac') {
        if (state !== 'pake-sent') return doAbort('protocol');
        return onConfirmMac(body);
      }
      return onConfirmSas();
    }
    if (kind === 'wm-contact-card') {
      if (state !== 'key-confirmed') return doAbort('protocol');
      return onPeerCard(body);
    }
    return doAbort('protocol'); // any other kind mid-handshake
  }

  // Local human verdict on the SAS comparison.
  function acceptSas() {
    if (state !== 'card-exchanged') throw new Error(`acceptSas() in state ${state}`);
    localSasOk = true;
    state = peerSasOk ? 'confirmed' : 'sas-pending';
    return { ok: true, state, send: [buildScxConfirm({ phase: 'sas' })] };
  }

  function rejectSas() {
    if (state !== 'card-exchanged' && state !== 'sas-pending') {
      throw new Error(`rejectSas() in state ${state}`);
    }
    return doAbort('sas-mismatch');
  }

  // For transports: deadline expiry, user cancel, etc.
  function abort(reason = 'timeout') {
    if (!SCX_ABORT_REASONS.includes(reason)) throw new Error(`bad reason: ${reason}`);
    if (state === 'aborted' || state === 'confirmed') throw new Error(`abort() in state ${state}`);
    return doAbort(reason);
  }

  return {
    role,
    get mailboxId() { return mailboxId; },
    get state() { return state; },
    get abortReason() { return abortReason; },
    // Ke, hex — exposed only once the peer proved knowledge of the code.
    get sessionKey() { return macVerified && keys ? bytesToHex(keys.ke) : null; },
    get transcriptHash() { return transcriptHash; },
    get sas() { return sas; },
    get card() { return myCard; },
    get peerCard() { return peerCard; },
    start,
    receive,
    acceptSas,
    rejectSas,
    abort,
  };
}
