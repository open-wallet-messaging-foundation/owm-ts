// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OWM envelope build/parse with STRICT validation: for a known kind, a
// payload with a missing, extra, or type-mismatched key is rejected.
// Unknown kinds are surfaced as { unknown: true } so clients can fall back
// to rendering readable JSON text instead of dropping the message.

import { PING_PURPOSES, ACTOR_TYPES, SETTLEMENT_METHODS, BROADCAST_PURPOSES } from './kinds.js';
import { JOIN_MODES } from './invite.js';

// SCX enums (WM-3). scx-confirm carries either a PAKE confirmation MAC
// (phase 'mac') or the human SAS-match verdict (phase 'sas'). scx-abort is
// the only way an SCX handshake ends early — wrong guesses break loudly.
export const SCX_CONFIRM_PHASES = Object.freeze(['mac', 'sas']);
export const SCX_ABORT_REASONS = Object.freeze([
  'bad-confirmation', // PAKE confirmation MAC mismatch (wrong code / MITM)
  'bad-card-signature', // contact card not bound to THIS transcript
  'sas-mismatch', // humans compared SAS and it differed
  'timeout', // peer never showed up / stalled
  'protocol', // malformed or out-of-order message
  'declined', // user declined a WM-7 auth/grant prompt (terminal, not an SCX handshake failure)
]);

// OWM-INVITE / OWM-STAGE enums (WM-4). An invite-response 'later' is a polite defer —
// the invite object's own TTL still decides when it dies.
export const INVITE_RESPONSES = Object.freeze(['accept', 'decline', 'later']);
export const STAGE_MODES = Object.freeze(['listening-party', 'live-mesh', 'live-sfu']);
export const PLAYBACK_STATES = Object.freeze(['playing', 'paused']);
export const STAGE_CUES = Object.freeze(['raise-hand', 'on-stage', 'off-stage', 'encore', 'baton']);

const isHex = (len) => (x) => x.length === len && /^[0-9a-f]+$/.test(x);
// CAIP-2 chain id (eip155:1, solana:mainnet) and CAIP-10 account id
// (chain + ':' + address). Namespace/reference charsets per the CAIP specs.
const isCaip2 = (x) => /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/.test(x);
const isCaip10 = (x) => /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}$/.test(x);
// Decimal amount as a STRING — floats never touch money fields.
const isAmount = (x) => x.length <= 32 && /^[0-9]+(\.[0-9]+)?$/.test(x);
// Uncompressed SEC1 P-256 point: 0x04 || X || Y, 65 bytes, lowercase hex.
const isShareHex = (x) => x.length === 130 && x.startsWith('04') && /^[0-9a-f]+$/.test(x);
// WM-7 field values ride newline-delimited canonical signing strings, so
// newlines are banned in every string field of kinds 530-534.
const noNewline = (max) => (x) => x.length >= 1 && x.length <= max && !/[\r\n]/.test(x);
const isAddr = (x) => /^0x[0-9a-fA-F]{40}$/.test(x);
// Match codes are short decimal strings the user transcribes (2 digits by
// default; the spec ceiling is 8).
const isMatch = (x) => /^[0-9]{1,8}$/.test(x);
// OAuth-style scope: printable non-space tokens, single-space separated.
const isScope = (x) => x.length <= 512 && /^[!-~]+( [!-~]+)*$/.test(x);
// WM-7 time fields (iat/exp/ts) are unix SECONDS (JWT convention) — unlike
// the unix-ms `ts` of WM-3/WM-4 kinds. Documented in WM-7 §2.
const isUnixS = (x) => Number.isInteger(x) && x > 0 && x < 1e12;

// Per-kind field specs: name -> { type, required, enum?, check? }.
const SPECS = {
  'wm-ping': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    purpose: { type: 'string', required: true, enum: PING_PURPOSES },
    nonce: { type: 'string', required: true, check: (x) => x.length >= 16 },
    ts: { type: 'number', required: true },
  },
  'wm-pong': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    nonce: { type: 'string', required: true, check: (x) => x.length >= 16 },
    auto: { type: 'boolean', required: true },
    ts: { type: 'number', required: true },
  },
  'wm-knock': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    purpose: { type: 'string', required: true, enum: PING_PURPOSES },
    nonce: { type: 'string', required: true, check: (x) => x.length >= 16 },
    note: { type: 'string', required: false, check: (x) => x.length <= 280 },
    ts: { type: 'number', required: true },
  },
  'scx-pake-a': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    share: { type: 'string', required: true, check: isShareHex },
  },
  'scx-pake-b': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    share: { type: 'string', required: true, check: isShareHex },
  },
  'wm-contact-card': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    address: { type: 'string', required: true, check: (x) => /^0x[0-9a-fA-F]{40}$/.test(x) },
    inboxId: { type: 'string', required: true, check: (x) => x.length >= 1 && x.length <= 128 && !/[\r\n]/.test(x) },
    displayName: { type: 'string', required: false, check: (x) => x.length <= 64 && !/[\r\n]/.test(x) },
    guest: { type: 'boolean', required: false },
    ts: { type: 'number', required: true },
    sig: { type: 'string', required: true, check: isHex(130) }, // r||s||v, 65 bytes
  },
  'scx-confirm': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    phase: { type: 'string', required: true, enum: SCX_CONFIRM_PHASES },
    mac: { type: 'string', required: false, check: isHex(64) }, // HMAC-SHA256, phase 'mac' only
  },
  'scx-abort': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    reason: { type: 'string', required: true, enum: SCX_ABORT_REASONS },
  },
  // --- WM-7: OWM-AUTH / OWM-GRANT (kinds 530-534) ---------------------------
  // The match code deliberately does NOT ride wm-auth-challenge: the user
  // transcribes it from the initiating screen (number-ENTRY), so an
  // unsolicited prompt cannot be approved — the victim never saw a code.
  'wm-auth-challenge': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    rp: { type: 'string', required: true, check: noNewline(128) },
    action: { type: 'string', required: true, check: noNewline(140) },
    challenge: { type: 'string', required: true, check: isHex(64) }, // 32-byte nonce
    binding: { type: 'string', required: false, check: noNewline(256) }, // strict mode
    iat: { type: 'number', required: true, check: isUnixS },
    exp: { type: 'number', required: true, check: isUnixS }, // MUST be <= iat + 120
  },
  'wm-auth-response': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    challenge: { type: 'string', required: true, check: isHex(64) },
    match: { type: 'string', required: true, check: isMatch },
    addr: { type: 'string', required: true, check: isAddr },
    sig: { type: 'string', required: true, check: isHex(130) }, // r||s||v, 65 bytes
  },
  'wm-grant-request': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    rp: { type: 'string', required: true, check: noNewline(128) },
    client: { type: 'string', required: true, check: noNewline(128) },
    scope: { type: 'string', required: true, check: isScope },
    aud: { type: 'string', required: true, check: noNewline(256) },
    nonce: { type: 'string', required: true, check: isHex(64) },
    iat: { type: 'number', required: true, check: isUnixS },
    exp: { type: 'number', required: true, check: isUnixS },
  },
  'wm-grant': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    rp: { type: 'string', required: true, check: noNewline(128) },
    client: { type: 'string', required: true, check: noNewline(128) },
    scope: { type: 'string', required: true, check: isScope },
    aud: { type: 'string', required: true, check: noNewline(256) },
    nonce: { type: 'string', required: true, check: isHex(64) },
    iat: { type: 'number', required: true, check: isUnixS },
    exp: { type: 'number', required: true, check: isUnixS },
    addr: { type: 'string', required: true, check: isAddr },
    sig: { type: 'string', required: true, check: isHex(130) },
  },
  'wm-grant-revoke': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    grantId: { type: 'string', required: true, check: isHex(64) }, // SHA-256 of the canonical grant string
    ts: { type: 'number', required: true, check: isUnixS },
    sig: { type: 'string', required: true, check: isHex(130) },
  },
  // --- OWM-APPROVAL (WM-7 §9, kinds 535-537) ---------------------------------
  // Signing canonical + quorum verifier live in approval.js. The action is
  // free text (WYSIWYS — the thing approved IS the thing displayed) and may
  // be multiline; signatures bind sha256(action), not the raw text.
  'wm-approval-request': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    approvalId: { type: 'string', required: true, check: isHex(64) },
    rp: { type: 'string', required: true, check: noNewline(128) },
    action: { type: 'string', required: true, check: (x) => x.length >= 1 && x.length <= 2000 },
    policy: { type: 'object', required: true, check: (x) => isApprovalPolicy(x) },
    iat: { type: 'number', required: true, check: isUnixS },
    exp: { type: 'number', required: true, check: isUnixS },
  },
  'wm-approval-sig': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    approvalId: { type: 'string', required: true, check: isHex(64) },
    signer: { type: 'string', required: true, check: isAddr },
    actionHash: { type: 'string', required: true, check: isHex(64) },
    sig: { type: 'string', required: true, check: isHex(130) },
  },
  'wm-approval-result': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    approvalId: { type: 'string', required: true, check: isHex(64) },
    actionHash: { type: 'string', required: true, check: isHex(64) },
    sigs: {
      type: 'object', // array of {signer, sig}; ≥m enforced by the verifier
      required: true,
      check: (x) => Array.isArray(x) && x.length >= 1 && x.length <= 64 && x.every(isResultSig),
    },
    ts: { type: 'number', required: true, check: isUnixS },
  },
  // --- OWM-INVITE (WM-4, kinds 517-519) --------------------------------------
  // An ADDRESSED invitation riding an existing E2EE channel: no bearer
  // secret at all — admission pre-authorizes the recipient's identity
  // (createInvite({boundTo: recipient}) on the admin side).
  'wm-invite': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    roomId: { type: 'string', required: true, check: noNewline(128) },
    admin: { type: 'string', required: true, check: noNewline(128) }, // admitting inboxId
    name: { type: 'string', required: false, check: (x) => x.length <= 64 && !/[\r\n]/.test(x) },
    mode: { type: 'string', required: true, enum: JOIN_MODES },
    note: { type: 'string', required: false, check: (x) => x.length <= 280 },
    nonce: { type: 'string', required: true, check: (x) => x.length >= 16 },
    ts: { type: 'number', required: true },
    exp: { type: 'number', required: true }, // unix ms; builder enforces exp > ts
  },
  'wm-invite-response': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    nonce: { type: 'string', required: true, check: (x) => x.length >= 16 }, // echoes the wm-invite
    roomId: { type: 'string', required: true, check: noNewline(128) },
    response: { type: 'string', required: true, enum: INVITE_RESPONSES },
    ts: { type: 'number', required: true },
  },
  // Warm introduction: the introducer signs over THIS intro (see intro.js),
  // so the attestation stays verifiable when quoted in the new B<->C DM.
  // Every string field rides the newline-joined canonical signing string,
  // hence the noNewline checks.
  'wm-intro': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    nonce: { type: 'string', required: true, check: (x) => x.length >= 16 && !/[\r\n]/.test(x) }, // shared by both copies
    introducer: { type: 'string', required: true, check: isAddr },
    about: { type: 'string', required: true, check: isAddr }, // the introduced party
    aboutInboxId: { type: 'string', required: true, check: noNewline(128) },
    aboutName: { type: 'string', required: false, check: (x) => x.length <= 64 && !/[\r\n]/.test(x) },
    actor: { type: 'string', required: false, enum: ACTOR_TYPES },
    purpose: { type: 'string', required: true, check: noNewline(140) },
    ts: { type: 'number', required: true },
    sig: { type: 'string', required: true, check: isHex(130) },
  },
  // --- OWM-STAGE (WM-4, kinds 540-542) ---------------------------------------
  // Room-scoped; the MLS room is the venue, so none of these carry a roomId.
  // There is deliberately NO media-key kind: keys derive from the room.
  'wm-stage-config': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    mode: { type: 'string', required: true, enum: STAGE_MODES },
    title: { type: 'string', required: false, check: (x) => x.length <= 64 && !/[\r\n]/.test(x) },
    performers: {
      type: 'object', // JSON array of inboxIds; the unmuted set
      required: true,
      check: (x) => Array.isArray(x) && x.length >= 1 && x.length <= 32
        && x.every((p) => typeof p === 'string' && p.length >= 1 && p.length <= 128 && !/[\r\n]/.test(p)),
    },
    capacity: { type: 'number', required: false, check: (x) => Number.isInteger(x) && x >= 1 && x <= 10000 },
    seq: { type: 'number', required: true, check: (x) => Number.isInteger(x) && x >= 0 }, // config revision
    ts: { type: 'number', required: true },
  },
  // The Tier-1 heart: "track T was at positionMs when the wall clock read
  // atMs". Clients correct drift by nudging playbackRate, never seeking.
  'wm-playback-sync': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    trackId: { type: 'string', required: true, check: noNewline(128) },
    positionMs: { type: 'number', required: true, check: (x) => Number.isInteger(x) && x >= 0 },
    state: { type: 'string', required: true, enum: PLAYBACK_STATES },
    atMs: { type: 'number', required: true, check: (x) => Number.isInteger(x) && x > 0 }, // wall-clock anchor
    seq: { type: 'number', required: true, check: (x) => Number.isInteger(x) && x >= 0 }, // stale-beacon rejection
  },
  'wm-stage-cue': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    cue: { type: 'string', required: true, enum: STAGE_CUES },
    subject: { type: 'string', required: false, check: noNewline(128) }, // whom the cue is about
    ts: { type: 'number', required: true },
  },
  // --- OWM-PAY (WM-4, kinds 543-546) -----------------------------------------
  // Signing canonicals live in pay.js. Doctrine: the channel never carries
  // value — these are intents and records; the chain settles.
  'wm-settlement-card': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    addr: { type: 'string', required: true, check: isAddr }, // the signing OWM identity
    accounts: {
      type: 'object', // array of settlement accounts; strict per-entry shape
      required: true,
      check: (x) => Array.isArray(x) && x.length >= 1 && x.length <= 32 && x.every(isSettlementAccount),
    },
    ts: { type: 'number', required: true },
    exp: { type: 'number', required: false },
    sig: { type: 'string', required: true, check: isHex(130) },
  },
  'wm-tx-intent': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    intentId: { type: 'string', required: true, check: isHex(64) },
    chain: { type: 'string', required: true, check: isCaip2 },
    method: { type: 'string', required: true, enum: SETTLEMENT_METHODS }, // the closed core
    payload: {
      type: 'object', // rail-specific (EVM: EIP-5792 calls; Solana: tx request)
      required: true,
      check: (x) => x !== null && !Array.isArray(x) && JSON.stringify(x).length <= 16384,
    },
    to: { type: 'string', required: false, check: noNewline(128) }, // display target
    note: { type: 'string', required: false, check: (x) => x.length <= 280 },
    ts: { type: 'number', required: true },
    exp: { type: 'number', required: false },
  },
  'wm-tx-reference': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    intentId: { type: 'string', required: false, check: isHex(64) }, // absent for unsolicited receipts
    chain: { type: 'string', required: true, check: isCaip2 },
    txHash: { type: 'string', required: true, check: noNewline(128) }, // chain-format varies
    ts: { type: 'number', required: true },
  },
  // Signed over the receive targets; clients render the pay UI ONLY when the
  // signature verifies AND the signer holds the matching room role /
  // verified-sender badge. Unverified copies render as inert text — no
  // button, no jar.
  'wm-broadcast-request': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    nonce: { type: 'string', required: true, check: (x) => x.length >= 16 && !/[\r\n]/.test(x) },
    purpose: { type: 'string', required: true, enum: BROADCAST_PURPOSES },
    amount: { type: 'string', required: false, check: isAmount }, // absent = open (donation)
    asset: { type: 'string', required: false, check: noNewline(64) },
    targets: {
      type: 'object', // CAIP-10 receive addresses (from the requester's 543)
      required: true,
      check: (x) => Array.isArray(x) && x.length >= 1 && x.length <= 8 && x.every((t) => typeof t === 'string' && isCaip10(t)),
    },
    memo: { type: 'string', required: false, check: noNewline(140) },
    requester: { type: 'string', required: true, check: isAddr },
    ts: { type: 'number', required: true },
    exp: { type: 'number', required: true },
    sig: { type: 'string', required: true, check: isHex(130) },
  },
  // --- OWM-PRESENCE (WM-4, kind 547) -----------------------------------------
  // Mutual presence attestation; signing canonical lives in presence.js.
  // Proves KEY presence in the encrypted session, not a warm body.
  'wm-call-attestation': {
    v: { type: 'number', required: true, check: (x) => x === 1 },
    roomId: { type: 'string', required: true, check: noNewline(128) },
    callId: { type: 'string', required: true, check: (x) => x.length >= 16 && !/[\r\n]/.test(x) },
    fingerprint: { type: 'string', required: true, check: noNewline(64) }, // epoch-bound room SAS / ZRTP SAS
    participantsHash: { type: 'string', required: true, check: isHex(64) }, // sha256 of sorted inboxIds
    fromTs: { type: 'number', required: true },
    toTs: { type: 'number', required: true }, // builder enforces toTs >= fromTs
    attester: { type: 'string', required: true, check: isAddr },
    sig: { type: 'string', required: true, check: isHex(130) },
  },
};

// OWM-APPROVAL policy: m-of-signers with a validity horizon. Distinct roster
// enforced here so a padded signers list can't inflate the quorum.
function isApprovalPolicy(p) {
  if (typeof p !== 'object' || p === null || Array.isArray(p)) return false;
  if (!Object.keys(p).every((k) => ['m', 'signers', 'exp'].includes(k))) return false;
  if (!Array.isArray(p.signers) || p.signers.length < 1 || p.signers.length > 64
    || !p.signers.every((s) => typeof s === 'string' && /^0x[0-9a-fA-F]{40}$/.test(s))) return false;
  if (new Set(p.signers.map((s) => s.toLowerCase())).size !== p.signers.length) return false;
  if (!(Number.isInteger(p.m) && p.m >= 1 && p.m <= p.signers.length)) return false;
  return isUnixS(p.exp);
}

function isResultSig(e) {
  if (typeof e !== 'object' || e === null || Array.isArray(e)) return false;
  if (!Object.keys(e).every((k) => ['signer', 'sig'].includes(k))) return false;
  return typeof e.signer === 'string' && /^0x[0-9a-fA-F]{40}$/.test(e.signer)
    && typeof e.sig === 'string' && /^[0-9a-f]{130}$/.test(e.sig);
}

// One settlement account inside a 543 card — strict like everything else:
// unknown keys reject the entry.
const ACCOUNT_KEYS = new Set(['account', 'methods', 'assets', 'memoRequired', 'minConfirmations', 'proof']);
function isSettlementAccount(a) {
  if (typeof a !== 'object' || a === null || Array.isArray(a)) return false;
  if (!Object.keys(a).every((k) => ACCOUNT_KEYS.has(k))) return false;
  if (typeof a.account !== 'string' || !isCaip10(a.account)) return false;
  if (!Array.isArray(a.methods) || a.methods.length < 1
    || !a.methods.every((m) => SETTLEMENT_METHODS.includes(m))) return false;
  if (a.assets !== undefined && (!Array.isArray(a.assets) || a.assets.length > 64
    || !a.assets.every((s) => typeof s === 'string' && s.length <= 128 && !/[\r\n|]/.test(s)))) return false;
  if (a.memoRequired !== undefined && typeof a.memoRequired !== 'boolean') return false;
  if (a.minConfirmations !== undefined
    && !(Number.isInteger(a.minConfirmations) && a.minConfirmations >= 0 && a.minConfirmations <= 1000)) return false;
  if (a.proof !== undefined && (typeof a.proof !== 'string' || a.proof.length > 512 || /[\r\n|]/.test(a.proof))) return false;
  return true;
}

function validate(kind, body) {
  const spec = SPECS[kind];
  if (!spec) return { ok: false, error: `no spec for kind ${kind}` };
  for (const [field, rule] of Object.entries(spec)) {
    const present = Object.hasOwn(body, field);
    if (!present) {
      if (rule.required) return { ok: false, error: `missing key: ${field}` };
      continue;
    }
    const val = body[field];
    if (typeof val !== rule.type) return { ok: false, error: `type mismatch: ${field}` };
    if (rule.enum && !rule.enum.includes(val)) return { ok: false, error: `bad enum value: ${field}` };
    if (rule.check && !rule.check(val)) return { ok: false, error: `check failed: ${field}` };
  }
  for (const key of Object.keys(body)) {
    if (key !== '_kind' && !Object.hasOwn(spec, key)) return { ok: false, error: `extra key: ${key}` };
  }
  return { ok: true };
}

function build(kind, fields) {
  const env = { _kind: kind, v: 1, ...fields };
  const res = validate(kind, env);
  if (!res.ok) throw new Error(`invalid ${kind}: ${res.error}`);
  return env;
}

export function randomNonce(bytes = 16) {
  const buf = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function buildPing({ purpose, ts, nonce = randomNonce() }) {
  return build('wm-ping', { purpose, nonce, ts });
}

export function buildPong({ nonce, auto, ts }) {
  return build('wm-pong', { nonce, auto, ts });
}

export function buildKnock({ purpose, ts, note, nonce = randomNonce() }) {
  const fields = { purpose, nonce, ts };
  if (note !== undefined) fields.note = note;
  return build('wm-knock', fields);
}

export function buildScxPakeA({ share }) {
  return build('scx-pake-a', { share });
}

export function buildScxPakeB({ share }) {
  return build('scx-pake-b', { share });
}

// Wrap a signed contact card (see scx.js buildContactCard) as an envelope.
export function buildWmContactCard(card) {
  const { v: _v, _kind: _k, ...fields } = card;
  return build('wm-contact-card', fields);
}

export function buildScxConfirm({ phase, mac }) {
  if (phase === 'mac' && mac === undefined) throw new Error('phase mac requires a mac');
  if (phase === 'sas' && mac !== undefined) throw new Error('phase sas carries no mac');
  const fields = { phase };
  if (mac !== undefined) fields.mac = mac;
  return build('scx-confirm', fields);
}

export function buildScxAbort({ reason }) {
  return build('scx-abort', { reason });
}

// --- WM-7 builders (530-534). Signing lives in auth.js; these only shape
// and strictly validate the wire envelopes.

export function buildWmAuthChallenge({ rp, action, challenge, binding, iat, exp }) {
  const fields = { rp, action, challenge, iat, exp };
  if (binding !== undefined) fields.binding = binding;
  return build('wm-auth-challenge', fields);
}

export function buildWmAuthResponse({ challenge, match, addr, sig }) {
  return build('wm-auth-response', { challenge, match, addr, sig });
}

export function buildWmGrantRequest({ rp, client, scope, aud, nonce, iat, exp }) {
  return build('wm-grant-request', { rp, client, scope, aud, nonce, iat, exp });
}

export function buildWmGrant({ rp, client, scope, aud, nonce, iat, exp, addr, sig }) {
  return build('wm-grant', { rp, client, scope, aud, nonce, iat, exp, addr, sig });
}

export function buildWmGrantRevoke({ grantId, ts, sig }) {
  return build('wm-grant-revoke', { grantId, ts, sig });
}

// --- OWM-APPROVAL builders (535-537). Signing + quorum live in approval.js.

export function buildWmApprovalRequest({ approvalId, rp, action, policy, iat, exp }) {
  return build('wm-approval-request', { approvalId, rp, action, policy, iat, exp });
}

export function buildWmApprovalSig({ approvalId, signer, actionHash, sig }) {
  return build('wm-approval-sig', { approvalId, signer, actionHash, sig });
}

export function buildWmApprovalResult({ approvalId, actionHash, sigs, ts }) {
  return build('wm-approval-result', { approvalId, actionHash, sigs, ts });
}

// --- OWM-INVITE builders (517-519). Intro signing lives in intro.js; this only
// shapes and strictly validates the wire envelope.

export function buildWmInvite({ roomId, admin, name, mode, note, ts, exp, nonce = randomNonce() }) {
  if (!(typeof exp === 'number' && typeof ts === 'number' && exp > ts)) {
    throw new Error('invalid wm-invite: exp must be > ts');
  }
  const fields = { roomId, admin, mode, nonce, ts, exp };
  if (name !== undefined) fields.name = name;
  if (note !== undefined) fields.note = note;
  return build('wm-invite', fields);
}

export function buildWmInviteResponse({ nonce, roomId, response, ts }) {
  return build('wm-invite-response', { nonce, roomId, response, ts });
}

export function buildWmIntro({ nonce, introducer, about, aboutInboxId, aboutName, actor, purpose, ts, sig }) {
  const fields = { nonce, introducer, about, aboutInboxId, purpose, ts, sig };
  if (aboutName !== undefined) fields.aboutName = aboutName;
  if (actor !== undefined) fields.actor = actor;
  return build('wm-intro', fields);
}

// --- OWM-STAGE builders (540-542).

export function buildWmStageConfig({ mode, title, performers, capacity, seq, ts }) {
  const fields = { mode, performers, seq, ts };
  if (title !== undefined) fields.title = title;
  if (capacity !== undefined) fields.capacity = capacity;
  return build('wm-stage-config', fields);
}

export function buildWmPlaybackSync({ trackId, positionMs, state, atMs, seq }) {
  return build('wm-playback-sync', { trackId, positionMs, state, atMs, seq });
}

export function buildWmStageCue({ cue, subject, ts }) {
  const fields = { cue, ts };
  if (subject !== undefined) fields.subject = subject;
  return build('wm-stage-cue', fields);
}

// --- OWM-PAY builders (543-546). Signing lives in pay.js; these only shape
// and strictly validate the wire envelopes.

export function buildWmSettlementCard({ addr, accounts, ts, exp, sig }) {
  const fields = { addr, accounts, ts, sig };
  if (exp !== undefined) fields.exp = exp;
  return build('wm-settlement-card', fields);
}

export function buildWmTxIntent({ intentId, chain, method, payload, to, note, ts, exp }) {
  const fields = { intentId, chain, method, payload, ts };
  if (to !== undefined) fields.to = to;
  if (note !== undefined) fields.note = note;
  if (exp !== undefined) fields.exp = exp;
  return build('wm-tx-intent', fields);
}

export function buildWmTxReference({ intentId, chain, txHash, ts }) {
  const fields = { chain, txHash, ts };
  if (intentId !== undefined) fields.intentId = intentId;
  return build('wm-tx-reference', fields);
}

export function buildWmBroadcastRequest({ nonce, purpose, amount, asset, targets, memo, requester, ts, exp, sig }) {
  if (!(typeof exp === 'number' && typeof ts === 'number' && exp > ts)) {
    throw new Error('invalid wm-broadcast-request: exp must be > ts');
  }
  const fields = { nonce, purpose, targets, requester, ts, exp, sig };
  if (amount !== undefined) fields.amount = amount;
  if (asset !== undefined) fields.asset = asset;
  if (memo !== undefined) fields.memo = memo;
  return build('wm-broadcast-request', fields);
}

// --- OWM-PRESENCE builder (547). Signing lives in presence.js.

export function buildWmCallAttestation({ roomId, callId, fingerprint, participantsHash, fromTs, toTs, attester, sig }) {
  if (!(typeof fromTs === 'number' && typeof toTs === 'number' && toTs >= fromTs)) {
    throw new Error('invalid wm-call-attestation: toTs must be >= fromTs');
  }
  return build('wm-call-attestation', { roomId, callId, fingerprint, participantsHash, fromTs, toTs, attester, sig });
}

// Parse a raw XMTP text message. Returns:
//   { ok: true, kind, body }            — known kind, strictly valid
//   { ok: false, error }                — known kind, invalid payload
//   { ok: false, unknown: true, kind }  — well-formed envelope, unknown kind
//   { ok: false, plain: true }          — not an OWM envelope (plain chat text)
export function parseMessage(raw) {
  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    return { ok: false, plain: true };
  }
  if (typeof body !== 'object' || body === null || typeof body._kind !== 'string') {
    return { ok: false, plain: true };
  }
  const kind = body._kind;
  if (!SPECS[kind]) return { ok: false, unknown: true, kind };
  const res = validate(kind, body);
  if (!res.ok) return { ok: false, error: res.error, kind };
  return { ok: true, kind, body };
}
