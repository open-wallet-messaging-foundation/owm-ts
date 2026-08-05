// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// Rendezvous mailbox client (WM-2 §1) — zero-dependency, built on global
// fetch. Talks to an owm-rendezvous relay: create/claim a short-lived
// two-sided blind mailbox, append opaque frames, long-poll the OTHER side's
// frames. Side capabilities ride ONLY the Authorization header — never a
// URL, never a log line. Frames are opaque bytes at this layer; SCX (WM-3)
// is what gives them meaning.
//
// House style: input validation throws; HTTP failures throw an Error
// carrying { status, code } (the relay's kebab-case error code) so callers
// can branch on 409/403/404 without string-matching.

const MAILBOX_PATH = '/owm/v1/mailbox';
const MAX_WAIT_S = 25; // relay clamp (WM-2 §1.3); we refuse rather than clamp

// --- base64 (standard alphabet, padded — the relay's frame encoding) --------

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_INDEX = new Map([...B64].map((ch, i) => [ch, i]));

export function bytesToBase64(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new Error('bytes must be a Uint8Array');
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const hasB = i + 1 < bytes.length;
    const hasC = i + 2 < bytes.length;
    const b = hasB ? bytes[i + 1] : 0;
    const c = hasC ? bytes[i + 2] : 0;
    out += B64[a >> 2];
    out += B64[((a & 3) << 4) | (b >> 4)];
    out += hasB ? B64[((b & 15) << 2) | (c >> 6)] : '=';
    out += hasC ? B64[c & 63] : '=';
  }
  return out;
}

export function base64ToBytes(str) {
  if (typeof str !== 'string'
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(str)) {
    throw new Error('invalid base64');
  }
  const clean = str.replace(/=+$/, '');
  const pad = str.length - clean.length;
  const out = new Uint8Array((str.length / 4) * 3 - pad);
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const ch of clean) {
    acc = (acc << 6) | B64_INDEX.get(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o] = (acc >> bits) & 0xff;
      o += 1;
    }
  }
  return out;
}

// --- shared plumbing ---------------------------------------------------------

function normalizeBaseUrl(baseUrl) {
  if (typeof baseUrl !== 'string' || !/^https?:\/\//.test(baseUrl)) {
    throw new Error('baseUrl must be an http(s) URL');
  }
  return baseUrl.replace(/\/+$/, '');
}

function checkId(id) {
  if (!Number.isSafeInteger(id) || id < 0) throw new Error('id must be a non-negative integer');
}

function checkCap(sideCap) {
  if (typeof sideCap !== 'string' || sideCap === '') throw new Error('sideCap required');
}

// Best-effort extraction of the relay's {"error": "<kebab-code>"} body.
async function errorCode(res) {
  try {
    const body = await res.json();
    return typeof body?.error === 'string' ? body.error : undefined;
  } catch {
    return undefined;
  }
}

function httpError(label, status, code) {
  const err = new Error(`rendezvous ${label}: HTTP ${status}${code ? ` (${code})` : ''}`);
  err.status = status;
  if (code !== undefined) err.code = code;
  return err;
}

async function readJson(res, label) {
  try {
    return await res.json();
  } catch {
    throw new Error(`rendezvous ${label}: malformed response JSON`);
  }
}

// --- API ---------------------------------------------------------------------

// POST /owm/v1/mailbox → { id, sideCap, ttlS, expiresAt }.
export async function createMailbox({ baseUrl, ttlS, fetchImpl = globalThis.fetch } = {}) {
  const base = normalizeBaseUrl(baseUrl);
  const opts = { method: 'POST' };
  if (ttlS !== undefined) {
    if (!Number.isSafeInteger(ttlS) || ttlS < 1) throw new Error('ttlS must be a positive integer');
    opts.headers = { 'content-type': 'application/json' };
    opts.body = JSON.stringify({ ttl_s: ttlS });
  }
  const res = await fetchImpl(`${base}${MAILBOX_PATH}`, opts);
  if (res.status !== 201) throw httpError('create', res.status, await errorCode(res));
  const body = await readJson(res, 'create');
  if (!Number.isSafeInteger(body?.id) || body.id < 0
    || typeof body?.side_cap !== 'string' || body.side_cap === ''
    || typeof body?.ttl_s !== 'number' || typeof body?.expires_at !== 'number') {
    throw new Error('rendezvous create: malformed response body');
  }
  return { id: body.id, sideCap: body.side_cap, ttlS: body.ttl_s, expiresAt: body.expires_at };
}

// POST /owm/v1/mailbox/{id}/claim → { sideCap, ttlS, expiresAt }. Succeeds
// exactly once; a second claim surfaces as { status: 409,
// code: 'already-claimed' }.
export async function claimMailbox({ baseUrl, id, fetchImpl = globalThis.fetch } = {}) {
  const base = normalizeBaseUrl(baseUrl);
  checkId(id);
  const res = await fetchImpl(`${base}${MAILBOX_PATH}/${id}/claim`, { method: 'POST' });
  if (res.status !== 200) throw httpError('claim', res.status, await errorCode(res));
  const body = await readJson(res, 'claim');
  if (typeof body?.side_cap !== 'string' || body.side_cap === ''
    || typeof body?.ttl_s !== 'number' || typeof body?.expires_at !== 'number') {
    throw new Error('rendezvous claim: malformed response body');
  }
  return { sideCap: body.side_cap, ttlS: body.ttl_s, expiresAt: body.expires_at };
}

// PUT /owm/v1/mailbox/{id} — append one opaque frame (Uint8Array, or a
// string which is sent as its UTF-8 bytes). Resolves on 204.
export async function putFrame({ baseUrl, id, sideCap, frame, fetchImpl = globalThis.fetch } = {}) {
  const base = normalizeBaseUrl(baseUrl);
  checkId(id);
  checkCap(sideCap);
  let bytes;
  if (frame instanceof Uint8Array) bytes = frame;
  else if (typeof frame === 'string') bytes = new TextEncoder().encode(frame);
  else throw new Error('frame must be a Uint8Array or string');
  const res = await fetchImpl(`${base}${MAILBOX_PATH}/${id}`, {
    method: 'PUT',
    headers: { authorization: `Bearer ${sideCap}`, 'content-type': 'application/json' },
    body: JSON.stringify({ frame: bytesToBase64(bytes) }),
  });
  if (res.status !== 204) throw httpError('put', res.status, await errorCode(res));
}

// GET /owm/v1/mailbox/{id}?after=&wait= — long-poll the other side's frames.
// Returns { frames: [{ seq, side, frame: Uint8Array }], nextAfter }; empty
// frames when `waitS` elapsed with nothing new. Feed nextAfter back as
// `after`.
export async function pollFrames({
  baseUrl, id, sideCap, after = 0, waitS = 0, fetchImpl = globalThis.fetch,
} = {}) {
  const base = normalizeBaseUrl(baseUrl);
  checkId(id);
  checkCap(sideCap);
  if (!Number.isSafeInteger(after) || after < 0) throw new Error('after must be a non-negative integer');
  if (!Number.isSafeInteger(waitS) || waitS < 0 || waitS > MAX_WAIT_S) {
    throw new Error(`waitS must be an integer in [0, ${MAX_WAIT_S}]`);
  }
  const res = await fetchImpl(`${base}${MAILBOX_PATH}/${id}?after=${after}&wait=${waitS}`, {
    headers: { authorization: `Bearer ${sideCap}` },
  });
  if (res.status !== 200) throw httpError('poll', res.status, await errorCode(res));
  const body = await readJson(res, 'poll');
  if (!Array.isArray(body?.frames) || typeof body?.next_after !== 'number') {
    throw new Error('rendezvous poll: malformed response body');
  }
  const frames = body.frames.map((f) => {
    if (typeof f?.seq !== 'number' || typeof f?.side !== 'number' || typeof f?.frame !== 'string') {
      throw new Error('rendezvous poll: malformed frame');
    }
    return { seq: f.seq, side: f.side, frame: base64ToBytes(f.frame) };
  });
  return { frames, nextAfter: body.next_after };
}

// Convenience byte-pipe over one side of a mailbox, shaped for driving
// createScxSession (WM-3): send(bytes|string), recv() → Uint8Array (long-
// polls until a frame from the other side arrives; resolves null once
// close() was called and the local queue is drained). One recv() at a time —
// the cursor is not re-entrant.
export function openMailboxTransport({
  baseUrl, id, sideCap, waitS = 20, fetchImpl = globalThis.fetch,
} = {}) {
  normalizeBaseUrl(baseUrl);
  checkId(id);
  checkCap(sideCap);
  const queue = [];
  let after = 0;
  let closed = false;
  return {
    async send(frame) {
      if (closed) throw new Error('transport closed');
      await putFrame({ baseUrl, id, sideCap, frame, fetchImpl });
    },
    async recv() {
      for (;;) {
        if (queue.length > 0) return queue.shift();
        if (closed) return null;
        const { frames, nextAfter } = await pollFrames({ baseUrl, id, sideCap, after, waitS, fetchImpl });
        after = nextAfter;
        for (const f of frames) queue.push(f.frame);
      }
    },
    close() { closed = true; },
  };
}
