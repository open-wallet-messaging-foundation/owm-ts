// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  bytesToBase64, base64ToBytes,
  createMailbox, claimMailbox, putFrame, pollFrames, openMailboxTransport,
} from '../src/rendezvous-client.js';

const BASE = 'http://127.0.0.1:8757';

// Scripted fetch stub: each call consumes the next response in order and is
// recorded (url + options) for assertions. Entirely offline.
function stubFetch(...responses) {
  const calls = [];
  const impl = async (url, opts = {}) => {
    calls.push({ url: String(url), opts });
    if (responses.length === 0) throw new Error('stubFetch: unexpected extra call');
    const r = responses.shift();
    return {
      status: r.status,
      async json() {
        if (!('json' in r)) throw new SyntaxError('Unexpected end of JSON input');
        return r.json;
      },
    };
  };
  return { impl, calls };
}

const CAP = 'cap-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const CREATED = { id: 7, side_cap: CAP, ttl_s: 900, expires_at: 1770000900 };

// --- base64 -------------------------------------------------------------------

test('base64: RFC 4648 vectors round-trip, invalid input rejected', () => {
  const vectors = [['', ''], ['f', 'Zg=='], ['fo', 'Zm8='], ['foo', 'Zm9v'], ['foob', 'Zm9vYg==']];
  for (const [plain, b64] of vectors) {
    assert.equal(bytesToBase64(new TextEncoder().encode(plain)), b64);
    assert.equal(new TextDecoder().decode(base64ToBytes(b64)), plain);
  }
  const bin = Uint8Array.from({ length: 256 }, (_, i) => i);
  assert.deepEqual(base64ToBytes(bytesToBase64(bin)), bin);
  assert.throws(() => base64ToBytes('not base64!'));
  assert.throws(() => base64ToBytes('Zg=')); // bad padding length
  assert.throws(() => base64ToBytes(42));
  assert.throws(() => bytesToBase64('string'));
});

// --- createMailbox --------------------------------------------------------------

test('createMailbox: 201 → camelCased result; no body when ttlS omitted', async () => {
  const { impl, calls } = stubFetch({ status: 201, json: CREATED });
  const out = await createMailbox({ baseUrl: `${BASE}/`, fetchImpl: impl });
  assert.deepEqual(out, { id: 7, sideCap: CAP, ttlS: 900, expiresAt: 1770000900 });
  assert.equal(calls[0].url, `${BASE}/owm/v1/mailbox`); // trailing slash normalised
  assert.equal(calls[0].opts.method, 'POST');
  assert.equal(calls[0].opts.body, undefined);
});

test('createMailbox: ttlS rides the JSON body', async () => {
  const { impl, calls } = stubFetch({ status: 201, json: CREATED });
  await createMailbox({ baseUrl: BASE, ttlS: 120, fetchImpl: impl });
  assert.deepEqual(JSON.parse(calls[0].opts.body), { ttl_s: 120 });
});

test('createMailbox: non-201 throws with status + relay code', async () => {
  const { impl } = stubFetch({ status: 503, json: { error: 'at-capacity' } });
  await assert.rejects(createMailbox({ baseUrl: BASE, fetchImpl: impl }), (err) => {
    assert.equal(err.status, 503);
    assert.equal(err.code, 'at-capacity');
    assert.match(err.message, /HTTP 503/);
    return true;
  });
});

test('createMailbox: malformed JSON and malformed body both throw', async () => {
  const bad = stubFetch({ status: 201 }); // json() throws
  await assert.rejects(createMailbox({ baseUrl: BASE, fetchImpl: bad.impl }), /malformed response JSON/);
  const missing = stubFetch({ status: 201, json: { id: 7, ttl_s: 900, expires_at: 1 } }); // no side_cap
  await assert.rejects(createMailbox({ baseUrl: BASE, fetchImpl: missing.impl }), /malformed response body/);
});

test('createMailbox: input validation throws before any fetch', async () => {
  const { impl, calls } = stubFetch();
  await assert.rejects(createMailbox({ baseUrl: 'ftp://nope', fetchImpl: impl }), /http\(s\)/);
  await assert.rejects(createMailbox({ baseUrl: BASE, ttlS: 0, fetchImpl: impl }), /ttlS/);
  await assert.rejects(createMailbox({ baseUrl: BASE, ttlS: 1.5, fetchImpl: impl }), /ttlS/);
  assert.equal(calls.length, 0);
});

// --- claimMailbox ---------------------------------------------------------------

test('claimMailbox: 200 → { sideCap, ttlS, expiresAt }', async () => {
  const { impl, calls } = stubFetch({ status: 200, json: { side_cap: 'other-cap', ttl_s: 900, expires_at: 2 } });
  const out = await claimMailbox({ baseUrl: BASE, id: 7, fetchImpl: impl });
  assert.deepEqual(out, { sideCap: 'other-cap', ttlS: 900, expiresAt: 2 });
  assert.equal(calls[0].url, `${BASE}/owm/v1/mailbox/7/claim`);
  assert.equal(calls[0].opts.method, 'POST');
});

test('claimMailbox: second claim (409 already-claimed) is a clean error', async () => {
  const { impl } = stubFetch({ status: 409, json: { error: 'already-claimed' } });
  await assert.rejects(claimMailbox({ baseUrl: BASE, id: 7, fetchImpl: impl }), (err) => {
    assert.equal(err.status, 409);
    assert.equal(err.code, 'already-claimed');
    return true;
  });
});

test('claimMailbox: bad id refused before any fetch', async () => {
  const { impl, calls } = stubFetch();
  await assert.rejects(claimMailbox({ baseUrl: BASE, id: -1, fetchImpl: impl }), /non-negative/);
  await assert.rejects(claimMailbox({ baseUrl: BASE, id: '7', fetchImpl: impl }), /non-negative/);
  assert.equal(calls.length, 0);
});

// --- putFrame -------------------------------------------------------------------

test('putFrame: bytes ride as base64, cap rides ONLY the Authorization header', async () => {
  const { impl, calls } = stubFetch({ status: 204 });
  await putFrame({ baseUrl: BASE, id: 7, sideCap: CAP, frame: Uint8Array.of(1, 2, 3), fetchImpl: impl });
  const call = calls[0];
  assert.equal(call.url, `${BASE}/owm/v1/mailbox/7`);
  assert.equal(call.opts.method, 'PUT');
  assert.deepEqual(JSON.parse(call.opts.body), { frame: 'AQID' });
  assert.equal(call.opts.headers.authorization, `Bearer ${CAP}`);
  assert.ok(!call.url.includes(CAP), 'capability never appears in the URL');
});

test('putFrame: a string frame is sent as its UTF-8 bytes', async () => {
  const { impl, calls } = stubFetch({ status: 204 });
  await putFrame({ baseUrl: BASE, id: 7, sideCap: CAP, frame: 'hi', fetchImpl: impl });
  assert.deepEqual(JSON.parse(calls[0].opts.body), { frame: 'aGk=' });
});

test('putFrame: 403 bad-cap and bad frame types are refused', async () => {
  const { impl } = stubFetch({ status: 403, json: { error: 'bad-cap' } });
  await assert.rejects(
    putFrame({ baseUrl: BASE, id: 7, sideCap: 'wrong', frame: 'x', fetchImpl: impl }),
    (err) => err.status === 403 && err.code === 'bad-cap',
  );
  const none = stubFetch();
  await assert.rejects(putFrame({ baseUrl: BASE, id: 7, sideCap: CAP, frame: 42, fetchImpl: none.impl }), /Uint8Array or string/);
  await assert.rejects(putFrame({ baseUrl: BASE, id: 7, frame: 'x', fetchImpl: none.impl }), /sideCap/);
  assert.equal(none.calls.length, 0);
});

// --- pollFrames -----------------------------------------------------------------

test('pollFrames: decodes frames, returns nextAfter, cap in header only', async () => {
  const { impl, calls } = stubFetch({
    status: 200,
    json: { frames: [{ seq: 3, side: 1, frame: 'AQID' }, { seq: 5, side: 1, frame: 'aGk=' }], next_after: 5 },
  });
  const out = await pollFrames({ baseUrl: BASE, id: 7, sideCap: CAP, after: 2, waitS: 10, fetchImpl: impl });
  assert.equal(out.nextAfter, 5);
  assert.equal(out.frames.length, 2);
  assert.deepEqual(out.frames[0], { seq: 3, side: 1, frame: Uint8Array.of(1, 2, 3) });
  assert.equal(new TextDecoder().decode(out.frames[1].frame), 'hi');
  assert.equal(calls[0].url, `${BASE}/owm/v1/mailbox/7?after=2&wait=10`);
  assert.equal(calls[0].opts.headers.authorization, `Bearer ${CAP}`);
  assert.ok(!calls[0].url.includes(CAP), 'capability never appears in the query string');
});

test('pollFrames: 404 (expired/unknown mailbox) and malformed payloads throw', async () => {
  const gone = stubFetch({ status: 404, json: { error: 'not-found' } });
  await assert.rejects(
    pollFrames({ baseUrl: BASE, id: 9, sideCap: CAP, fetchImpl: gone.impl }),
    (err) => err.status === 404 && err.code === 'not-found',
  );
  const badBody = stubFetch({ status: 200, json: { frames: 'nope', next_after: 0 } });
  await assert.rejects(pollFrames({ baseUrl: BASE, id: 9, sideCap: CAP, fetchImpl: badBody.impl }), /malformed response body/);
  const badFrame = stubFetch({ status: 200, json: { frames: [{ seq: 1, side: 0, frame: '!!' }], next_after: 1 } });
  await assert.rejects(pollFrames({ baseUrl: BASE, id: 9, sideCap: CAP, fetchImpl: badFrame.impl }), /base64/);
});

test('pollFrames: waitS above the relay clamp is refused locally', async () => {
  const { impl, calls } = stubFetch();
  await assert.rejects(pollFrames({ baseUrl: BASE, id: 7, sideCap: CAP, waitS: 26, fetchImpl: impl }), /waitS/);
  await assert.rejects(pollFrames({ baseUrl: BASE, id: 7, sideCap: CAP, after: -1, fetchImpl: impl }), /after/);
  assert.equal(calls.length, 0);
});

// --- openMailboxTransport --------------------------------------------------------

test('transport: send PUTs, recv long-polls across empty windows and queues frames', async () => {
  const { impl, calls } = stubFetch(
    { status: 204 }, // send
    { status: 200, json: { frames: [], next_after: 0 } }, // empty long-poll window
    { status: 200, json: { frames: [{ seq: 1, side: 1, frame: 'AQID' }, { seq: 2, side: 1, frame: 'aGk=' }], next_after: 2 } },
  );
  const t = openMailboxTransport({ baseUrl: BASE, id: 7, sideCap: CAP, waitS: 5, fetchImpl: impl });
  await t.send('hello');
  const first = await t.recv();
  assert.deepEqual(first, Uint8Array.of(1, 2, 3));
  const second = await t.recv(); // served from the local queue — no new fetch
  assert.equal(new TextDecoder().decode(second), 'hi');
  assert.equal(calls.length, 3);
  assert.ok(calls[2].url.includes('after=0'), 'cursor fed back from next_after');
});

test('transport: close() drains then yields null; send after close throws', async () => {
  const { impl } = stubFetch({ status: 200, json: { frames: [{ seq: 1, side: 0, frame: 'AA==' }], next_after: 1 } });
  const t = openMailboxTransport({ baseUrl: BASE, id: 7, sideCap: CAP, fetchImpl: impl });
  const got = await t.recv();
  assert.deepEqual(got, Uint8Array.of(0));
  t.close();
  assert.equal(await t.recv(), null);
  await assert.rejects(t.send('late'), /closed/);
});

test('transport: constructor validates inputs up front', () => {
  assert.throws(() => openMailboxTransport({ baseUrl: 'nope', id: 1, sideCap: CAP }));
  assert.throws(() => openMailboxTransport({ baseUrl: BASE, id: 1.5, sideCap: CAP }));
  assert.throws(() => openMailboxTransport({ baseUrl: BASE, id: 1, sideCap: '' }));
});
