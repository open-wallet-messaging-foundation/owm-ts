// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SAS_EMOJI, SCX_STATES, deriveSas, computeTranscriptHash,
  addressFromPrivateKey, canonicalCardPayload, buildContactCard, verifyContactCard,
  createScxSession,
} from '../src/scx.js';
import {
  parseMessage, buildScxPakeA, buildScxPakeB, buildWmContactCard,
  buildScxConfirm, buildScxAbort, SCX_ABORT_REASONS, SCX_CONFIRM_PHASES,
} from '../src/envelope.js';

const NOW = 1770000000000;
const CODE = '7-acid-acorn-acre';
const OTHER_CODE = '7-acid-acorn-aged';
const TH = 'ab'.repeat(32); // a well-formed transcript hash
const OTHER_TH = 'cd'.repeat(32);

const ALICE = {
  privateKey: '11'.repeat(32),
  inboxId: 'alice-inbox',
  displayName: 'Alice',
};
const BOB = {
  privateKey: '22'.repeat(32),
  inboxId: 'bob-inbox',
  guest: true,
};

function makeSessions(codeA = CODE, codeB = CODE) {
  const a = createScxSession({ role: 'a', code: codeA, identity: ALICE, now: NOW });
  const b = createScxSession({ role: 'b', code: codeB, identity: BOB, now: NOW });
  return { a, b };
}

// Pump every queued envelope between the two sessions until both go quiet.
function pump(a, b) {
  const toB = [...a.start().send];
  const toA = [...b.start().send];
  while (toA.length || toB.length) {
    if (toB.length) toA.push(...b.receive(toB.shift()).send);
    if (toA.length) toB.push(...a.receive(toA.shift()).send);
  }
}

// --- happy path -------------------------------------------------------------

test('happy path: same code -> identical key, identical SAS, verified cards', () => {
  const { a, b } = makeSessions();
  assert.equal(a.mailboxId, 7);
  pump(a, b);
  assert.equal(a.state, 'card-exchanged');
  assert.equal(b.state, 'card-exchanged');
  // identical session key, only exposed after confirmation
  assert.match(a.sessionKey, /^[0-9a-f]{32}$/);
  assert.equal(a.sessionKey, b.sessionKey);
  // identical transcript hash and SAS on both screens
  assert.equal(a.transcriptHash, b.transcriptHash);
  assert.deepEqual(a.sas, b.sas);
  assert.equal(a.sas.emoji.length, 2);
  assert.match(a.sas.digits, /^[0-9]{4}$/);
  // exchanged cards verify and assert the right identities
  assert.equal(a.peerCard.address, addressFromPrivateKey(BOB.privateKey));
  assert.equal(a.peerCard.inboxId, 'bob-inbox');
  assert.equal(a.peerCard.guest, true);
  assert.equal(b.peerCard.address, addressFromPrivateKey(ALICE.privateKey));
  assert.equal(b.peerCard.displayName, 'Alice');
  assert.ok(verifyContactCard(a.peerCard, a.transcriptHash).ok);
  assert.ok(verifyContactCard(b.peerCard, b.transcriptHash).ok);
  // SAS match on both sides -> confirmed
  const ra = a.acceptSas();
  assert.equal(ra.state, 'sas-pending');
  b.receive(ra.send[0]);
  const rb = b.acceptSas();
  assert.equal(rb.state, 'confirmed');
  a.receive(rb.send[0]);
  assert.equal(a.state, 'confirmed');
});

test('sessionKey is null before the peer proves knowledge of the code', () => {
  const a = createScxSession({ role: 'a', code: CODE, identity: ALICE, now: NOW });
  assert.equal(a.sessionKey, null);
  a.start();
  assert.equal(a.sessionKey, null);
});

// --- wrong code -------------------------------------------------------------

test('wrong code: both sides abort with bad-confirmation and never yield a key', () => {
  const { a, b } = makeSessions(CODE, OTHER_CODE);
  pump(a, b);
  assert.equal(a.state, 'aborted');
  assert.equal(b.state, 'aborted');
  assert.equal(a.abortReason, 'bad-confirmation');
  assert.equal(b.abortReason, 'bad-confirmation');
  assert.equal(a.sessionKey, null);
  assert.equal(b.sessionKey, null);
  assert.equal(a.sas, null);
  // hard stop: an aborted session emits nothing further
  const after = a.receive(buildScxConfirm({ phase: 'sas' }));
  assert.ok(!after.ok);
  assert.equal(after.send.length, 0);
});

// --- parallel-session MITM --------------------------------------------------

test('MITM cut-and-paste: a genuine card from session 1 fails in session 2', () => {
  // session 1: Alice <-> Bob complete a real exchange
  const s1 = makeSessions();
  pump(s1.a, s1.b);
  assert.equal(s1.a.state, 'card-exchanged');
  const genuineBobCard = buildWmContactCard(s1.b.card); // signed over transcript 1
  // session 2: SAME Bob identity, different code -> different transcript
  const a2 = createScxSession({ role: 'a', code: OTHER_CODE, identity: ALICE, now: NOW });
  const b2 = createScxSession({ role: 'b', code: OTHER_CODE, identity: BOB, now: NOW });
  const ra = a2.start();
  const rb = b2.start();
  const macFromB = b2.receive(ra.send[0]).send[0];
  a2.receive(rb.send[0]); // a2 computes keys, sends its MAC
  a2.receive(macFromB); // a2 verifies b2's MAC -> key-confirmed, card sent
  assert.equal(a2.state, 'key-confirmed');
  assert.notEqual(a2.transcriptHash, s1.a.transcriptHash);
  // inject Bob's genuine signed card from session 1
  const res = a2.receive(genuineBobCard);
  assert.ok(!res.ok);
  assert.equal(a2.state, 'aborted');
  assert.equal(res.reason, 'bad-card-signature');
  assert.equal(res.send[0]._kind, 'scx-abort');
  assert.equal(a2.sessionKey, null);
});

// --- SAS mismatch -----------------------------------------------------------

test('SAS mismatch: reject aborts locally and the peer aborts on the notice', () => {
  const { a, b } = makeSessions();
  pump(a, b);
  const rej = b.rejectSas();
  assert.ok(!rej.ok);
  assert.equal(b.state, 'aborted');
  assert.equal(rej.reason, 'sas-mismatch');
  assert.equal(b.sessionKey, null);
  const got = a.receive(rej.send[0]);
  assert.ok(!got.ok);
  assert.equal(a.state, 'aborted');
  assert.equal(a.abortReason, 'sas-mismatch');
  assert.equal(a.sessionKey, null);
});

// --- protocol hygiene -------------------------------------------------------

test('off-curve pake share and reflected own share both abort with protocol', () => {
  const a1 = createScxSession({ role: 'a', code: CODE, identity: ALICE, now: NOW });
  a1.start();
  const res = a1.receive(buildScxPakeB({ share: `04${'ff'.repeat(64)}` }));
  assert.equal(a1.state, 'aborted');
  assert.equal(res.reason, 'protocol');

  const a2 = createScxSession({ role: 'a', code: CODE, identity: ALICE, now: NOW });
  const own = a2.start().send[0];
  const refl = a2.receive(own); // mailbox echoes our own message back
  assert.equal(a2.state, 'aborted');
  assert.equal(refl.reason, 'protocol');
});

test('out-of-order and non-SCX messages abort with protocol', () => {
  const a = createScxSession({ role: 'a', code: CODE, identity: ALICE, now: NOW });
  a.start();
  const early = buildScxConfirm({ phase: 'sas' }); // before any key exists
  assert.equal(a.receive(early).reason, 'protocol');

  const b = createScxSession({ role: 'b', code: CODE, identity: BOB, now: NOW });
  b.start();
  assert.equal(b.receive('not even json').reason, 'protocol');
});

test('transport-driven abort: timeout is emitted and final', () => {
  const a = createScxSession({ role: 'a', code: CODE, identity: ALICE, now: NOW });
  a.start();
  const res = a.abort('timeout');
  assert.equal(res.send[0].reason, 'timeout');
  assert.equal(a.state, 'aborted');
  assert.throws(() => a.abort('timeout')); // already final
  assert.throws(() => a.abort('because')); // not a registered reason
});

test('createScxSession validates its inputs', () => {
  assert.throws(() => createScxSession({ role: 'x', code: CODE, identity: ALICE, now: NOW }), /role/);
  assert.throws(() => createScxSession({ role: 'a', code: '7-acid-oops-acre', identity: ALICE, now: NOW }), /bad code/);
  assert.throws(() => createScxSession({ role: 'a', identity: ALICE, now: NOW }), /code or password/);
  assert.throws(() => createScxSession({ role: 'a', code: CODE, now: NOW }), /identity/);
  assert.throws(() => createScxSession({ role: 'a', code: CODE, identity: ALICE }), /now/);
  const { a } = makeSessions();
  assert.throws(() => a.acceptSas(), /acceptSas/); // no cards exchanged yet
});

// --- contact cards directly -------------------------------------------------

test('contact card round-trip, and the transcript binding rejects a swap', () => {
  const card = buildContactCard({
    privateKey: ALICE.privateKey, inboxId: 'alice-inbox', displayName: 'Alice', ts: NOW, transcriptHash: TH,
  });
  assert.equal(card.address, addressFromPrivateKey(ALICE.privateKey));
  assert.ok(verifyContactCard(card, TH).ok);
  // same genuine card, different exchange -> MUST fail
  assert.ok(!verifyContactCard(card, OTHER_TH).ok);
});

test('tampered cards fail verification', () => {
  const card = buildContactCard({
    privateKey: ALICE.privateKey, inboxId: 'alice-inbox', ts: NOW, transcriptHash: TH,
  });
  assert.ok(!verifyContactCard({ ...card, inboxId: 'evil-inbox' }, TH).ok);
  assert.ok(!verifyContactCard({ ...card, address: `0x${'99'.repeat(20)}` }, TH).ok);
  assert.ok(!verifyContactCard({ ...card, ts: NOW + 1 }, TH).ok);
  assert.ok(!verifyContactCard({ ...card, sig: `${'00'.repeat(64)}1b` }, TH).ok);
  assert.ok(!verifyContactCard({ ...card, sig: 'zz' }, TH).ok);
  assert.ok(!verifyContactCard(null, TH).ok);
  assert.ok(!verifyContactCard(card, 'nothex').ok);
});

test('buildContactCard validates inputs (newlines cannot break the payload)', () => {
  const base = { privateKey: ALICE.privateKey, inboxId: 'in', ts: NOW, transcriptHash: TH };
  assert.throws(() => buildContactCard({ ...base, inboxId: 'a\nb' }));
  assert.throws(() => buildContactCard({ ...base, displayName: 'a\nb' }));
  assert.throws(() => buildContactCard({ ...base, inboxId: '' }));
  assert.throws(() => buildContactCard({ ...base, transcriptHash: 'short' }));
  assert.throws(() => buildContactCard({ ...base, ts: 'now' }));
  assert.throws(() => buildContactCard({ ...base, privateKey: 'nope' }));
  // canonical payload pins the field order
  const p = canonicalCardPayload({ address: '0xAB', inboxId: 'i', ts: 1, transcriptHash: TH });
  assert.equal(p.split('\n')[0], 'owm-scx-card-v1');
  assert.ok(p.includes('address:0xab'));
});

// --- SAS derivation ---------------------------------------------------------

test('SAS table is 64 unique emoji and derivation is deterministic', () => {
  assert.equal(SAS_EMOJI.length, 64);
  assert.equal(new Set(SAS_EMOJI).size, 64);
  const s1 = deriveSas(TH);
  assert.deepEqual(s1, deriveSas(TH));
  assert.ok(SAS_EMOJI.includes(s1.emoji[0]) && SAS_EMOJI.includes(s1.emoji[1]));
  assert.match(s1.digits, /^[0-9]{4}$/);
  assert.equal(s1.display, `${s1.emoji[0]} ${s1.emoji[1]} ${s1.digits}`);
  assert.notEqual(deriveSas(OTHER_TH).display, s1.display);
  assert.throws(() => deriveSas('nothex'));
  // spot-check the normative mapping: th bytes 0xab -> index 0xab % 64 = 43
  assert.equal(s1.emoji[0], SAS_EMOJI[0xab % 64]);
});

test('SCX_STATES lists the full lifecycle', () => {
  assert.deepEqual([...SCX_STATES], [
    'init', 'pake-sent', 'key-confirmed', 'card-exchanged', 'sas-pending', 'confirmed', 'aborted',
  ]);
});

// --- envelope strictness for the five SCX kinds ------------------------------

function reparse(env) {
  return parseMessage(JSON.stringify(env));
}

test('all five SCX kinds build valid and round-trip through strict parse', () => {
  const card = buildContactCard({
    privateKey: BOB.privateKey, inboxId: 'bob-inbox', guest: true, ts: NOW, transcriptHash: TH,
  });
  const envs = [
    buildScxPakeA({ share: `04${'ab'.repeat(64)}` }),
    buildScxPakeB({ share: `04${'cd'.repeat(64)}` }),
    buildWmContactCard(card),
    buildScxConfirm({ phase: 'mac', mac: 'ef'.repeat(32) }),
    buildScxConfirm({ phase: 'sas' }),
    buildScxAbort({ reason: 'timeout' }),
  ];
  for (const env of envs) {
    const parsed = reparse(env);
    assert.ok(parsed.ok, `${env._kind}: ${parsed.error}`);
  }
});

test('strictness: missing, extra, and type-mismatched keys are rejected for each SCX kind', () => {
  const card = buildContactCard({
    privateKey: BOB.privateKey, inboxId: 'bob-inbox', ts: NOW, transcriptHash: TH,
  });
  const cases = [
    [buildScxPakeA({ share: `04${'ab'.repeat(64)}` }), 'share'],
    [buildScxPakeB({ share: `04${'ab'.repeat(64)}` }), 'share'],
    [buildWmContactCard(card), 'sig'],
    [buildScxConfirm({ phase: 'mac', mac: 'ef'.repeat(32) }), 'phase'],
    [buildScxAbort({ reason: 'protocol' }), 'reason'],
  ];
  for (const [env, requiredField] of cases) {
    const { [requiredField]: _gone, ...missing } = env;
    assert.match(reparse(missing).error, /missing key/, `${env._kind} missing`);
    assert.match(reparse({ ...env, smuggled: 1 }).error, /extra key/, `${env._kind} extra`);
    assert.match(reparse({ ...env, [requiredField]: 42 }).error, /type mismatch/, `${env._kind} type`);
  }
});

test('SCX field checks: share shape, mac shape, enums, card fields', () => {
  assert.throws(() => buildScxPakeA({ share: '02abcd' })); // compressed refused
  assert.throws(() => buildScxPakeA({ share: `05${'ab'.repeat(64)}` }));
  assert.throws(() => buildScxConfirm({ phase: 'maybe', mac: 'ef'.repeat(32) }));
  assert.throws(() => buildScxConfirm({ phase: 'mac' })); // mac required for phase mac
  assert.throws(() => buildScxConfirm({ phase: 'sas', mac: 'ef'.repeat(32) })); // and banned for sas
  assert.throws(() => buildScxAbort({ reason: 'gremlins' }));
  const card = buildContactCard({
    privateKey: BOB.privateKey, inboxId: 'bob-inbox', ts: NOW, transcriptHash: TH,
  });
  assert.throws(() => buildWmContactCard({ ...card, address: 'not-an-address' }));
  assert.throws(() => buildWmContactCard({ ...card, sig: 'abcd' }));
  assert.match(reparse({ _kind: 'scx-abort', v: 1, reason: 'gremlins' }).error, /bad enum/);
  assert.match(reparse({ _kind: 'scx-confirm', v: 1, phase: 'later' }).error, /bad enum/);
});

test('SCX enums are frozen and complete', () => {
  assert.deepEqual([...SCX_CONFIRM_PHASES], ['mac', 'sas']);
  for (const r of ['bad-confirmation', 'bad-card-signature', 'sas-mismatch', 'timeout', 'protocol']) {
    assert.ok(SCX_ABORT_REASONS.includes(r), r);
  }
});

test('computeTranscriptHash is domain-separated (not the raw key block)', async () => {
  const { sha256 } = await import('@noble/hashes/sha2.js');
  const { bytesToHex } = await import('@noble/hashes/utils.js');
  const tt = new Uint8Array([1, 2, 3]);
  const th = computeTranscriptHash(tt);
  assert.match(th, /^[0-9a-f]{64}$/);
  // raw SHA-256(TT) is Ke||Ka per RFC 9382 §4 — the public hash MUST differ
  assert.notEqual(th, bytesToHex(sha256(tt)));
});
