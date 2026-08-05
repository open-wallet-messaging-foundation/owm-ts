// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import test from 'node:test';
import assert from 'node:assert/strict';
import { WORDS, CODE_WORD_COUNT, generateCode, parseCode } from '../src/scx-code.js';

test('wordlist is the adapted EFF short list: 1296 unique lowercase words', () => {
  assert.equal(WORDS.length, 1296);
  assert.equal(new Set(WORDS).size, 1296);
  for (const w of WORDS) assert.match(w, /^[a-z]+$/);
  // the one documented adaptation: "yo-yo" -> "yolk" (hyphen is the separator)
  assert.ok(WORDS.includes('yolk'));
  assert.ok(!WORDS.some((w) => w.includes('-')));
});

test('generateCode format and parse round-trip', () => {
  const code = generateCode({ mailboxId: 7 });
  assert.match(code, /^7(-[a-z]+){3}$/);
  const parsed = parseCode(code);
  assert.ok(parsed.ok);
  assert.equal(parsed.mailboxId, 7);
  assert.equal(parsed.password, code.slice(2)); // the word portion only
  for (const w of parsed.password.split('-')) assert.ok(WORDS.includes(w));
});

test('generated codes differ call to call', () => {
  const seen = new Set(Array.from({ length: 8 }, () => generateCode({ mailboxId: 0 })));
  assert.ok(seen.size > 1);
});

test('generateCode validates mailboxId', () => {
  assert.throws(() => generateCode({ mailboxId: -1 }));
  assert.throws(() => generateCode({ mailboxId: 1.5 }));
  assert.throws(() => generateCode({ mailboxId: '7' }));
  assert.throws(() => generateCode({}));
});

test('parseCode accepts surrounding whitespace and mailbox 0', () => {
  const ok = parseCode('  0-acid-acorn-acre  ');
  assert.ok(ok.ok);
  assert.equal(ok.mailboxId, 0);
  assert.equal(ok.password, 'acid-acorn-acre');
});

test('parseCode rejects malformed codes', () => {
  const bad = [
    null, 42, '', '   ', 'acid-acorn-acre', '7-acid-acorn', '7-acid-acorn-acre-aged',
    'x-acid-acorn-acre', '-7-acid-acorn-acre', '07-acid-acorn-acre', '7--acorn-acre',
  ];
  for (const c of bad) {
    const r = parseCode(c);
    assert.ok(!r.ok, `should reject: ${JSON.stringify(c)}`);
    assert.ok(r.error);
  }
});

test('parseCode rejects words outside the wordlist (typo caught pre-PAKE)', () => {
  assert.match(parseCode('7-acid-qwerty-acre').error, /unknown word: qwerty/);
  assert.match(parseCode('7-ACID-acorn-acre').error, /unknown word/); // case-sensitive
  assert.equal(parseCode(`7-acid-acorn-${'a'.repeat(30)}`).ok, false);
});

test('CODE_WORD_COUNT is the spec value', () => {
  assert.equal(CODE_WORD_COUNT, 3);
});
