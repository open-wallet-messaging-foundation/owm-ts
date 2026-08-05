// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// ERC-1271 / ERC-6492 smart-contract-wallet verification (WM-7 §8).
// Entirely offline: every RPC is an injected fake that records its calls,
// so the tests also PROVE the EOA fast path never touches the transport.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildWmAuthResponse, buildWmGrant, buildWmGrantRevoke,
  canonicalAuthPayload, canonicalGrantPayload, canonicalGrantRevokePayload,
  signPersonalMessage, addressFromPrivateKey, toChecksumAddress, eip191Digest,
  computeGrantId,
} from '@open-wallet-messaging/core';
import {
  createChainVerifier, encodeIsValidSignatureCall, decodeErc6492,
  ERC1271_MAGIC, ERC6492_MAGIC_SUFFIX,
} from '../src/erc1271.js';
import { OwmAuthServer } from '../src/server.js';
import { GrantServer } from '../src/grants.js';
import { createWalletSession } from '../src/oidc.js';
import { OwmSiweMessage, SiweErrorType } from '../src/siwe.js';
import { OwmAuthenticator } from '../src/authenticator.js';
import { MemoryEnrollmentStore, MemoryGrantRegistry } from '../src/stores.js';

const OWNER_KEY = `0x${'11'.repeat(32)}`; // the contract wallet's owner key
const OWNER = addressFromPrivateKey(OWNER_KEY);
const CONTRACT = `0x${'c0de'.repeat(10)}`; // the smart account's address
const START = 1770000000000;
const CODE = '0x6001600055'; // any nonempty bytecode
const MAGIC_RET = `0x1626ba7e${'00'.repeat(28)}`; // bytes4 magic, ABI-padded

// A recording fake transport: getCode/call answers are configurable.
function fakeRpc({ code = CODE, ret = MAGIC_RET, throwOn = null, hang = false } = {}) {
  const fn = async (method, params) => {
    fn.calls.push({ method, params });
    if (hang) return new Promise(() => {});
    if (throwOn === '*' || throwOn === method) throw new Error('boom');
    if (method === 'eth_getCode') return code;
    if (method === 'eth_call') return ret;
    throw new Error(`unexpected rpc method ${method}`);
  };
  fn.calls = [];
  return fn;
}

// Hand-encode an ERC-6492 wrapper: abi.encode(address, bytes, bytes) + suffix.
function wrap6492(originalSigHex, { factory = 'fa'.repeat(20), factoryCalldata = 'aabbcc' } = {}) {
  const word = (n) => n.toString(16).padStart(64, '0');
  const pad = (hex) => (hex.length % 64 === 0 ? hex : hex + '0'.repeat(64 - (hex.length % 64)));
  const fcdPadded = pad(factoryCalldata);
  const offCalldata = 96; // right after the 3 head words
  const offSig = offCalldata + 32 + fcdPadded.length / 2;
  return `0x${'0'.repeat(24)}${factory}${word(offCalldata)}${word(offSig)}`
    + `${word(factoryCalldata.length / 2)}${fcdPadded}`
    + `${word(originalSigHex.length / 2)}${pad(originalSigHex)}`
    + ERC6492_MAGIC_SUFFIX;
}

// --- unit: createChainVerifier ------------------------------------------------

test('createChainVerifier requires a transport and a sane timeout', () => {
  assert.throws(() => createChainVerifier(), /rpcUrl or rpcCall/);
  assert.throws(() => createChainVerifier({}), /rpcUrl or rpcCall/);
  assert.throws(() => createChainVerifier({ rpcUrl: 'ftp://nope' }), /http/);
  assert.throws(() => createChainVerifier({ rpcCall: async () => '0x', timeoutMs: 0 }), /timeoutMs/);
});

test('EOA fast path verifies without touching the RPC transport', async () => {
  const rpc = fakeRpc();
  const verifier = createChainVerifier({ rpcCall: rpc });
  const payload = 'owm-auth-v1\nrp.example\nlog in\n' + 'ab'.repeat(32) + '\n42\n-\n1770000120';
  const sig = signPersonalMessage(payload, OWNER_KEY);
  // bare hex, 0x-prefixed, and recovery-id (v=00/01) forms all verify
  for (const s of [sig, `0x${sig}`, sig.slice(0, 128) + (parseInt(sig.slice(128), 16) - 27 ? '01' : '00')]) {
    const res = await verifier.verifySignature({ address: OWNER, payload, signature: s });
    assert.deepEqual(res, { ok: true, method: 'eoa' });
  }
  assert.equal(rpc.calls.length, 0, 'the EOA fast path must never touch RPC');
});

test('malformed inputs fail closed before any RPC', async () => {
  const rpc = fakeRpc();
  const verifier = createChainVerifier({ rpcCall: rpc });
  const cases = [
    { address: 'not-an-address', payload: 'p', signature: 'aa' },
    { address: OWNER, payload: 'p', signature: '' },
    { address: OWNER, payload: 'p', signature: '0xzz' },
    { address: OWNER, payload: 'p', signature: 'abc' }, // odd length
    { address: OWNER, payload: 42, signature: 'aa' },
  ];
  for (const c of cases) {
    const res = await verifier.verifySignature(c);
    assert.equal(res.ok, false);
    assert.equal(res.reason, 'bad-signature');
  }
  assert.equal(rpc.calls.length, 0);
});

test('ERC-1271 happy path: deployed code + exact magic → ok, calldata is exact', async () => {
  const rpc = fakeRpc();
  const verifier = createChainVerifier({ rpcCall: rpc });
  const payload = 'owm-grant-v1\nrp.example\napp\nread\napi.example\n' + 'ab'.repeat(32) + '\n1770000000\n1770000900';
  const sig = signPersonalMessage(payload, OWNER_KEY); // recovers to OWNER, not CONTRACT
  const res = await verifier.verifySignature({ address: CONTRACT, payload, signature: sig });
  assert.deepEqual(res, { ok: true, method: 'erc1271' });
  assert.deepEqual(rpc.calls.map((c) => c.method), ['eth_getCode', 'eth_call']);
  assert.deepEqual(rpc.calls[0].params, [CONTRACT.toLowerCase(), 'latest']);
  const [{ to, data }, tag] = rpc.calls[1].params;
  assert.equal(to, CONTRACT.toLowerCase());
  assert.equal(tag, 'latest');
  assert.equal(data, encodeIsValidSignatureCall(eip191Digest(payload), sig));
});

test('golden calldata vector for isValidSignature(bytes32,bytes)', () => {
  const hash = Uint8Array.from({ length: 32 }, (_, i) => i); // 0x00..0x1f
  const got = encodeIsValidSignatureCall(hash, '0xDEADBEEF');
  assert.equal(got,
    '0x1626ba7e'
    + '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
    + '0000000000000000000000000000000000000000000000000000000000000040'
    + '0000000000000000000000000000000000000000000000000000000000000004'
    + 'deadbeef00000000000000000000000000000000000000000000000000000000');
  // empty signature: length word 0, no data words
  assert.equal(encodeIsValidSignatureCall(hash, ''),
    '0x1626ba7e'
    + '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
    + '0000000000000000000000000000000000000000000000000000000000000040'
    + '0000000000000000000000000000000000000000000000000000000000000000');
  assert.throws(() => encodeIsValidSignatureCall('0x1234', 'aa'), /32 bytes/);
  assert.throws(() => encodeIsValidSignatureCall(hash, 'abc'), /even-length/);
  assert.equal(ERC1271_MAGIC, '0x1626ba7e');
});

test('wrong or sloppy magic return fails closed with bad-magic', async () => {
  const payload = 'p';
  const sig = 'ab'.repeat(65);
  for (const ret of [
    `0x${'ff'.repeat(32)}`, // explicit failure value
    '0x', // empty return
    `0x1626ba7e01${'00'.repeat(27)}`, // magic prefix, nonzero padding
    '0x1626ba', // truncated
    null,
  ]) {
    const verifier = createChainVerifier({ rpcCall: fakeRpc({ ret }) });
    const res = await verifier.verifySignature({ address: CONTRACT, payload, signature: sig });
    assert.deepEqual(res, { ok: false, method: 'erc1271', reason: 'bad-magic' });
  }
});

test('no code at the address fails closed with no-code (plain signature)', async () => {
  const rpc = fakeRpc({ code: '0x' });
  const verifier = createChainVerifier({ rpcCall: rpc });
  const res = await verifier.verifySignature({ address: CONTRACT, payload: 'p', signature: 'ab'.repeat(65) });
  assert.deepEqual(res, { ok: false, method: 'erc1271', reason: 'no-code' });
  assert.deepEqual(rpc.calls.map((c) => c.method), ['eth_getCode'], 'no eth_call without code');
});

test('RPC error and RPC timeout both fail closed with rpc-error', async () => {
  for (const opts of [{ throwOn: 'eth_getCode' }, { throwOn: 'eth_call' }]) {
    const verifier = createChainVerifier({ rpcCall: fakeRpc(opts) });
    const res = await verifier.verifySignature({ address: CONTRACT, payload: 'p', signature: 'ab'.repeat(65) });
    assert.equal(res.ok, false);
    assert.equal(res.reason, 'rpc-error');
  }
  const hung = createChainVerifier({ rpcCall: fakeRpc({ hang: true }), timeoutMs: 25 });
  const res = await hung.verifySignature({ address: CONTRACT, payload: 'p', signature: 'ab'.repeat(65) });
  assert.deepEqual(res, { ok: false, method: 'erc1271', reason: 'rpc-error' });
  // a garbage eth_getCode answer is also an rpc-error, not a pass
  const garbage = createChainVerifier({ rpcCall: fakeRpc({ code: 12345 }) });
  assert.equal((await garbage.verifySignature({ address: CONTRACT, payload: 'p', signature: 'aa' })).reason, 'rpc-error');
});

test('ERC-6492: suffix detected, wrapper unwrapped, deployed account verifies', async () => {
  const rpc = fakeRpc();
  const verifier = createChainVerifier({ rpcCall: rpc });
  const payload = 'sign me';
  const inner = signPersonalMessage(payload, OWNER_KEY);
  const wrapped = wrap6492(inner);
  // the decoder round-trips the hand-encoded wrapper
  const parts = decodeErc6492(wrapped.slice(2));
  assert.deepEqual(parts, { factory: `0x${'fa'.repeat(20)}`, factoryCalldata: 'aabbcc', originalSig: inner });
  const res = await verifier.verifySignature({ address: CONTRACT, payload, signature: wrapped });
  assert.deepEqual(res, { ok: true, method: 'erc6492' });
  // the eth_call carried the UNWRAPPED original signature
  assert.equal(rpc.calls[1].params[0].data, encodeIsValidSignatureCall(eip191Digest(payload), inner));
});

test('ERC-6492 counterfactual (no code yet) fails closed: counterfactual-unsupported', async () => {
  const rpc = fakeRpc({ code: '0x' });
  const verifier = createChainVerifier({ rpcCall: rpc });
  const wrapped = wrap6492('ab'.repeat(65));
  const res = await verifier.verifySignature({ address: CONTRACT, payload: 'p', signature: wrapped });
  assert.deepEqual(res, { ok: false, method: 'erc6492', reason: 'counterfactual-unsupported' });
  assert.deepEqual(rpc.calls.map((c) => c.method), ['eth_getCode'], 'never calls, never deploys');
});

test('malformed ERC-6492 wrappers fail closed before any RPC', async () => {
  const rpc = fakeRpc();
  const verifier = createChainVerifier({ rpcCall: rpc });
  for (const bad of [
    `0xabcd${ERC6492_MAGIC_SUFFIX}`, // too short for the head
    `0x${'00'.repeat(96)}${ERC6492_MAGIC_SUFFIX}`, // offsets point past the body
    `0x${'ff'.repeat(96)}${ERC6492_MAGIC_SUFFIX}`, // nonsense head words
  ]) {
    const res = await verifier.verifySignature({ address: CONTRACT, payload: 'p', signature: bad });
    assert.deepEqual(res, { ok: false, method: 'erc6492', reason: 'bad-signature' });
  }
  assert.equal(rpc.calls.length, 0);
  assert.equal(decodeErc6492('deadbeef'), null, 'no suffix → not a wrapper');
});

test('rpcUrl transport: JSON-RPC over fetch, http/error failures fail closed', async (t) => {
  const seen = [];
  const orig = globalThis.fetch;
  t.after(() => { globalThis.fetch = orig; });
  globalThis.fetch = async (url, init) => {
    const req = JSON.parse(init.body);
    seen.push({ url, method: req.method });
    return {
      ok: true,
      json: async () => ({ jsonrpc: '2.0', id: req.id, result: req.method === 'eth_getCode' ? CODE : MAGIC_RET }),
    };
  };
  const verifier = createChainVerifier({ rpcUrl: 'https://rpc.example' });
  const res = await verifier.verifySignature({ address: CONTRACT, payload: 'p', signature: 'ab'.repeat(65) });
  assert.deepEqual(res, { ok: true, method: 'erc1271' });
  assert.deepEqual(seen.map((s) => s.method), ['eth_getCode', 'eth_call']);
  // HTTP failure → rpc-error
  globalThis.fetch = async () => ({ ok: false, status: 500 });
  const err = await verifier.verifySignature({ address: CONTRACT, payload: 'p', signature: 'ab'.repeat(65) });
  assert.deepEqual(err, { ok: false, method: 'erc1271', reason: 'rpc-error' });
  // JSON-RPC error object → rpc-error
  globalThis.fetch = async () => ({ ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, error: { code: -32000 } }) });
  const err2 = await verifier.verifySignature({ address: CONTRACT, payload: 'p', signature: 'ab'.repeat(65) });
  assert.deepEqual(err2, { ok: false, method: 'erc1271', reason: 'rpc-error' });
});

// --- integration: the four verification seams ---------------------------------

async function contractEnrolledServer(rpc, opts = {}) {
  const enrollmentStore = new MemoryEnrollmentStore();
  await enrollmentStore.put('u1', {
    address: CONTRACT, enrolledVia: 'test', enrolledAt: START, failures: 0, locked: false,
  });
  const verifier = rpc ? createChainVerifier({ rpcCall: rpc }) : undefined;
  return new OwmAuthServer({
    rp: 'rp.example', clock: () => START, enrollmentStore, ...(verifier ? { verifier } : {}), ...opts,
  });
}

// The contract wallet's reply: the OWNER key signs the canonical string,
// the envelope claims the CONTRACT address (Safe-style 65-byte owner sig).
function contractAuthResponse({ challenge, matchCode, exp, action = 'log in', addr = CONTRACT }) {
  const payload = canonicalAuthPayload({
    rp: 'rp.example', action, challenge, match: matchCode, binding: undefined, exp,
  });
  return buildWmAuthResponse({
    challenge, match: matchCode, addr, sig: signPersonalMessage(payload, OWNER_KEY),
  });
}

test('OwmAuthServer.verifyResponse: ERC-1271 happy path for an enrolled contract wallet', async () => {
  const rpc = fakeRpc();
  const server = await contractEnrolledServer(rpc);
  const { envelope, matchCode } = await server.createChallenge({ userId: 'u1', action: 'log in' });
  const resp = contractAuthResponse({ challenge: envelope.challenge, matchCode, exp: envelope.exp });
  const res = await server.verifyResponse(resp);
  assert.ok(res.ok);
  assert.equal(res.userId, 'u1');
  assert.equal(res.address, CONTRACT.toLowerCase());
  assert.deepEqual(rpc.calls.map((c) => c.method), ['eth_getCode', 'eth_call']);
});

test('OwmAuthServer: bad magic fails as bad-signature and still counts toward lockout', async () => {
  const rpc = fakeRpc({ ret: `0x${'ff'.repeat(32)}` });
  const server = await contractEnrolledServer(rpc, { maxFailures: 1 });
  const { envelope, matchCode } = await server.createChallenge({ userId: 'u1', action: 'log in' });
  const res = await server.verifyResponse(contractAuthResponse({ challenge: envelope.challenge, matchCode, exp: envelope.exp }));
  assert.equal(res.ok, false);
  assert.equal(res.reason, 'bad-signature');
  assert.equal(res.locked, true, 'chain-path failures feed the same lockout ledger');
});

test('OwmAuthServer: contract wallet claiming a non-enrolled address fails wrong-address', async () => {
  const other = `0x${'d1ce'.repeat(10)}`;
  const rpc = fakeRpc(); // even a "valid" 1271 answer cannot bypass the pin
  const server = await contractEnrolledServer(rpc);
  const { envelope, matchCode } = await server.createChallenge({ userId: 'u1', action: 'log in' });
  const res = await server.verifyResponse(contractAuthResponse({
    challenge: envelope.challenge, matchCode, exp: envelope.exp, addr: other,
  }));
  assert.equal(res.ok, false);
  assert.equal(res.reason, 'wrong-address');
});

test('OwmAuthServer.verifyEnrollmentProof pins a contract wallet via ERC-1271', async () => {
  const verifier = createChainVerifier({ rpcCall: fakeRpc() });
  const server = new OwmAuthServer({ rp: 'rp.example', clock: () => START, verifier });
  const { envelope, matchCode } = await server.createEnrollmentChallenge({ userId: 'u2' });
  const proof = contractAuthResponse({
    challenge: envelope.challenge, matchCode, exp: envelope.exp,
    action: 'enroll this wallet as your second factor',
  });
  const res = await server.verifyEnrollmentProof(proof);
  assert.ok(res.ok);
  assert.equal((await server.getEnrollment('u2')).address, CONTRACT.toLowerCase());
});

function contractGrant({ exp, addr = CONTRACT, key = OWNER_KEY } = {}) {
  const iat = Math.floor(START / 1000);
  const fields = {
    rp: 'rp.example', client: 'shiny-app', scope: 'read:balance',
    aud: 'api.example', nonce: 'ab'.repeat(32), iat, exp: exp ?? iat + 900,
  };
  const sig = signPersonalMessage(canonicalGrantPayload(fields), key);
  return { fields, envelope: buildWmGrant({ ...fields, addr, sig }) };
}

test('GrantServer.verifyGrant: ERC-1271 happy path, grantId matches, registry works', async () => {
  const registry = new MemoryGrantRegistry();
  const grants = new GrantServer({
    rp: 'rp.example', aud: 'api.example', registry,
    verifier: createChainVerifier({ rpcCall: fakeRpc() }), clock: () => START,
  });
  const { fields, envelope } = contractGrant();
  const res = await grants.verifyGrant(envelope);
  assert.ok(res.ok);
  assert.equal(res.address, CONTRACT.toLowerCase());
  assert.equal(res.grantId, computeGrantId(fields));
  assert.ok(await registry.get(res.grantId), 'auto-registered on first sight');
});

test('GrantServer.verifyGrant: chain path still enforces expiry and the address pin', async () => {
  const grants = new GrantServer({
    rp: 'rp.example', aud: 'api.example',
    verifier: createChainVerifier({ rpcCall: fakeRpc() }), clock: () => START,
  });
  // core checks sig BEFORE exp, so an expired contract grant reaches the
  // chain path — which must still fail it closed as 'expired'
  const expired = contractGrant({ exp: Math.floor(START / 1000) - 10 });
  assert.equal((await grants.verifyGrant(expired.envelope)).reason, 'expired');
  const { envelope } = contractGrant();
  assert.equal((await grants.verifyGrant(envelope, { expectedAddress: OWNER })).reason, 'wrong-address');
});

test('GrantServer.revoke: only the granting contract may revoke, via ERC-1271', async () => {
  const registry = new MemoryGrantRegistry();
  const rpc = fakeRpc();
  const grants = new GrantServer({
    rp: 'rp.example', aud: 'api.example', registry,
    verifier: createChainVerifier({ rpcCall: rpc }), clock: () => START,
  });
  const { envelope } = contractGrant();
  const issued = await grants.verifyGrant(envelope);
  assert.ok(issued.ok);
  const ts = Math.floor(START / 1000) + 60;
  // owner key signs the revoke on the contract's behalf → 1271 accepts
  const revoke = buildWmGrantRevoke({
    grantId: issued.grantId, ts,
    sig: signPersonalMessage(canonicalGrantRevokePayload({ grantId: issued.grantId, ts }), OWNER_KEY),
  });
  const res = await grants.revoke(revoke);
  assert.ok(res.ok);
  assert.equal((await grants.verifyGrant(envelope)).reason, 'revoked');
  // a stranger's key still cannot revoke: 1271 says bad-magic → fail closed
  const grants2 = new GrantServer({
    rp: 'rp.example', aud: 'api.example', registry: new MemoryGrantRegistry(),
    verifier: createChainVerifier({ rpcCall: fakeRpc({ ret: `0x${'ff'.repeat(32)}` }) }), clock: () => START,
  });
  const again = contractGrant();
  const ok2 = await grants2.verifyGrant(again.envelope);
  assert.equal(ok2.ok, false, 'bad-magic verifier refuses even the grant');
});

test('createWalletSession.verifySignIn: OWM-AUTH path accepts a contract wallet', async () => {
  const session = createWalletSession({
    rp: 'rp.example', clock: () => START, verifier: createChainVerifier({ rpcCall: fakeRpc() }),
  });
  const exp = Math.floor(START / 1000) + 120;
  const challenge = 'cd'.repeat(32);
  const resp = contractAuthResponse({ challenge, matchCode: '42', exp, action: 'sign in' });
  const res = await session.verifySignIn({
    authResponse: resp,
    expected: { challenge, match: '42', exp, enrolledAddress: CONTRACT },
  });
  assert.ok(res.ok);
  assert.equal(res.method, 'owm-auth');
  assert.equal(res.address, CONTRACT.toLowerCase());
  const check = session.verifySession(res.token);
  assert.ok(check.ok);
  assert.equal(check.claims.sub, `eip155:1:${CONTRACT.toLowerCase()}`);
  // enrolled-address pin survives the chain path
  const pinned = await session.verifySignIn({
    authResponse: resp,
    expected: { challenge, match: '42', exp, enrolledAddress: OWNER },
  });
  assert.equal(pinned.reason, 'wrong-address');
});

function siweFixture() {
  const msg = new OwmSiweMessage({
    domain: 'rp.example',
    address: toChecksumAddress(CONTRACT),
    uri: 'https://rp.example/login',
    version: '1',
    chainId: 1,
    nonce: 'abcdefgh1234',
    issuedAt: new Date(START - 60000).toISOString(),
  });
  return { msg, text: msg.prepareMessage() };
}

test('OwmSiweMessage.verify: ERC-1271 via the { verifier } opt, arbitrary-length sig', async () => {
  const rpc = fakeRpc();
  const verifier = createChainVerifier({ rpcCall: rpc });
  const { msg, text } = siweFixture();
  const fatSig = `0x${'ab'.repeat(100)}`; // longer than 65 bytes — 1271-only shape
  const res = await msg.verify(
    { signature: fatSig, domain: 'rp.example', nonce: 'abcdefgh1234', time: new Date(START).toISOString() },
    { suppressExceptions: true, verifier },
  );
  assert.equal(res.success, true);
  assert.equal(rpc.calls[1].params[0].data, encodeIsValidSignatureCall(eip191Digest(text), 'ab'.repeat(100)));
  // bad magic → the classic INVALID_SIGNATURE error, catch branches keep matching
  const bad = await msg.verify(
    { signature: fatSig, time: new Date(START).toISOString() },
    { suppressExceptions: true, verifier: createChainVerifier({ rpcCall: fakeRpc({ ret: '0x' }) }) },
  );
  assert.equal(bad.success, false);
  assert.equal(bad.error.type, SiweErrorType.INVALID_SIGNATURE);
});

test('createWalletSession SIWE path threads the verifier through (6492 wrapped)', async () => {
  const rpc = fakeRpc();
  const session = createWalletSession({
    rp: 'rp.example', clock: () => START, verifier: createChainVerifier({ rpcCall: rpc }),
  });
  const { text } = siweFixture();
  const wrapped = wrap6492('ab'.repeat(65)); // 6492 wrapper only fits non-envelope seams
  const res = await session.verifySignIn({ message: text, signature: wrapped, nonce: 'abcdefgh1234' });
  assert.ok(res.ok);
  assert.equal(res.method, 'siwe');
  assert.equal(res.address, CONTRACT.toLowerCase());
});

// --- no-verifier parity: EOA-only behaviour is unchanged -----------------------

test('without a verifier, contract-wallet inputs fail exactly as before', async () => {
  // server seam
  const server = await contractEnrolledServer(null);
  const { envelope, matchCode } = await server.createChallenge({ userId: 'u1', action: 'log in' });
  const res = await server.verifyResponse(contractAuthResponse({ challenge: envelope.challenge, matchCode, exp: envelope.exp }));
  assert.equal(res.ok, false);
  assert.equal(res.reason, 'bad-signature');
  // grant seam
  const grants = new GrantServer({ rp: 'rp.example', aud: 'api.example', clock: () => START });
  assert.equal((await grants.verifyGrant(contractGrant().envelope)).reason, 'bad-signature');
  // session seam
  const session = createWalletSession({ rp: 'rp.example', clock: () => START });
  const exp = Math.floor(START / 1000) + 120;
  const challenge = 'cd'.repeat(32);
  const noV = await session.verifySignIn({
    authResponse: contractAuthResponse({ challenge, matchCode: '42', exp, action: 'sign in' }),
    expected: { challenge, match: '42', exp },
  });
  assert.equal(noV.reason, 'bad-signature');
  // siwe seam
  const { msg } = siweFixture();
  const siweRes = await msg.verify(
    { signature: `0x${'ab'.repeat(100)}`, time: new Date(START).toISOString() },
    { suppressExceptions: true },
  );
  assert.equal(siweRes.success, false);
  assert.equal(siweRes.error.type, SiweErrorType.INVALID_SIGNATURE);
});

test('with a verifier configured, plain EOA flows never touch RPC end-to-end', async () => {
  const rpc = fakeRpc();
  const verifier = createChainVerifier({ rpcCall: rpc });
  // full EOA ceremony through OwmAuthServer with the verifier configured
  const server = new OwmAuthServer({ rp: 'rp.example', clock: () => START, verifier });
  const wallet = new OwmAuthenticator({ privateKey: OWNER_KEY });
  const enroll = await server.createEnrollmentChallenge({ userId: 'u1' });
  const proof = wallet.handleAuthChallenge(enroll.envelope, { matchCode: enroll.matchCode, now: START });
  assert.ok((await server.verifyEnrollmentProof(proof)).ok);
  const { envelope, matchCode } = await server.createChallenge({ userId: 'u1', action: 'log in' });
  const res = await server.verifyResponse(wallet.handleAuthChallenge(envelope, { matchCode, now: START }));
  assert.ok(res.ok);
  assert.equal(res.address, wallet.addressFor('rp.example'));
  // EOA SIWE through the session with the verifier configured
  const session = createWalletSession({ rp: 'rp.example', clock: () => START, verifier });
  const msg = new OwmSiweMessage({
    domain: 'rp.example', address: toChecksumAddress(OWNER), uri: 'https://rp.example/login',
    version: '1', chainId: 1, nonce: 'abcdefgh1234', issuedAt: new Date(START - 60000).toISOString(),
  });
  const text = msg.prepareMessage();
  const s = await session.verifySignIn({ message: text, signature: `0x${signPersonalMessage(text, OWNER_KEY)}` });
  assert.ok(s.ok);
  assert.equal(rpc.calls.length, 0, 'EOA traffic must never generate RPC calls');
});
