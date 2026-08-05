// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// WM-4 OWM-PAY signing: settlement cards (543) and broadcast requests
// (546). Same idiom as SCX cards / grants / intros — EIP-191 over a
// newline-joined, domain-tagged canonical string. The '|' separator is
// banned inside account fields by the wm-settlement-card SPEC, and
// newlines are banned in every signed string field.
//
// Doctrine reminders: a settlement card's non-EVM `proof`
// binds that chain's key to this OWM identity but verifying it requires
// that chain's crypto — verifiers without it MUST render the listing as a
// claim, never a fact. A broadcast request's signature is over the RECEIVE
// TARGETS — clients render the pay UI only when the signature verifies AND
// the signer holds the matching room role / verified-sender badge (WM-4).

import { addressFromPrivateKey, signPersonalMessage, recoverPersonalMessage } from './eth-sign.js';
import { buildWmSettlementCard, buildWmBroadcastRequest } from './envelope.js';

function accountLine(a) {
  return [
    a.account,
    a.methods.join(' '),
    (a.assets ?? []).join(' '),
    a.memoRequired ? 1 : 0,
    a.minConfirmations ?? '',
    a.proof ?? '',
  ].join('|');
}

export function canonicalSettlementCard({ addr, accounts, ts, exp }) {
  return [
    'owm-settlement-card-v1',
    `addr:${addr.toLowerCase()}`,
    `ts:${ts}`,
    `exp:${exp ?? ''}`,
    ...accounts.map(accountLine),
  ].join('\n');
}

export function createSettlementCard({ privateKey, accounts, ts, exp }) {
  const addr = addressFromPrivateKey(privateKey);
  const sig = signPersonalMessage(canonicalSettlementCard({ addr, accounts, ts, exp }), privateKey);
  return buildWmSettlementCard({ addr, accounts, ts, exp, sig });
}

export function verifySettlementCard(env, now) {
  if (typeof env !== 'object' || env === null) return { ok: false, error: 'not a card' };
  if (typeof now === 'number' && typeof env.exp === 'number' && now >= env.exp) {
    return { ok: false, error: 'expired' };
  }
  const signer = recoverPersonalMessage(canonicalSettlementCard(env), env.sig);
  if (!signer) return { ok: false, error: 'bad signature' };
  if (signer !== env.addr.toLowerCase()) return { ok: false, error: 'signer is not the declared identity' };
  return { ok: true, addr: signer };
}

export function canonicalBroadcastRequest({ nonce, purpose, amount, asset, targets, memo, requester, ts, exp }) {
  return [
    'owm-broadcast-request-v1',
    `nonce:${nonce}`,
    `purpose:${purpose}`,
    `amount:${amount ?? ''}`,
    `asset:${asset ?? ''}`,
    `targets:${targets.join(' ')}`,
    `memo:${memo ?? ''}`,
    `requester:${requester.toLowerCase()}`,
    `ts:${ts}`,
    `exp:${exp}`,
  ].join('\n');
}

export function createBroadcastRequest({ privateKey, nonce, purpose, amount, asset, targets, memo, ts, exp }) {
  const requester = addressFromPrivateKey(privateKey);
  const sig = signPersonalMessage(
    canonicalBroadcastRequest({ nonce, purpose, amount, asset, targets, memo, requester, ts, exp }),
    privateKey,
  );
  return buildWmBroadcastRequest({ nonce, purpose, amount, asset, targets, memo, requester, ts, exp, sig });
}

// Verifies the signature chain only. The caller must SEPARATELY check the
// role binding (signer is the room's performer / a WM-4 verified sender)
// before rendering any pay UI — a valid signature from a random room
// member is exactly the poisoning case the render rule exists to stop.
export function verifyBroadcastRequest(env, now) {
  if (typeof env !== 'object' || env === null) return { ok: false, error: 'not a request' };
  if (typeof now === 'number' && now >= env.exp) return { ok: false, error: 'expired' };
  const signer = recoverPersonalMessage(canonicalBroadcastRequest(env), env.sig);
  if (!signer) return { ok: false, error: 'bad signature' };
  if (signer !== env.requester.toLowerCase()) return { ok: false, error: 'signer is not the requester' };
  return { ok: true, requester: signer };
}
