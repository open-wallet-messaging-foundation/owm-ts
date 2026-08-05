// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// WM-4 warm introductions (wm-intro, kind 519). A, connected to both B and
// C, sends each a SIGNED vouch for the other; each side gets a consent gate,
// and on double-accept the new DM opens carrying A's attestation. The
// signature is over a canonical string bound to this specific intro (shared
// nonce, both parties' identities, purpose), so the attestation stays
// verifiable when quoted outside the channel it arrived on — and a genuine
// intro cannot be replayed to vouch for someone else.
//
// Same idiom as SCX contact cards (scx.js) and WM-7 grants (auth.js):
// EIP-191 personal-message signatures over a newline-joined, domain-tagged
// payload. Newlines are banned in every string field by the wm-intro SPEC.

import { addressFromPrivateKey, signPersonalMessage, recoverPersonalMessage } from './eth-sign.js';
import { buildWmIntro } from './envelope.js';

export function canonicalIntroPayload({ nonce, introducer, about, aboutInboxId, aboutName, actor, purpose, ts }) {
  return [
    'owm-intro-v1',
    `nonce:${nonce}`,
    `introducer:${introducer.toLowerCase()}`,
    `about:${about.toLowerCase()}`,
    `aboutInboxId:${aboutInboxId}`,
    `aboutName:${aboutName ?? ''}`,
    `actor:${actor ?? ''}`,
    `purpose:${purpose}`,
    `ts:${ts}`,
  ].join('\n');
}

// Build one signed copy of an intro (the copy TO one side, ABOUT the other).
// The caller sends two copies — same nonce, mirrored `about` fields.
export function createIntro({ privateKey, nonce, about, aboutInboxId, aboutName, actor, purpose, ts }) {
  const introducer = addressFromPrivateKey(privateKey);
  const payload = canonicalIntroPayload({ nonce, introducer, about, aboutInboxId, aboutName, actor, purpose, ts });
  const sig = signPersonalMessage(payload, privateKey);
  return buildWmIntro({ nonce, introducer, about, aboutInboxId, aboutName, actor, purpose, ts, sig });
}

// Verify a wm-intro envelope: recover the signer from the canonical payload
// and require it to equal the self-declared introducer. Callers must ALSO
// decide whether they trust that introducer (address-book match) — a valid
// signature from a stranger vouches for nothing.
export function verifyIntro(env) {
  if (typeof env !== 'object' || env === null) return { ok: false, error: 'not an intro' };
  const payload = canonicalIntroPayload(env);
  const signer = recoverPersonalMessage(payload, env.sig);
  if (!signer) return { ok: false, error: 'bad signature' };
  if (signer !== env.introducer.toLowerCase()) return { ok: false, error: 'signer is not the introducer' };
  return { ok: true, introducer: signer };
}
