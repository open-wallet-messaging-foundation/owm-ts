// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// WM-4 OWM-PRESENCE signing: call attestations (547). Each participant
// signs their OWN copy; N mutual copies form the attestation set,
// offline-verifiable like a 537 aggregate.
//
// Normative honesty: this proves KEY PRESENCE in the
// encrypted session, not a warm body — human assurance comes from the SAS
// read aloud + per-signer WYSIWYS, never from this signature alone. It is
// consensual by construction: nobody can be attested without their own
// signature, and an absent signature proves nothing about absence.

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { addressFromPrivateKey, signPersonalMessage, recoverPersonalMessage } from './eth-sign.js';
import { buildWmCallAttestation } from './envelope.js';

// Deterministic hash of the participant set: sorted inboxIds, one per
// line, domain-tagged. Everyone on the call computes the same value.
export function participantsHash(inboxIds) {
  if (!Array.isArray(inboxIds) || inboxIds.length === 0) throw new Error('inboxIds required');
  const canon = ['owm-participants-v1', ...[...inboxIds].sort()].join('\n');
  return bytesToHex(sha256(utf8ToBytes(canon)));
}

export function canonicalCallAttestation({ roomId, callId, fingerprint, participantsHash: ph, fromTs, toTs, attester }) {
  return [
    'owm-call-attestation-v1',
    `roomId:${roomId}`,
    `callId:${callId}`,
    `fingerprint:${fingerprint}`,
    `participants:${ph}`,
    `from:${fromTs}`,
    `to:${toTs}`,
    `attester:${attester.toLowerCase()}`,
  ].join('\n');
}

export function createCallAttestation({ privateKey, roomId, callId, fingerprint, participantsHash: ph, fromTs, toTs }) {
  const attester = addressFromPrivateKey(privateKey);
  const sig = signPersonalMessage(
    canonicalCallAttestation({ roomId, callId, fingerprint, participantsHash: ph, fromTs, toTs, attester }),
    privateKey,
  );
  return buildWmCallAttestation({ roomId, callId, fingerprint, participantsHash: ph, fromTs, toTs, attester, sig });
}

export function verifyCallAttestation(env) {
  if (typeof env !== 'object' || env === null) return { ok: false, error: 'not an attestation' };
  const signer = recoverPersonalMessage(canonicalCallAttestation(env), env.sig);
  if (!signer) return { ok: false, error: 'bad signature' };
  if (signer !== env.attester.toLowerCase()) return { ok: false, error: 'signer is not the attester' };
  return { ok: true, attester: signer };
}

// Verify a mutual attestation SET: every copy must verify, agree on the
// same (roomId, callId, fingerprint, participantsHash), and come from a
// distinct attester. Returns the distinct attesters on success. Policy
// decides how many attesters it demands and how they map to OWM-APPROVAL
// signers (WM-7 §9).
export function verifyAttestationSet(envs) {
  if (!Array.isArray(envs) || envs.length === 0) return { ok: false, error: 'empty set' };
  const first = envs[0];
  const attesters = new Set();
  for (const env of envs) {
    const v = verifyCallAttestation(env);
    if (!v.ok) return { ok: false, error: v.error };
    if (env.roomId !== first.roomId || env.callId !== first.callId
      || env.fingerprint !== first.fingerprint || env.participantsHash !== first.participantsHash) {
      return { ok: false, error: 'attestations disagree on the call' };
    }
    if (attesters.has(v.attester)) return { ok: false, error: `duplicate attester: ${v.attester}` };
    attesters.add(v.attester);
  }
  return { ok: true, attesters: [...attesters] };
}
