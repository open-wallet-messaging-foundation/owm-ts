// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OWM-SCOPE — capability scopes and least-privilege signing.
//
// Every signature in OWM authorizes SOMETHING; least privilege demands we
// name exactly what, and nothing more. A scope is a dot-delimited
// capability token (`owm.pay.settle`). Three surfaces share ONE taxonomy:
//   - the SIGNING abstraction (each signing request declares its scope),
//   - OWM-GRANT (WM-7 §4 — a grant delegates a set of scopes to a client/agent),
//   - OWM-BIND (WM-7 §10) and agent delegation (what authority a principal
//     hands on, and to whom).
// One taxonomy means an agent granted `owm.message.send` literally cannot
// get a payment signed: no signer in the chain will sign `owm.pay.settle`
// for it, and the gateway rejects the request as out-of-grant-scope.
//
// THE SECURITY CRUX (WYSIWYS for authority): a DECLARED scope is only
// trustworthy if it is derivable from the signed BYTES. Every OWM canonical
// begins with a domain tag on its first line (`owm-auth-v1`, `owm-grant-v1`,
// …), and that tag is inside what gets signed — so a signature over an auth
// payload can never be replayed as a grant. `scopeForCanonical` recovers the
// bound base scope from the payload; a conforming signer computes it itself
// and refuses if the request's declared scope disagrees. The declared scope
// is a hint and a policy key, NEVER a substitute for parsing the payload.

// The canonical taxonomy. Dot-delimited, hierarchical, `owm.`-namespaced.
// A grant may also carry app-defined scopes alongside these; the `owm.`
// namespace is reserved for protocol capabilities.
export const SCOPES = Object.freeze([
  'owm.identity.enroll', // create/attach an XMTP identity (signs XMTP's bytes)
  'owm.message.send',
  'owm.room.create',
  'owm.room.admin', // add/remove members, revoke invites
  'owm.invite.create',
  'owm.contact.exchange', // SCX contact card (owm-scx-card-v1)
  'owm.intro.vouch', // owm-intro-v1
  'owm.auth.respond', // owm-auth-v1 (second factor / step-up)
  'owm.grant.issue', // owm-grant-v1
  'owm.grant.revoke', // owm-grant-revoke-v1
  'owm.approval.sign', // owm-approval-v1
  'owm.pay.request', // owm-broadcast-request-v1 (tip jar / donation / ticket)
  'owm.pay.settle', // authorize an on-chain settlement (tx-intent)
  'owm.settlement-card.issue', // owm-settlement-card-v1
  'owm.presence.attest', // owm-call-attestation-v1
  'owm.bind.enroll', // OWM-BIND institutional binding enrol
  'owm.bind.rotate',
  'owm.bind.revoke',
]);

const SCOPE_SET = new Set(SCOPES);

// Domain tag (first line of a canonical signing payload) -> the scope a
// signature over that payload authorizes. Because the tag is signed, this
// mapping is cryptographically bound: it cannot be spoofed by a lying
// relying party or gateway.
const DOMAIN_SCOPE = Object.freeze({
  'owm-auth-v1': 'owm.auth.respond',
  'owm-grant-v1': 'owm.grant.issue',
  'owm-grant-revoke-v1': 'owm.grant.revoke',
  'owm-approval-v1': 'owm.approval.sign',
  'owm-intro-v1': 'owm.intro.vouch',
  'owm-settlement-card-v1': 'owm.settlement-card.issue',
  'owm-broadcast-request-v1': 'owm.pay.request',
  'owm-call-attestation-v1': 'owm.presence.attest',
  'owm-scx-card-v1': 'owm.contact.exchange',
});

export function isKnownScope(s) {
  return typeof s === 'string' && SCOPE_SET.has(s);
}

// Parse a space-separated scope string (the OWM-GRANT `scope` format) into
// a token list; pass through an array unchanged.
export function parseScope(s) {
  if (Array.isArray(s)) return s;
  return typeof s === 'string' ? s.split(' ').filter(Boolean) : [];
}

// The scope a signature over `payload` authorizes, recovered from the
// domain tag INSIDE the signed bytes — or null if the payload carries no
// recognized OWM domain tag (e.g. XMTP enrollment bytes, whose scope is
// declared, not payload-bound). A signer MUST prefer this over any
// externally-declared scope.
export function scopeForCanonical(payload) {
  if (typeof payload !== 'string' || payload.length === 0) return null;
  const nl = payload.indexOf('\n');
  const tag = nl === -1 ? payload : payload.slice(0, nl);
  return DOMAIN_SCOPE[tag] ?? null;
}

// Least-privilege subsumption. A granted scope covers itself and everything
// hierarchically beneath it: `owm.pay` covers `owm.pay.settle`; the segment
// boundary (`.`) stops `owm.pay` from covering `owm.payment.*`. `*` covers
// all — root authority, the OPPOSITE of least privilege: allowed so tooling
// can express it, discouraged in every real policy.
export function scopeCovers(granted, requested) {
  if (granted === '*' || granted === requested) return true;
  return typeof requested === 'string' && requested.startsWith(`${granted}.`);
}

// Does the GRANTED scope set permit the REQUESTED scope? This is the check a
// gateway runs before minting a signing request for an agent, and a signer
// runs against its own policy allowlist before signing.
export function scopeSatisfies(grantedSet, requested) {
  return parseScope(grantedSet).some((g) => scopeCovers(g, requested));
}

// Expand a (possibly wildcard/broad) grant into the concrete leaf scopes it
// authorizes — for showing a human EXACTLY what they are about to delegate.
export function expandScope(grantedSet) {
  const set = parseScope(grantedSet);
  return SCOPES.filter((leaf) => set.some((g) => scopeCovers(g, leaf)));
}

// Verify a declared scope against the payload it accompanies. Returns:
//   { ok:true, scope, source:'payload-bound' } — tag recognized, declared matches
//   { ok:true, scope, source:'declared' }      — no recognized tag; declared accepted as-is
//   { ok:false, error }                         — declared scope contradicts the signed bytes
// The 'payload-bound' path is the trustworthy one; 'declared' is the honest
// fallback for non-OWM signing bytes (identity enrollment) and MUST be
// surfaced to the human, never silently trusted.
export function checkDeclaredScope(declared, payload) {
  const bound = scopeForCanonical(payload);
  if (bound) {
    if (declared === bound) return { ok: true, scope: bound, source: 'payload-bound' };
    return { ok: false, error: `declared scope "${declared}" contradicts payload-bound scope "${bound}"` };
  }
  if (!isKnownScope(declared)) return { ok: false, error: `unknown scope "${declared}"` };
  return { ok: true, scope: declared, source: 'declared' };
}
