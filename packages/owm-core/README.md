# @open-wallet-messaging/core

The pure-logic core of OWM (Open Wallet Messaging): envelopes, the kind
registry, invite tokens, SCX secure contact exchange (SPAKE2 + signed
contact cards + SAS), the OWM-AUTH/OWM-GRANT signing primitives, EIP-191
utilities, and a zero-dependency rendezvous-relay client.

No I/O, no framework, no transport — everything here is a function you
can call in a test. Crypto comes from `@noble/curves` and
`@noble/hashes`; that's the entire dependency list.

```sh
npm install @open-wallet-messaging/core
```

Wire formats are normative in the spec documents — this README shows you
how to *use* the code and links out for byte-level detail:
[`WM-2`](https://github.com/open-wallet-messaging-foundation/spec/blob/main/WM-2-relays.md) (relays),
[`WM-3`](https://github.com/open-wallet-messaging-foundation/spec/blob/main/WM-3-scx.md) (SCX),
[`WM-7`](https://github.com/open-wallet-messaging-foundation/spec/blob/main/WM-7-auth.md) (auth/grants). Kind numbers live in
`api/kinds.json`, mirrored in `src/kinds.js`.

## The modules at a glance

| Module | What it gives you |
|---|---|
| [`kinds.js`](#the-kind-registry) | numeric kind codes ↔ kebab-case wire names |
| [`envelope.js`](#strict-envelopes) | strict build/parse for every OWM message |
| [`invite.js`](#invites-and-fragment-only-tokens) | bearer invite tokens, lifecycle, fragment-only links |
| [`scx-code.js` / `spake2.js` / `scx.js`](#scx-secure-contact-exchange) | pairing codes, the PAKE, the whole SCX session |
| [`auth.js`](#auth-and-grant-signing) | canonical signing strings + sign/verify for kinds 530–534 |
| [`eth-sign.js`](#eip-191-signing-utilities) | EIP-191 personal-message sign/recover, addresses, EIP-55 |
| [`rendezvous-client.js`](#rendezvous-client) | blind-mailbox HTTP client for the `owm-rendezvous` relay |

Everything is exported flat from the package root:

```js
import { parseMessage, createScxSession, generateCode /* … */ } from '@open-wallet-messaging/core';
```

---

## The kind registry

Every OWM message has a numeric kind and a kebab-case wire name. The
normative registry is `api/kinds.json`; `kinds.js` mirrors it:

```js
import { KIND, wireName, kindCode, isOwmKind, isVendorKind } from '@open-wallet-messaging/core';

KIND.WmAuthChallenge;          // 530
wireName(530);                 // 'wm-auth-challenge'
kindCode('wm-ping');           // 500
isOwmKind(512);                // true  — 500–549 is the OWM primitive range
isVendorKind(1001, 'vnd.acme.thing');  // true — 1000+, 'vnd.' prefix required
```

> **Tips**
> - Adding a kind means changing `api/kinds.json` first — the JS table
>   mirrors it, never the other way round.
> - Vendor extensions live at 1000+ with a `vnd.` wire-name prefix; don't
>   squat the primitive range.

## Strict envelopes

`envelope.js` builds and parses every OWM message with one hard rule:
**for a known kind, a payload with a missing, extra, or type-mismatched
key is rejected.** No "be liberal in what you accept" — a message that
doesn't validate is refused with a reason, and a message of an *unknown*
kind is surfaced (not dropped) so a client can fall back to rendering
readable text. Render-or-fallback, never silently discard, never
half-parse.

```js
import { buildPing, parseMessage } from '@open-wallet-messaging/core';

const ping = buildPing({ purpose: 'attention', ts: Date.now() });
const wire = JSON.stringify(ping);

const parsed = parseMessage(wire);
// four possible shapes — handle all of them:
//   { ok: true, kind, body }            known kind, strictly valid
//   { ok: false, error, kind }          known kind, invalid payload → refuse
//   { ok: false, unknown: true, kind }  unknown kind → render as text, don't drop
//   { ok: false, plain: true }          not an envelope at all → it's chat text
```

Builders exist for every kind: `buildPing`, `buildPong`, `buildKnock`,
`buildScxPakeA/B`, `buildWmContactCard`, `buildScxConfirm`,
`buildScxAbort`, `buildWmAuthChallenge`, `buildWmAuthResponse`,
`buildWmGrantRequest`, `buildWmGrant`, `buildWmGrantRevoke`. Each
validates on build, so an invalid envelope throws at the source instead
of failing at the peer.

> **Tips**
> - `parseMessage` takes the **raw string**; builders return objects. If
>   you already hold an object, `parseMessage(JSON.stringify(obj))` is
>   the idiom (that's what `@open-wallet-messaging/auth` does internally).
> - Mind the time units: WM-3/WM-4 kinds carry `ts` in unix
>   **milliseconds**, but the WM-7 kinds (530–534) carry `iat`/`exp`/`ts`
>   in unix **seconds** (JWT convention). This is deliberate and
>   documented in WM-7 §2 — and it will bite you exactly once.
> - String fields in the 530s ban CR/LF outright (they ride
>   newline-delimited canonical signing strings).
> - `randomNonce(bytes = 16)` gives you lowercase-hex CSPRNG nonces —
>   use 32 bytes for challenge/grant nonces as the specs do.

## Invites and fragment-only tokens

Bearer invite tokens for rooms: a 256-bit opaque nonce with a small
lifecycle state machine (`active → redeemed | exhausted | revoked |
expired`) and an optional address pre-commitment for high-assurance
invites.

```js
import {
  createInvite, inviteStatus, isAdmissible, redeem,
  buildInviteLink, parseInviteLink,
} from '@open-wallet-messaging/core';

const invite = createInvite({ roomId: 'room-1', now: Date.now(), maxUses: 1 });
const link = buildInviteLink({
  origin: 'https://app.example.org',
  roomId: 'room-1',
  adminInboxId: 'inbox-abc',
  token: invite.token,
});
// https://app.example.org/?room=room-1&admin=inbox-abc&m=chat#t=<token>

const parsed = parseInviteLink(link);          // { roomId, token, … }
if (isAdmissible(invite, Date.now(), presenterAddress)) {
  const updated = redeem(invite, Date.now(), presenterAddress);
}
```

**Why the token rides the URL fragment (`#t=`), and only the fragment:**
browsers never send fragments in HTTP requests. That single fact keeps
the secret out of server access logs, CDN and proxy logs, `Referer`
headers, and the link-preview fetchers that chat apps unleash on every
pasted URL. A token in a query string would be logged a dozen places
before the invitee ever clicked it — which is why `parseInviteLink`
**refuses** (throws) if it finds a token in the query string. Never
weaken this.

> **Tips**
> - Invites are plain objects and the mutators are pure (`redeem`
>   returns a new object) — persist them however you like.
> - `boundTo` pre-commits an invite to one presenter address; anyone
>   else is inadmissible even holding the token.
> - Bearer links are for *invitations*, never money-destination
>   exchange — that's what SCX is for (WM-3 §10).

## SCX: secure contact exchange

The problem: two people want to exchange wallet addresses
(payment-grade, proof-of-ownership) but their only common channel is
insecure — a phone call, an SMS, a chat app. Pasting an address into
that channel invites swap attacks and typo disasters.

The SCX answer: the insecure channel carries only a short, low-value
**pairing code**, readable out loud in five seconds:

```
7-panda-mocha-quilt
│ └── three wordlist words = the PAKE password (~31 bits)
└──── rendezvous mailbox number (no security value)
```

Alice reads that to Bob over the call. Both sides then run SPAKE2
(RFC 9382) through a blind rendezvous mailbox: the weak code becomes a
full-strength session key, and — the PAKE's magic — an attacker gets
**exactly one online guess**, and a wrong guess breaks the handshake
*visibly* (`scx-abort`), never silently. ~31 bits is plenty when brute
force is one guess per handshake with a human watching.

Then each side sends a **contact card** signed over *this exchange's
transcript hash* — so a genuine card captured from any other session
fails verification here (no cut-and-paste MITM). Finally both screens
show the same **SAS** (2 emoji + 4 digits, e.g. `🦄 🍋 0417`); the
humans compare out loud and tap ✓. Mismatch → abort, no
"proceed anyway" button, ever.

```js
import { generateCode, parseCode, createScxSession } from '@open-wallet-messaging/core';

// Alice (role 'a' — she generated the code)
const code = generateCode({ mailboxId: 7 });      // e.g. '7-panda-mocha-quilt'
const alice = createScxSession({
  role: 'a', code,
  identity: { privateKey: aliceKey, inboxId: 'alice-inbox', displayName: 'Alice' },
  now: Date.now(),
});

// Bob (role 'b' — he typed the code in; parseCode catches typos FIRST)
const bob = createScxSession({
  role: 'b', code,
  identity: { privateKey: bobKey, inboxId: 'bob-inbox', displayName: 'Bob' },
  now: Date.now(),
});

// Drive both sides: send whatever `send` arrays come back, feed inbound
// envelopes to receive(). Transport-agnostic — any ordered byte pipe.
let res = alice.start();                          // → [scx-pake-a]
// … shuttle envelopes until both reach 'card-exchanged' …

console.log(alice.sas.display);                   // '🦄 🍋 0417'
console.log(bob.sas.display);                     // '🦄 🍋 0417'  — humans compare
alice.acceptSas(); bob.acceptSas();               // → state 'confirmed'
console.log(alice.peerCard);                      // Bob's verified, transcript-bound card
```

The full runnable version (with a real relay in the middle) is
[`examples/scx-demo/`](https://github.com/open-wallet-messaging-foundation/owm-ts/tree/main/examples/scx-demo). The state machine,
key schedule, and security claims are specified in
[`WM-3`](https://github.com/open-wallet-messaging-foundation/spec/blob/main/WM-3-scx.md).

> **Tips**
> - `parseCode` rejects unknown words **before** the PAKE runs — a
>   transcription typo ("moka" for "mocha") is caught locally instead of
>   burning the one online guess.
> - The wordlist is the EFF short wordlist (1,296 words, unique 3-char
>   prefixes, no homophones) — chosen precisely for phone calls.
> - The session is a pure state machine: `start()`, `receive(env)`,
>   `acceptSas()`, `rejectSas()`, `abort(reason)`. Everything it wants
>   sent comes back in `send` arrays; it never touches a socket.
> - `session.sessionKey` (`Ke`) is `null` until the peer proves knowledge
>   of the code, and is wiped on abort. Don't cache it early.
> - Never skip the SAS in software. The one degenerate case where it's
>   trivially satisfied (QR in person) still *shows* it.
> - `verifyContactCard(card, transcriptHash)` is also exported standalone
>   — `@open-wallet-messaging/auth` uses it to enroll auth keys from an SCX ceremony.
> - `spake2.js` is exported (`deriveW`, `spake2Start`, `spake2Finish`,
>   `constantTimeEqual`) and validated against all four RFC 9382
>   Appendix B vectors, but SCX is the intended consumer — prefer
>   `createScxSession` unless you're building a protocol.

## Auth and grant signing

The pure protocol half of WM-7 (the `@open-wallet-messaging/auth` package builds the
server/wallet state machines on top of these). Canonical signing strings
with mutually disjoint domain tags, plus sign/verify for challenges,
responses, grants, and revocations:

```js
import {
  buildAuthChallenge, signAuthResponse, verifyAuthResponse,
  signGrant, verifyGrant, signGrantRevoke, verifyGrantRevoke,
  computeGrantId, deriveRpSubKey,
} from '@open-wallet-messaging/core';

// server: mint a challenge (now = unix MS; envelope times = unix SECONDS)
const challenge = buildAuthChallenge({
  rp: 'example.org', action: 'log in', now: Date.now(), ttlS: 120,
});

// wallet: sign it with the code the user typed
const response = signAuthResponse({
  privateKey: walletKey, challenge, match: '42',
});

// server: verify against ITS OWN state — never against envelope fields
const res = verifyAuthResponse(response, {
  rp: 'example.org', action: 'log in',
  challenge: challenge.challenge, match: '42', exp: challenge.exp,
  enrolledAddress: '0x…', now: Date.now(),
});
// { ok: true, address } or { ok: false, reason: 'challenge-mismatch' |
//   'expired' | 'match-mismatch' | 'bad-signature' | 'wrong-address' }
```

Three domain tags — `owm-auth-v1`, `owm-grant-v1`,
`owm-grant-revoke-v1` — sit on top of the EIP-191 prefix, so an auth
signature can never verify as a grant, a revoke, an SCX card, or an
Ethereum transaction (the tests prove each cross-verification fails).

> **Tips**
> - `verifyAuthResponse` expects **every** field from your own state
>   (what you issued and displayed). Rebuilding expectations from the
>   attacker's envelope defeats the whole design.
> - `signAuthResponse` refuses challenges with TTL > 120 s — wallets must
>   never blind-sign a stockpileable challenge.
> - `computeGrantId(fields)` is SHA-256 of the canonical grant string:
>   deterministic, computable by anyone holding the fields.
> - `deriveRpSubKey(seed, rp)` (one address per relying party) is a
>   documented **placeholder** for BIP-32 hardened derivation — see
>   WM-7 §5 before shipping wallets on it.
> - Time convention, once more: `now` parameters are unix **ms**;
>   `iat`/`exp`/`ts` inside envelopes are unix **seconds**.

## EIP-191 signing utilities

One shared implementation for every OWM signature:

```js
import {
  signPersonalMessage, recoverPersonalMessage,
  addressFromPrivateKey, toChecksumAddress, eip191Digest,
} from '@open-wallet-messaging/core';

const sig = signPersonalMessage('hello', privateKey);  // 130 hex chars, r||s||v (v: 27/28)
const signer = recoverPersonalMessage('hello', sig);   // lowercase 0x address, or null
addressFromPrivateKey(privateKey);                     // lowercase 0x address
toChecksumAddress('0xfb69…');                          // EIP-55 mixed-case for display
```

> **Tips**
> - `recoverPersonalMessage` returns `null` for anything malformed — it
>   never throws on wire data. Compare the recovered address to your
>   expected one (case-insensitively); never trust a self-asserted
>   signer.
> - The EIP-191 prefix alone already guarantees none of these signatures
>   can be a valid Ethereum transaction; the domain tags add
>   protocol-level separation on top.

## Rendezvous client

A zero-dependency client for the `owm-rendezvous` relay (WM-2 §1):
short-lived, two-sided **blind mailboxes**. The relay sees opaque frames
only; side capabilities travel in the `Authorization` header — never a
URL, never a log line.

```js
import {
  createMailbox, claimMailbox, putFrame, pollFrames, openMailboxTransport,
} from '@open-wallet-messaging/core';

// Side A creates; the mailbox id goes into the pairing code
const box = await createMailbox({ baseUrl: 'http://127.0.0.1:8080' });
// Side B claims the other seat — exactly once (409 'already-claimed' after)
const seat = await claimMailbox({ baseUrl, id: box.id });

// Or skip the frame plumbing entirely — a byte pipe shaped for SCX:
const transport = openMailboxTransport({ baseUrl, id: box.id, sideCap: box.sideCap });
await transport.send(JSON.stringify(envelope));
const bytes = await transport.recv();            // long-polls the other side's frames
transport.close();
```

> **Tips**
> - HTTP failures throw an `Error` carrying `{ status, code }` (the
>   relay's kebab-case error code), so branch on `err.code ===
>   'already-claimed'` instead of string-matching messages.
> - `waitS` is capped at 25 (the relay clamp) — the client refuses higher
>   values rather than silently clamping.
> - You read only the *other* side's frames; your own never echo back.
> - One `recv()` at a time per transport — the cursor is not re-entrant.
> - `bytesToBase64` / `base64ToBytes` (standard, padded alphabet) are
>   exported too — the relay's frame encoding.

---

## Testing

```sh
cd packages/owm-core && npm test    # pure logic, no network, no relay
```

Every module ships happy- and unhappy-path tests; SPAKE2 is checked
against the RFC 9382 Appendix B vectors. If you're extending the
package, the test files double as usage documentation — start there.

Dependencies: `@noble/curves`, `@noble/hashes`. Node ≥ 20, MIT.
