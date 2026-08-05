# @open-wallet-messaging/auth

Use a crypto wallet as a **second factor**, a **sign-in method**, and a
**delegated-authorization grantor** — server-side, with nothing but
`@open-wallet-messaging/core` and Node built-ins.

In one breath: this library replaces the verification side of
Google-Authenticator-style TOTP (speakeasy/otplib), is a drop-in for the
`siwe` package, and can either *bridge into* your existing OIDC login
stack or *replace it outright*. The user's phone wallet becomes the
authenticator; your database stores a public address instead of a secret.

```sh
npm install @open-wallet-messaging/auth
```

What it does **not** do yet, stated up front: no WebAuthn-level
origin-binding (see [the honest ceiling](#security-properties-and-the-honest-ceiling)),
smart-contract-wallet (ERC-1271/6492) signatures are **off by default** —
they need a chain RPC, which you opt into explicitly (see
[Smart-contract wallets](#smart-contract-wallets-safe-erc-4337)) — and
the OIDC bridge is a deliberate v0-dev profile (no refresh tokens, no
dynamic client registration — details below). The wire formats are
normative in [`spec/WM-7-auth.md`](https://github.com/open-wallet-messaging-foundation/spec/blob/main/WM-7-auth.md).

## What it replaces

| You have today | You get | The seam |
|---|---|---|
| TOTP (speakeasy / otplib) | [`OwmAuthServer` + `TwoFactor`](#2fa-and-step-up-approval) | the verification call-site |
| `siwe` (EIP-4361) | [`OwmSiweMessage`](#sign-in-with-a-wallet-siwe-compatible) | change the import — API-compatible |
| OIDC login (openid-client / passport) | [`createOidcIssuer`](#the-oidc-bridge) | point your OIDC client at one more issuer |
| OIDC you'd rather delete | [`createWalletSession`](#native-wallet-sessions) | issue/verify a session JWT, no IdP |
| OAuth delegated access | [`GrantServer`](#delegated-grants-oauth-without-oauth) | replace token verification |

## Two-minute quickstart

A complete, runnable 2FA round-trip. In real life the "wallet" lines run
on the user's phone and the envelope travels E2EE (XMTP is the reference
transport); here both halves live in one process so you can watch the
whole ceremony:

```js
import { OwmAuthServer, TwoFactor, OwmAuthenticator } from '@open-wallet-messaging/auth';

// --- your server ---
const server = new OwmAuthServer({ rp: 'example.org' });
const twoFactor = new TwoFactor({ server });

// --- the user's wallet (normally on their phone) ---
const wallet = new OwmAuthenticator({ seed: 'c0ffee'.repeat(6) });

// One-time enrollment inside an already-authenticated session:
const enroll = await server.createEnrollmentChallenge({ userId: 'u1' });
const proof = wallet.handleAuthChallenge(enroll.envelope, { matchCode: enroll.matchCode });
await server.verifyEnrollmentProof(proof); // pins the wallet's address to 'u1'

// Every login after that:
const { challengeId, matchCode, envelope } = await twoFactor.request('u1', 'log in');
// 1. show matchCode ("07") on YOUR login screen
// 2. send envelope to the wallet over your transport
// 3. the user reads the code off your screen and types it into the wallet:
const response = wallet.handleAuthChallenge(envelope, { matchCode });
// 4. transport feeds the reply back:
await twoFactor.submit(response);
const ok = await twoFactor.awaitApproval(challengeId, { timeoutMs: 60_000 });
console.log(ok); // { ok: true, userId: 'u1', address: '0x…' }
```

Run the narrated version: `node examples/auth-demo/two-factor.mjs` from
the repo root (all four demos in [`examples/auth-demo/`](https://github.com/open-wallet-messaging-foundation/owm-ts/tree/main/examples/auth-demo)
are standalone — no transport, no network).

## How the ceremony works (30 seconds)

OWM-AUTH is **challenge–push–sign**, not code-entry:

1. The user acts on your screen ("log in", "release the wire"). Your
   screen displays a short **match code** (2 digits by default).
2. Your server pushes a challenge envelope to the enrolled wallet,
   end-to-end encrypted. The match code is **not in the envelope**.
3. The wallet renders the relying party and the action verbatim, and asks
   the user to **type the match code from your screen**. Then it signs
   `rp + action + nonce (+ binding) + exp` under a domain-separated
   EIP-191 message and replies.
4. Your server verifies: right nonce (single-use), right code, right
   signature, right (enrolled) address. Any attempt burns the nonce.

That direction-flip — the code travels *user → wallet*, never over the
wire — is why an unsolicited push can't be approved: the victim never saw
a code. And because the server stores only a public address, a database
breach leaks nothing that helps an attacker pass 2FA.

---

## 2FA and step-up approval

`OwmAuthServer` is the protocol engine; `TwoFactor` wraps it in the shape
of a TOTP verification call-site (request → await a promise).

### Migrating from speakeasy / otplib

The drop-in is at the **verification seam**, not the API signature —
there is no shared secret to provision and no 6-digit code to check:

| speakeasy / otplib | @open-wallet-messaging/auth |
|---|---|
| `speakeasy.generateSecret()` + QR provisioning | one-time enrollment: `createEnrollmentChallenge` / `verifyEnrollmentProof`, or `acceptScxCard` after a WM-3 SCX ceremony |
| store `secret` per user (a server-side shared secret) | store a public `address` per user (pluggable `EnrollmentStore`) |
| `totp.verify({ token, secret, window })` | `await twoFactor.awaitApproval(challengeId, { timeoutMs })` |
| user reads a code off an app and types it into YOUR site | your site shows a 2-digit match code; the user types it into THEIR wallet |
| brute force surface: 6 digits / 30 s window | single-use 32-byte nonce, ≤ 120 s, burned on any attempt; lockout after N failures |

```js
import { OwmAuthServer, TwoFactor } from '@open-wallet-messaging/auth';

const server = new OwmAuthServer({
  rp: 'example.org',
  maxFailures: 5,                       // lockout threshold
  onSecurityAlert: async ({ userId, failures }) => {
    await notifySecurityTeam(userId, failures);   // fires ONCE, on lockout
  },
});
const twoFactor = new TwoFactor({ server });

// login route (after password / first factor):
const { challengeId, matchCode, envelope } = await twoFactor.request(userId, 'log in');
showOnLoginScreen(matchCode);
await sendToWallet(userId, envelope);                       // your transport
// transport callback — feed EVERY wallet reply in:
onWalletReply((reply, ctx) => twoFactor.submit(reply, { challengeId: ctx.challengeId }));
// block the login on the outcome:
try {
  const { address } = await twoFactor.awaitApproval(challengeId, { timeoutMs: 60_000 });
  completeLogin(userId, address);
} catch (e) {
  // e.reason: 'timeout' | 'declined' | 'match-mismatch' | … ; e.locked: boolean
  rejectLogin(e.reason);
}
```

### Why the number-entry design kills MFA bombing

Push-2FA number-*matching* (Duo/Microsoft style) shows a number on both
screens and asks "same?" — a tired user taps yes at 3 a.m. Here the code
exists **only on the initiating screen**, and the wallet demands the user
type it. An attacker who triggers a push can spam the victim all night;
the victim cannot approve it, because there is no code to type — they
never saw one. Bombing dies by construction, not by user discipline. Two
digits are enough because the code is not a secret; it's a
channel-binding gesture. The security lives in the signature and nonce.

### Step-up approval for payments (WYSIWYS)

The same ceremony approves transactions: pass the full human-readable
summary as `action`, and what the user sees on their wallet is exactly
what gets signed — "what you see is what you sign":

```js
const stepUp = await twoFactor.request(
  userId,
  'Release wire #4711: $25,000 to acct …991',
);
```

`action` is capped at 140 chars, no newlines, and the wallet renders it
verbatim. Do not use vague actions ("confirm operation") — the action
string is your user's last line of defence against a swapped payload.

> **Tips & gotchas**
> - **`iat`/`exp` in the 530s envelopes are unix SECONDS** (the JWT
>   convention), while every `clock`/`now` option in this library is unix
>   **milliseconds**. If you build or inspect envelopes yourself, this
>   WILL bite you: an `exp` accidentally set in ms is ~56,000 years in
>   the future and gets rejected at the envelope layer (`isUnixS` caps at
>   1e12).
> - `ttlS` must be 1..120 — the spec hard-caps challenge life at 120 s and
>   wallets refuse to sign anything longer. Note the constructor does not
>   check this; an out-of-range `ttlS` throws at the first
>   `createChallenge()`.
> - `matchDigits` accepts 2..8. Stick with 2 unless a compliance checklist
>   demands more — longer codes add typing friction, not security.
> - Inject `clock: () => fakeNow` in tests and freeze time; every test in
>   this repo does exactly that (see `test/server.test.js`).
> - `verifyResponse`/`submit` take the **parsed envelope object**, not a
>   JSON string. If your transport hands you text, `JSON.parse` it first.
> - A wallet decline arrives as an `scx-abort` envelope, which carries
>   **no challenge id** — pass `{ challengeId }` from your transport
>   context or the decline can't be attributed (`unknown-challenge`).
> - Declines count toward lockout on purpose: N declines = someone is
>   bombing your user or the user keeps refusing — either way you want
>   the alert.
> - `twoFactor.request()` **throws** for a locked or unenrolled user;
>   wrap it. `unlockUser(userId)` is the support-desk path.
> - `submit()` settles the ceremony even if `awaitApproval()` was never
>   called (no unhandled-rejection landmines); a late `awaitApproval`
>   gets `reason: 'unknown-challenge'`.

---

## Sign in with a wallet (SIWE-compatible)

`OwmSiweMessage` mirrors the `siwe` package's `SiweMessage` (EIP-4361):
constructor from fields or message string, byte-exact `prepareMessage()`,
the same `verify()` resolve/reject shape, the same error strings,
`generateNonce()`. The migration is literally the import line:

```js
// before:
// import { SiweMessage, generateNonce } from 'siwe';
import { OwmSiweMessage as SiweMessage, generateNonce } from '@open-wallet-messaging/auth';

const nonce = generateNonce();                    // per session, server-side
const msg = new SiweMessage({
  domain: 'app.example.org',
  address: userAddress,                           // EIP-55 checksummed
  statement: 'Sign in to Example',
  uri: 'https://app.example.org/login',
  version: '1',
  chainId: 1,
  nonce,
});
const text = msg.prepareMessage();                // the user signs this
// … wallet returns `signature` …
const result = await msg.verify({ signature, domain: 'app.example.org', nonce });
if (result.success) login(msg.address);
```

| `siwe` v2 | `@open-wallet-messaging/auth` |
|---|---|
| `new SiweMessage(fields \| string)` | same |
| `msg.prepareMessage()` / `toMessage()` | same, byte-for-byte output |
| `await msg.verify({ signature, domain, nonce, time })` | same shape: resolves `{ success, data }`, rejects `{ success, error, data }` |
| `verify(…, { suppressExceptions: true })` | same — always resolves |
| `SiweErrorType.INVALID_SIGNATURE` etc. | same strings, so existing `catch` branches keep matching |
| `generateNonce()` | same contract (≥ 8 alphanumerics; we emit 17 chars ≈ 96 bits) |
| EIP-1271 contract wallets | **opt-in**: pass `{ verifier }` (from `createChainVerifier`) in the verify opts — the analogue of siwe's `provider` escape hatch. Without it, EOA only. See [Smart-contract wallets](#smart-contract-wallets-safe-erc-4337). |

> **Tips & gotchas**
> - `verify()` **rejects with a plain object** (`{ success: false, error,
>   data }`), not an `Error` — exactly like `siwe`. If that trips your
>   error handling, pass `{ suppressExceptions: true }` and branch on
>   `result.success`.
> - A mixed-case address must be a valid EIP-55 checksum or construction
>   throws. Use `toChecksumAddress` from `@open-wallet-messaging/core` to produce one.
> - Always check `nonce` (and `domain`) at verify time, against a nonce
>   YOU issued and stored server-side. A signature without a server-side
>   nonce check can be replayed.
> - `expirationTime` is exclusive (`time >= expirationTime` fails) —
>   matches `siwe`.

---

## Sign-in profiles: bridge or native?

Both profiles authenticate with the wallet. The difference is what
happens *after*: keep speaking OIDC to the rest of your stack, or drop
OIDC and hand out a plain signed session JWT. **This is the decision that
matters most in this library — pick deliberately:**

| | **OIDC bridge** (`createOidcIssuer`) | **Native sessions** (`createWalletSession`) |
|---|---|---|
| Keep existing openid-client / passport / NextAuth plumbing | ✔ yes — you add one more issuer, like adding "Sign in with Google" | ✘ you delete it |
| Redirects, authorization codes | yes (code + PKCE) | none |
| Central IdP watching logins | your own facade (self-hosted) | nobody |
| Output | standard ES256 `id_token` | compact ES256 session JWT `{ iss, sub, iat, exp }` |
| Other services verify via | your `/jwks` endpoint | your exported `jwks()` |
| Best when | many existing OIDC-consuming apps, gradual migration | greenfield, or you want the redirect dance gone |
| Maturity | v0-dev profile (see honesty note) | small and complete for what it does |

The quiet headline: **you don't need OIDC to have SSO.** A wallet
signature plus a JWKS-verifiable session token gives you cross-service
login with no identity provider in the loop. The bridge exists so you can
get there without a flag-day rewrite.

### The OIDC bridge

`createOidcIssuer` is a framework-agnostic issuer facade: you mount four
handlers on whatever HTTP stack you already run, and supply *one*
callback — the wallet ceremony. Everything OIDC-shaped is handled for
you: discovery, JWKS, authorization-code flow with **PKCE (S256)
required**, single-use codes, exact `redirect_uri` matching, `state`
passthrough, `nonce` claim, ES256 `id_token` with `sub` as a CAIP-10
account (`eip155:1:0x…`).

```js
import { createOidcIssuer } from '@open-wallet-messaging/auth';

const oidc = createOidcIssuer({
  issuer: 'https://auth.example.org',
  // YOUR wallet dance: run an OwmAuthServer challenge over XMTP, verify a
  // SIWE message, show a QR — anything. Throw (or return falsy) to deny.
  ceremony: async (authorizeParams) => {
    const { address } = await runWalletChallenge(authorizeParams);
    return { address };
  },
  signingKey: loadPem('oidc-es256.pem'),          // omit for a throwaway dev key
  clients: {                                       // static registration — use it
    'my-web-app': { redirect_uris: ['https://app.example.org/cb'] },
  },
});

// Mount the four handlers (express-ish pseudocode):
app.get('/.well-known/openid-configuration', (_, res) => res.json(oidc.discovery()));
app.get('/jwks', (_, res) => res.json(oidc.jwks()));
app.get('/authorize', async (req, res) => {
  const r = await oidc.authorize(req.query);
  if (r.redirectTo) return res.redirect(r.redirectTo);
  res.status(r.status).json({ error: r.error, error_description: r.error_description });
});
app.post('/token', async (req, res) => {
  const r = await oidc.token(req.body);
  res.status(r.status).json(r.body);
});
```

Your existing OIDC client config then gains one more issuer and nothing
else changes.

**v0-dev honesty:** the bridge is a minimal profile. NOT yet implemented:
dynamic client registration, consent persistence, refresh tokens, and the
userinfo endpoint. Without the `clients` option, any `client_id` with an
http(s) `redirect_uri` is accepted — that mode is for development only.
Authorization codes live in process memory: one process (or sticky
routing) for the authorize→token window.

> **Tips & gotchas**
> - PKCE is mandatory: `code_challenge` must be the 43-char base64url
>   S256 of the verifier, `code_challenge_method=S256`. A missing PKCE
>   pair errors *at authorize*, so you find out early, not at token time.
> - Codes are burned on FIRST presentation, valid or not — a wrong
>   `code_verifier` kills the code; the client must restart the flow.
>   That's deliberate: retry-after-failure is the interception attack.
> - Failures before `redirect_uri` is validated return `status: 400` and
>   never redirect (no open-redirect oracle); later failures come back as
>   `redirectTo` with standard `error=` params.
> - `oidc.token()` returns `{ status, body }` — remember to send the
>   status, not just the JSON.
> - `id_token.sub` is CAIP-10 (`eip155:1:0x…`), not a bare address. Have
>   downstream code expect that or map it in the `ceremony` result via
>   `sub`.

### Native wallet sessions

`createWalletSession` deletes the whole dance: no redirects, no codes, no
IdP. Verify a sign-in (either flavour), get a session JWT, verify that
JWT anywhere that holds your JWKS.

```js
import { createWalletSession } from '@open-wallet-messaging/auth';

const session = createWalletSession({
  rp: 'example.org',
  signingKey: loadPem('session-es256.pem'),  // omit for a throwaway dev key
  ttlS: 3600,
});

// Path A — OWM-AUTH ceremony (action MUST be "sign in"):
const a = await session.verifySignIn({
  authResponse: walletReply,
  expected: { challenge, match, exp, enrolledAddress },  // from YOUR state
});

// Path B — a SIWE message + signature:
const b = await session.verifySignIn({ message: siweText, signature });

if (a.ok) setSessionCookie(a.token);   // { iss: 'example.org', sub: 'eip155:1:0x…', iat, exp }

// Any service verifying:
const check = session.verifySession(cookie);          // this instance
const alt = verifyJwtES256(cookie, session.jwks());   // or any JWT library + the JWKS
```

> **Tips & gotchas**
> - Omitting `signingKey` generates a fresh key pair **per call** —
>   perfect for tests, fatal in production (every restart invalidates all
>   sessions). Pass a persisted P-256 PEM.
> - `verifySignIn` forces `action: 'sign in'` for the OWM-AUTH path. A
>   step-up response ("release the wire") can never mint a login session
>   — you'll get `reason: 'wrong-action'`. This is a feature.
> - The SIWE path defaults `domain` to your `rp`; pass `nonce` too and
>   check it against your session store.
> - `verifySession` also checks `iss` — a token minted by another RP's
>   session fails here even with a valid signature.

---

## Delegated grants (OAuth without OAuth)

OAuth's core job — "app X may access my resource at service Y within
scope S until time T" — as a **wallet-signed capability** instead of a
bearer token from a central authorization server. No token endpoint, no
client secret, no introspection round-trip: `GrantServer.verifyGrant` is
pure offline signature verification, and the grant is sender-constrained
by construction (the signing key *is* the constraint — what OAuth
retrofits as DPoP).

```js
import { GrantServer, MemoryGrantRegistry, OwmAuthenticator } from '@open-wallet-messaging/auth';

const grants = new GrantServer({
  rp: 'example.org',
  aud: 'api.example.org',           // this resource server's identity
  registry: new MemoryGrantRegistry(),  // required for revocation + long-lived grants
});

// 1. Ask: build a request the wallet renders VERBATIM (WYSIWYS consent)
const request = grants.buildGrantRequest({
  client: 'shiny-app',
  scope: 'read:balance pay:invoice',
  ttlS: 900,                        // 15 min — the short-exp default
});

// 2. The user approves on their wallet → signed wm-grant comes back
const grant = wallet.approveGrantRequest(request);      // OwmAuthenticator

// 3. Accept at issuance (single-use nonce — only answers to OUR requests)
const issued = await grants.acceptGrant(grant);         // { ok, grantId, scope, … }

// 4. Verify at every presentation — offline
const check = await grants.verifyGrant(grant);          // { ok: true, … }

// 5. Revoke: only the key that signed the grant may revoke it
const revoke = wallet.revokeGrant(issued.grantId);
await grants.revoke(revoke);
await grants.verifyGrant(grant);                        // { ok: false, reason: 'revoked' }
```

**The trade-off, kept honestly.** Offline verification is bounded by
`exp` — a verifier that never phones home can't learn about a revocation.
OAuth answered this with short-lived tokens plus refresh; OWM-GRANT
answers the same way: grants default to 15 minutes, and any grant whose
*lifetime* (`exp − iat`) exceeds `longExpThresholdS` (default 1 h)
**fails verification unless a registry is configured** — fail closed, not
open. With a registry, revocation costs one lookup and wins over
everything, including unexpired grants.

> **Tips & gotchas**
> - `acceptGrant` only accepts grants answering a request THIS instance
>   built (single-use nonce). The pending-nonce set is in process memory
>   — route the wallet's reply back to the instance that asked, or track
>   requests yourself and call `verifyGrant` directly.
> - The nonce burns **only on success** — a garbled reply doesn't kill an
>   outstanding request.
> - `verifyGrant` auto-registers a valid grant in the registry on first
>   sight, so revocation works even for grants that skipped `acceptGrant`.
> - `revoke()` without a registry returns `{ ok: false, reason:
>   'no-registry' }` — revocation state has to live somewhere.
> - `grantId` is deterministic: SHA-256 of the canonical grant string.
>   Anyone holding the grant fields can compute it (`computeGrantId` in
>   `@open-wallet-messaging/core`) — handy for audit logs.
> - `scope` is OAuth-style (space-separated printable tokens, ≤ 512
>   chars) and is rendered to the user verbatim. Make scopes readable:
>   `wire:release:USD-25000:acct-991` beats `op7`.
> - `iat`/`exp` on the wire are unix **seconds** (same WM-7 convention as
>   the 530s kinds).

---

## Smart-contract wallets (Safe, ERC-4337)

Every verifier above defaults to EOA secp256k1 recovery, which silently
excludes users whose "wallet" is a contract — a Safe, an Argent account,
any ERC-4337 smart account. Those wallets can't produce a recoverable
signature *from their own address*; the standard answer is
[ERC-1271](https://eips.ethereum.org/EIPS/eip-1271): ask the contract
itself, `isValidSignature(hash, sig) == 0x1626ba7e`, via a **read-only**
RPC call. That's what `createChainVerifier` adds — as an explicit opt-in:

```js
import { createChainVerifier, OwmAuthServer, GrantServer, createWalletSession } from '@open-wallet-messaging/auth';

const verifier = createChainVerifier({ rpcUrl: 'https://your-own-node.example' });
const server = new OwmAuthServer({ rp: 'example.org', verifier });   // 2FA / step-up
const grants = new GrantServer({ rp: 'example.org', aud: 'api.example.org', verifier });
const session = createWalletSession({ rp: 'example.org', verifier }); // both sign-in paths
await msg.verify({ signature, domain, nonce }, { verifier });         // SIWE, per call
```

How it verifies, in order — **EOA first, fail closed always**:

1. **EOA recovery** exactly as before. If it matches, done — the RPC is
   *never touched*, and with no `verifier` configured behaviour is
   bit-for-bit the EOA-only default.
2. **[ERC-6492](https://eips.ethereum.org/EIPS/eip-6492) unwrap** when the
   signature carries the 32-byte `0x6492…6492` suffix (signatures from
   not-yet-deployed accounts).
3. **ERC-1271** when the address has contract code: one `eth_call` of
   `isValidSignature` with hash = the EIP-191 digest of the exact
   canonical string / SIWE text. Only the exact magic value `0x1626ba7e`
   passes; wrong magic (`bad-magic`), no code (`no-code`), RPC errors and
   timeouts (`rpc-error`) all fail closed.

**The RPC trust shift, stated plainly.** ERC-1271 verification trusts the
RPC endpoint: a malicious endpoint can fabricate contract code and a magic
return, i.e. forge acceptance. Point `rpcUrl` at **your own node** — or
inject `rpcCall` (`async (method, params) => result`) to fan out to a
quorum of independent endpoints — for anything high-value. EOA-only
deployments keep zero RPC trust; that's why this is opt-in rather than a
default.

**Counterfactual honesty.** A 6492-wrapped signature from an account with
*no code deployed yet* fails closed with `counterfactual-unsupported`.
The EIP's deploy-and-simulate universal-validator pattern requires
embedding contract bytecode the EIP text doesn't publish (source only),
so this reference doesn't ship it. Deploy the account (first UserOp,
Safe setup tx), then its signatures verify normally — wrapped or not.

> **Tips & gotchas**
> - The 530s **envelopes cap `sig` at 65 bytes** (130 hex), so 6492
>   wrappers and fat multisig blobs don't fit OWM-AUTH/GRANT envelopes —
>   there they work when the account validates a 65-byte owner/session-key
>   signature (the common Safe/4337 shape). The SIWE seam takes
>   arbitrary-length signatures, wrappers included.
> - The verifier issues only `eth_getCode` and `eth_call`. It never sends
>   a transaction, never holds a key.
> - `verifySignature({ address, payload, signature })` is exported for
>   direct use and returns `{ ok, method: 'eoa'|'erc1271'|'erc6492',
>   reason? }` — the seam results themselves are unchanged.
> - Contract state can change: a Safe that rotates owners invalidates old
>   presentable signatures at the *next* verification, which is exactly
>   what you want. Verification results are per-call; don't cache them.
> - Failure reasons are designed to be log-safe on their own — don't log
>   them together with addresses or signatures at error level.

---

## The wallet side (`OwmAuthenticator`)

The reference implementation of the *user's* half: it answers challenges,
approves grants, and revokes them. Tests and the demos drive it directly;
a real wallet app wraps the same calls in device unlock and WYSIWYS
rendering.

Two modes:

```js
// single-key: one address everywhere (simple, but linkable)
const w1 = new OwmAuthenticator({ privateKey: '0x…64 hex…' });

// per-RP sub-keys: one address PER relying party (like passkeys)
const w2 = new OwmAuthenticator({ seed: 'a1b2…at least 16 bytes…' });
w2.addressFor('example.org');   // 0xaaa…
w2.addressFor('other.site');    // 0xbbb… — unlinkable to the first
```

Why per-RP matters: **one address used across sites is a tracking cookie
the user cannot clear.** Every RP you log into with the same address can
correlate you with every other one — plus your on-chain history. Seed
mode derives an independent sub-key per RP, so each site sees its own
address and the primary address never appears anywhere. This is exactly
the passkey model (one keypair per site), applied to wallets.

> **Tips & gotchas**
> - The seed-mode derivation (`keccak256(seed ‖ rp)`) is a documented
>   **placeholder** for BIP-32 hardened derivation — fine for the
>   protocol work, scheduled for replacement before v0 freeze (WM-7 §5).
> - `handleAuthChallenge` refuses to sign malformed or over-TTL
>   challenges and returns an `scx-abort` for expired ones — a wallet
>   must never blind-sign.
> - `revokeGrant` in seed mode needs to know which RP's sub-key signed
>   the grant. Grants approved by the same instance are remembered;
>   otherwise pass `{ rp }`.
> - Enroll a **dedicated auth sub-key, never a treasury key**: auth-key
>   theft must not be money theft.

---

## Enrollment: pinning the address

Enrollment is the one moment of trust — everything after is math. Two
supported paths, one forbidden one:

**1. In-session proof-of-possession** (shown in the quickstart): a
challenge/response round-trip inside an *already-authenticated* session;
whatever address validly signs gets pinned. Never offer this on an
unauthenticated path.

**2. An SCX ceremony (WM-3)** — for when there is no existing session, or
the trust anchor is a human relationship (support desk, onboarding call).
The parties run the pairing-code ceremony from `@open-wallet-messaging/core` (SPAKE2 +
transcript-bound contact cards + SAS — see
[`spec/WM-3-scx.md`](https://github.com/open-wallet-messaging-foundation/spec/blob/main/WM-3-scx.md) and the `@open-wallet-messaging/core` README),
and the resulting card is pinned:

```js
// after a confirmed SCX session:
await server.acceptScxCard({
  userId: 'u1',
  card: scxSession.peerCard,
  transcriptHash: scxSession.transcriptHash,  // YOUR side's transcript
});
```

The card's signature covers that ceremony's transcript, so a card
captured from any *other* exchange fails here — cut-and-paste is dead.

**3. A pasted address: never.** An address typed into a form proves
nothing about key control and everything about who's socially engineering
whom.

> **Tips & gotchas**
> - Key-loss recovery = re-enrollment from an authenticated session.
>   Never seed export, never an unauthenticated "update wallet" endpoint.
> - Enrollment-phase failures count toward lockout too (tracked in
>   memory until an enrollment record exists).
> - `verifyEnrollmentProof` pins nothing on failure — a wrong match code
>   leaves the user unenrolled, not half-enrolled.

---

## Plugging in real stores

The in-memory stores are for tests and demos. Production hands in three
small interfaces — all methods async, records are plain JSON-serialisable
objects the stores never interpret, so any KV or SQL fits:

| Interface | Methods | What each must guarantee |
|---|---|---|
| `ChallengeStore` | `get(id)` → record\|null · `put(id, record)` · `delete(id)` | **Burn-on-verify must be effective under concurrency**: once one verification attempt deletes a challenge, a concurrent attempt must not still read it. On a single node the async seam is enough; multi-node, make read-then-delete atomic (e.g. Redis `GETDEL`, or `DELETE … RETURNING`). Challenges are tiny and live ≤ 120 s — a TTL'd KV is ideal. |
| `EnrollmentStore` | `get(userId)` · `put(userId, record)` · `delete(userId)` | Durable — it holds the pinned address AND the failure/lock ledger. Losing it un-enrolls everyone; restoring a stale copy can silently unlock a locked account. |
| `GrantRegistry` | `get(grantId)` · `put(grantId, record)` · `revoke(grantId)` · `isRevoked(grantId)` | `isRevoked` must return true forever once revoked — even after the grant record itself expires out. Store revocations separately from grants (the in-memory reference uses a Set for exactly this reason). |

```js
const server = new OwmAuthServer({
  rp: 'example.org',
  challengeStore: new RedisChallengeStore(redis),   // yours
  enrollmentStore: new SqlEnrollmentStore(db),      // yours
});
```

---

## Transport: bring your own wire

This library never touches a network. The seam is envelopes-in /
envelopes-out:

```
your server                                     the wallet
createChallenge() ──► envelope ──[ your transport ]──► handleAuthChallenge()
verifyResponse() ◄── envelope ◄──[ your transport ]──◄ (signed response / decline)
```

Anything that delivers JSON both ways works: a WebSocket, a queue, a QR
code, two functions in one test process. The **reference transport is
XMTP** — challenges ride end-to-end encrypted wallet-to-wallet messages,
with content-free knock notifications (WM-6) so even the push provider
never learns an auth prompt was sent. The envelopes themselves are strict
OWM envelopes (`@open-wallet-messaging/core` `parseMessage` — unknown or malformed input
never crashes a handler, it comes back as a typed refusal).

---

## Security properties (and the honest ceiling)

What you get:

- **No shared secret server-side.** The server pins a public address. A
  database breach leaks nothing that passes 2FA — compare a TOTP seed
  table, where a breach breaks every enrolled user at once.
- **Nothing to read out to a phisher.** The classic "read me the 6-digit
  code" call is dead: the match code is useless without the wallet's
  signature, and the signature binds rp + action + nonce + expiry.
- **MFA bombing dead by construction.** Approval requires typing a code
  only the genuine initiating screen displayed (number-ENTRY, not
  number-matching). Declines count toward lockout, with a security alert.
- **Replay and brute force**: single-use 32-byte nonces, ≤ 120 s
  lifetime, burned on ANY verification attempt, success or failure.
- **Domain separation.** Auth signatures (`owm-auth-v1`), grants
  (`owm-grant-v1`), revokes (`owm-grant-revoke-v1`) and SCX cards carry
  mutually disjoint domain tags on top of the EIP-191 prefix — an auth
  signature can never be replayed as a transaction, a grant, or a card.
  The test suites prove the cross-verifications fail.
- **Per-RP sub-identities** (seed mode): no cross-site tracking handle.

The ceiling, honestly:

- **Live-relay phishing parity.** A real-time evilginx-class proxy that
  drives the genuine site *and relays the match code* is not
  cryptographically excluded in default mode. That's the same ceiling as
  every non-WebAuthn method, including push-2FA with number matching —
  OWM-AUTH matches the best of that class and strictly dominates TOTP
  and SMS OTP, but it is **not WebAuthn** until strict-mode binding
  ships. The `binding` field (a session hash signed into the response)
  is the hook; the envelope and canonical-string support exist today,
  the proximity/origin-verified ceremony is future work (WM-7 §6).
- **Offline grant verification is bounded by `exp`** — hence the
  fail-closed registry rule for long-lived grants.
- The per-RP derivation is a placeholder (see above); the OIDC bridge is
  a v0-dev profile; the reference stores are in-memory.

---

## API reference

### `server.js` — `OwmAuthServer`

| Member | Args | Returns | Throws |
|---|---|---|---|
| `new OwmAuthServer(opts)` | `{ rp, challengeStore?, enrollmentStore?, maxFailures?=5, ttlS?=120, matchDigits?=2, onSecurityAlert?, clock? }` | instance | missing `rp`; `maxFailures < 1`; `matchDigits` outside 2..8 |
| `createEnrollmentChallenge` | `{ userId, action? }` | `Promise<{ envelope, matchCode, challengeId }>` | missing userId; user locked |
| `verifyEnrollmentProof` | `(envelope, { matchCode? })` | `Promise<{ ok, userId, address } \| { ok: false, reason }>` | — |
| `acceptScxCard` | `{ userId, card, transcriptHash }` | `Promise<{ ok, userId, address } \| { ok: false, reason }>` | missing userId |
| `createChallenge` | `{ userId, action, binding? }` | `Promise<{ envelope, matchCode, challengeId }>` | missing args; not enrolled; locked; ttlS out of range |
| `verifyResponse` | `(envelope, { matchCode?, challengeId? })` | `Promise<{ ok, userId, address, action } \| { ok: false, reason, locked? }>` | — |
| `isLocked` / `unlockUser` | `(userId)` | `Promise<boolean>` / `Promise<void>` | — |
| `getEnrollment` | `(userId)` | `Promise<record \| null>` | — |

Failure reasons: `bad-envelope`, `unknown-challenge`, `declined`,
`locked`, `not-enrolled`, `challenge-mismatch`, `expired`,
`match-mismatch`, `bad-signature`, `wrong-address`.

### `two-factor.js` — `TwoFactor`

| Member | Args | Returns | Throws / rejects |
|---|---|---|---|
| `new TwoFactor(opts)` | `{ server, defaultAction?='log in' }` | instance | missing server |
| `request` | `(userId, action?, { binding? })` | `Promise<{ challengeId, matchCode, envelope }>` | not enrolled; locked |
| `submit` | `(envelope, { challengeId? })` | `Promise<verification result>` | — |
| `awaitApproval` | `(challengeId, { timeoutMs?=120000 })` | `Promise<{ ok, userId, address }>` | rejects with `Error{ reason, locked? }` on timeout / decline / failure / unknown id |

### `grants.js` — `GrantServer`

| Member | Args | Returns | Throws |
|---|---|---|---|
| `new GrantServer(opts)` | `{ rp, aud, registry?, defaultTtlS?=900, longExpThresholdS?=3600, clock? }` | instance | missing rp/aud |
| `buildGrantRequest` | `{ client, scope, aud?, ttlS? }` | `wm-grant-request` envelope | invalid field (e.g. newline in scope) |
| `acceptGrant` | `(grant, { expectedAddress? })` | `Promise<{ ok, grantId, address, client, scope, exp } \| { ok: false, reason }>` | — |
| `verifyGrant` | `(grant, { expectedAddress?, now? })` | same shape as above | — |
| `revoke` | `(revokeEnvelope)` | `Promise<{ ok, grantId } \| { ok: false, reason }>` | — |

Failure reasons: `unknown-nonce`, `bad-signature`, `wrong-address`,
`expired`, `aud-mismatch`, `rp-mismatch`, `long-exp-requires-registry`,
`revoked`, `no-registry`, `unknown-grant`.

### `authenticator.js` — `OwmAuthenticator`

| Member | Args | Returns | Throws |
|---|---|---|---|
| `new OwmAuthenticator(opts)` | exactly one of `{ privateKey }` / `{ seed }` | instance | both/neither given |
| `keyFor` / `addressFor` | `(rp)` | hex key / `0x…` address | bad seed/rp |
| `handleAuthChallenge` | `(envelope, { matchCode, approve?=true, binding?, now? })` | `wm-auth-response` or `scx-abort` | malformed challenge; missing matchCode |
| `approveGrantRequest` | `(envelope, { approve?=true })` | `wm-grant` or `scx-abort` | malformed request |
| `revokeGrant` | `(grantId, { rp?, now? })` | `wm-grant-revoke` | unknown rp in seed mode |

### `siwe.js`

| Export | Args | Returns | Throws / rejects |
|---|---|---|---|
| `new OwmSiweMessage(param)` | fields object or EIP-4361 string | instance | parse/validation failure |
| `.prepareMessage()` / `.toMessage()` | — | EIP-4361 string | invalid fields |
| `.verify(params, opts?)` | `{ signature, domain?, nonce?, time? }`, `{ suppressExceptions? }` | `Promise<{ success, data, error? }>` | rejects `{ success: false, error, data }` unless suppressed |
| `generateNonce()` | — | 17-char alphanumeric string | — |
| `SiweError`, `SiweErrorType` | — | error class / frozen string map | — |

### `oidc.js`

| Export | Args | Returns |
|---|---|---|
| `createOidcIssuer(opts)` | `{ issuer, ceremony, signingKey?, codeTtlS?=120, idTokenTtlS?=3600, accessTokenTtlS?=3600, clients?, clock? }` | `{ issuer, discovery(), jwks(), authorize(params), token(params) }` |
| `createWalletSession(opts)` | `{ rp, signingKey?, ttlS?=3600, chainId?=1, clock?, verifier? }` | `{ rp, issueSession(address, extraClaims?), verifySignIn(input), verifySession(token), jwks() }` |

### `erc1271.js` — smart-contract-wallet verification (opt-in)

| Export | Args | Returns |
|---|---|---|
| `createChainVerifier(opts)` | `{ rpcUrl? \| rpcCall?, timeoutMs?=5000 }` (one transport required) | `{ verifySignature({ address, payload, signature }) }` → `Promise<{ ok, method: 'eoa'\|'erc1271'\|'erc6492', reason? }>` |
| `encodeIsValidSignatureCall(hash, sigHex)` | 32-byte hash + signature hex | exact `isValidSignature(bytes32,bytes)` calldata |
| `decodeErc6492(sigHex)` | bare hex incl. suffix | `{ factory, factoryCalldata, originalSig } \| null` |
| `ERC1271_MAGIC` / `ERC6492_MAGIC_SUFFIX` | — | `'0x1626ba7e'` / the 32-byte `6492…` suffix hex |

Failure reasons: `bad-signature`, `no-code`, `counterfactual-unsupported`,
`bad-magic`, `rpc-error` — all fail closed. The `verifier` option is
accepted by `OwmAuthServer`, `GrantServer`, `createWalletSession`, and
`OwmSiweMessage.verify` opts.

### `jwt.js`

| Export | Args | Returns |
|---|---|---|
| `generateEs256KeyPair()` | — | `{ privateKey, publicKey }` KeyObjects |
| `importSigningKey(key?)` | KeyObject / PEM / undefined | `{ privateKey, publicKey }` (throws on non-P-256) |
| `publicJwk(publicKey)` | KeyObject | JWK with `alg`, `use`, `kid` |
| `jwkThumbprint(jwk)` | EC JWK | RFC 7638 base64url thumbprint |
| `signJwtES256(claims, privateKey, { kid? })` | claims use unix **seconds** | compact JWT |
| `verifyJwtES256(token, keyOrJwks, { now? })` | `now` unix **ms** | `{ ok, header, claims } \| { ok: false, reason }` |

### `stores.js`

`MemoryChallengeStore`, `MemoryEnrollmentStore`, `MemoryGrantRegistry` —
reference in-memory implementations of the three interfaces above.

---

## Troubleshooting / FAQ

**Why did `verifyResponse` burn my nonce on a failed match?**
Because retry-after-failure IS the attack. If a failed attempt left the
challenge alive, an attacker holding a stolen response could iterate
match codes. One challenge, one attempt, any outcome. Issue a new
challenge; it costs nothing.

**My challenge is instantly `expired` / gets rejected at build time.**
Almost always the seconds/milliseconds mix-up: WM-7 envelope times
(`iat`, `exp`, `ts`) are unix **seconds**; every `clock`/`now` option in
this library is unix **milliseconds** (converted internally). Don't
hand-build envelope timestamps in ms.

**The wallet throws "challenge TTL exceeds 120s — refusing to sign".**
Your `ttlS` is over the WM-7 ceiling. Wallets refuse over-TTL challenges
so a phisher can't stockpile long-lived ones. Keep `ttlS` ≤ 120.

**A decline comes back as `unknown-challenge`.**
Declines are `scx-abort` envelopes and carry no challenge id. Pass
`{ challengeId }` from your transport context to `submit`/`verifyResponse`.

**`awaitApproval` rejects with `unknown-challenge` immediately.**
The ceremony already settled (a reply arrived before you awaited, or it
timed out earlier) — or the id is from another process. `request()` and
`awaitApproval()` must run in the same process; the pending map is not a
store.

**Long-lived grant fails with `long-exp-requires-registry`.**
By design: a grant living beyond `longExpThresholdS` (default 1 h) can't
be revoked without a registry lookup, so verification fails closed.
Configure a `registry`, or issue short grants.

**Can users be enrolled on multiple devices?**
Not per userId today — one enrollment record per user. Multi-device
means either re-enrollment (new device replaces old) or an
enrollment-store schema of your own on top.

**Does the server need XMTP?**
No. The library is transport-agnostic; XMTP is the reference transport.
Every test and demo in this repo runs with zero network.

**Where do the wire formats live?**
[`spec/WM-7-auth.md`](https://github.com/open-wallet-messaging-foundation/spec/blob/main/WM-7-auth.md) is normative for kinds
530–534, the canonical signing strings, and the security analysis;
[`spec/WM-3-scx.md`](https://github.com/open-wallet-messaging-foundation/spec/blob/main/WM-3-scx.md) covers the SCX enrollment
ceremony; kind numbers are registered in `api/kinds.json`.

---

## Import surface

```js
import {
  OwmAuthServer, DEFAULT_MAX_FAILURES, TwoFactor,   // 2FA / step-up
  GrantServer,                                      // delegated authorization
  OwmAuthenticator,                                 // reference wallet side
  OwmSiweMessage, SiweError, SiweErrorType, generateNonce,  // EIP-4361
  createOidcIssuer, createWalletSession,            // sign-in profiles
  createChainVerifier,                              // ERC-1271/6492 opt-in
  MemoryChallengeStore, MemoryEnrollmentStore, MemoryGrantRegistry,
  signJwtES256, verifyJwtES256, publicJwk, jwkThumbprint,
  generateEs256KeyPair, importSigningKey,
} from '@open-wallet-messaging/auth';
```

Dependencies: `@open-wallet-messaging/core` + Node built-ins. Nothing else. Node ≥ 20, MIT.
