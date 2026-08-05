# auth-demo

Runnable, self-contained walkthroughs of `@open-wallet-messaging/auth` (spec:
`spec/WM-7-auth.md`). Everything runs in one process with zero network
and zero setup — server and "wallet" side by side so you can watch every
envelope. Each file is standalone:

```sh
node two-factor.mjs    # 2FA / step-up: enroll → approve → wrong code → lockout
node sign-in.mjs       # SIWE round-trip + native wallet sessions (no OIDC)
node oidc-bridge.mjs   # full OIDC code+PKCE flow against the bridge issuer
node grants.mjs        # delegated grants: request → approve → verify → revoke
```

Needs Node ≥ 20. Imports come straight from the workspace
(`packages/owm-auth`, `packages/owm-core`) — no install step beyond the
repo's own `npm install`.

## two-factor.mjs

The full OWM-AUTH ceremony: enrollment pins the wallet's address, a login
shows the match code on the "site screen" and the user types it into the
wallet, a step-up approval signs the human-readable action verbatim, a
wrong match code burns the challenge (retry-after-failure is the attack),
and three strikes lock the user and fire the security alert.

```
=== Login: challenge → user types the match code → approved ===
[site screen] shows match code: 36
[envelope]    contains NO match code: true
login approved: { userId: 'ada', address: '0x42f6…' }
replaying the same response: unknown-challenge (single-use nonce, burned)
…
third strike: match-mismatch → locked: true
security alert fired once: true {"rp":"demo.example.org","userId":"ada","failures":3,"reason":"lockout"}
```

## sign-in.mjs

Part 1: an EIP-4361 message built with `OwmSiweMessage` (the `siwe`
drop-in), signed, verified, and shown to round-trip byte-for-byte —
plus a siwe-compatible failure. Part 2: `createWalletSession` accepts
either that SIWE message or an OWM-AUTH response and mints a compact
ES256 session JWT, verified via `verifySession` and via the exported
JWKS with a generic verifier; a step-up response can never mint a login.

```
verifySession claims: {"iss":"app.example.org","sub":"eip155:1:0x17c5…","iat":…,"exp":…}
a non-"sign in" action is refused: wrong-action
one hour later: expired — done.
```

## oidc-bridge.mjs

The whole authorization-code + PKCE flow an OIDC client would perform,
in-process: discovery → authorize (the issuer's `ceremony` callback runs
a real OWM-AUTH challenge round-trip) → token → `id_token` verified
against the issuer's JWKS. Then the sharp edges: codes are single-use
and burn on first presentation (a wrong verifier kills the code for the
right one too), and unknown clients never get a redirect.

```
claims: { "iss": "https://auth.example.org", "sub": "eip155:1:0x34a8…", "aud": "demo-app", … }
replaying the code: invalid_grant
wrong verifier: invalid_grant → then the RIGHT verifier: invalid_grant
```

## grants.mjs

OAuth's delegated-access job as a wallet-signed capability: the RP builds
a `wm-grant-request` the wallet renders verbatim, the wallet signs it
with its per-RP sub-key, the resource server verifies **offline**, a
tampered scope breaks the signature, a 30-day grant fails closed without
a registry, and only the granting key can revoke — after which the
still-unexpired grant verifies as `revoked`.

```
30-day grant, no registry: long-exp-requires-registry
rogue key tries to revoke: wrong-address
verifying the (unexpired) grant now: revoked — revocation wins over everything.
```
