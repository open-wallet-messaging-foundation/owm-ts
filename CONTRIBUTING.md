# Contributing to owm-ts

The TypeScript/JavaScript reference implementation of OWM: `@open-wallet-messaging/core`,
`@open-wallet-messaging/auth`, the runnable examples, and the live smoke tests that prove
the whole thing works against a real network.

Ordinary open-source flow — fork, branch, PR — with two gates worth
knowing before you start.

## Gate 1: tests are mandatory

Every module carries **pure-logic tests (zero dependencies, offline)** for
both the happy path and the unhappy one. A PR without tests is not a
smaller PR; it is an unfinished one.

```sh
cd packages/owm-core && npm test     # pure tests, no network
node live/run.sh                     # live smoke on the real XMTP dev network
```

If your change touches anything that goes over the wire, it also needs a
**conformance vector** in [`owm-api`](https://github.com/open-wallet-messaging-foundation/owm-api)
— that is what makes other implementations inherit your fix.

## Gate 2: the invariants

These are the properties the standard exists to provide. A PR that
weakens one gets closed with a link here — not because we are precious,
but because each of these is load-bearing for someone's safety.

- **Strict envelope validation.** Missing, extra, or type-mismatched keys
  are rejected. Unknown *kinds* fall back to readable text and are never
  silently dropped — different rule, equally important.
- **Invite tokens ride the URL fragment only.** A token in a query string
  lands in server logs. Parsing refuses it. Do not "fix" this.
- **The library never handles private keys it was not handed.** No
  key material in logs, errors, or telemetry — ever, including in
  debugging code you meant to remove.
- **Say the ceiling.** If a function's guarantee has limits, the JSDoc
  says so in plain words. Honest documentation of a weakness beats a
  confident sentence that is subtly untrue.

## What is especially welcome

- **Breaking things.** Attack SCX, the auth ceremonies, the quorum
  verifier, the parsers. A confirmed break is the most valuable
  contribution there is — see [SECURITY.md](SECURITY.md) for how to report
  one privately if it has teeth.
- **A second implementation's perspective.** If you are building OWM in
  another language and something here is hard to mirror, that is a design
  bug worth an issue.
- **Making the examples clearer.** They are how most people meet the
  protocol.

## Style

Match the surrounding code. Comments explain *why*, not *what* —
particularly the security-relevant why, which is the one thing the next
reader cannot re-derive from the code.

## Licence

MIT (see [LICENSE](LICENSE)). By opening a PR you confirm you can license
your contribution under it.

## Who signs for a commit

Every commit in an Open Wallet Messaging repository is authored by an
**identified individual** who takes responsibility for it. Not an anonymous
handle, not a shared organisation mailbox, and not an AI.

Practically, that means each commit carries a Developer Certificate of
Origin sign-off with your real name and a working address:

```
Signed-off-by: Your Name <you@example.com>
```

`git commit -s` adds it for you. By adding it you assert the
[Developer Certificate of Origin](https://developercertificate.org) — in
short, that you wrote the contribution or otherwise have the right to
submit it under this repository's licence.

**On tooling and AI assistance:** use whatever helps you write good code —
compilers, linters, language models. Disclose it if you like; several of us
do, in the commit body. What is not negotiable is that a named human has
read the change, understood it, and is accountable for it. An assistant can
draft a commit; it cannot be responsible for one. In a project whose entire
value is that signatures mean something, authorship that means nothing
would be a strange place to start.