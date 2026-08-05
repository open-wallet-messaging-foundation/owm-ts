# Security policy

## Reporting a vulnerability

**Email security@owm.foundation.** Please do not open a public issue for a
security problem — in a protocol repository, the issue tracker is the worst
possible disclosure channel.

Tell us what you found, how to reproduce it, and what you think the impact
is. If you have a proof of concept, include it. If you are not sure whether
something is a bug or a misreading of the spec, report it anyway — an
ambiguity that leads implementers into an insecure choice **is** a spec
defect, and those are the reports we most want.

## What to expect

- Acknowledgement within **3 working days**.
- An assessment (accepted / not-a-vulnerability / needs-more-info) within
  **10 working days**, with our reasoning.
- Credit in the fix notes if you want it, and silence if you prefer.
- Coordinated disclosure: we will agree a date with you. We will not sit on
  a confirmed vulnerability indefinitely to protect anyone's schedule,
  including our own.

**Honest limits, stated up front:** the OWM Foundation is small and
currently unfunded for this work. There is **no bug bounty** — we cannot
pay you, and we will not pretend otherwise. An external security audit and
a funded bounty programme are on the roadmap and are exactly what the
foundation is raising money for. Until then, what we can offer is a fast,
respectful response, public credit, and the fix landing in the standard
that everyone else then inherits.

## Scope

In scope: this repository — cryptographic
constructions, the pairing and contact-exchange ceremonies, envelope
validation, invite-token handling, authorization and approval flows,
and any place the specification's ceilings are wrong or overstated.

For implementation bugs, report against the relevant repository
(`owm-ts`, `owm-relay`, `owm-notifier`, `owm-react-native`) — or here if
you are not sure which; we will route it.

Out of scope: the owm.foundation marketing site's cosmetic issues, and
anything requiring physical access to a user's unlocked device (that is a
stated ceiling, not a vulnerability).

## Our disclosure posture

Confirmed protocol vulnerabilities get a public advisory in this
repository once a fix or mitigation exists, including the cases where the
honest answer is "this is a limitation we cannot remove — here is what
implementers must do instead."
