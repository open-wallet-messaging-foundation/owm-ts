# wallet-chat — two wallets meet over an SMS code, then chat

The friendliest way into OWM: a chat between two wallets, initiated with
nothing more than a text message. It's built as a ladder — start at the
bottom, climb one rung at a time:

| Rung | File | What it shows |
|---|---|---|
| 1 | `chat.mjs` | plain wallet-to-wallet chat — no ceremony, no relay |
| 2 | `host.mjs` | side A: pairing code → SMS → verify → chat |
| 2 | `join.mjs` | side B: enter the code → verify → chat |
| 1+2 | `demo.mjs` | the whole thing, scripted and self-checking — **run this first** |

Everything runs against the real XMTP `dev` network with real MLS
encryption; identities are throwaway unless you pin one (see
[tips](#tips)).

## 30-second start

```sh
npm install                     # repo root, once (workspace deps)
cd examples/wallet-chat
npm install                     # this example's own deps (@xmtp/node-sdk, viem)
node demo.mjs                   # both sides in one process, self-asserting
```

You'll see the local rendezvous relay start, a pairing code like
`42-panda-mocha-quilt`, a mock SMS line, an SAS like `🐢 🍇 0417` matching
on both "screens", two verified contact cards, and three chat messages each
way on the live network — ending in `RESULT: 12 passed, 0 failed`.

Needs: Node ≥ 20, network access, and Rust (`cargo`) for the local relay —
or skip Rust entirely by pointing `OWM_RENDEZVOUS_URL` at a running relay.

## rung 1 — just chat (two terminals)

```sh
# terminal A                            # terminal B
node chat.mjs                           node chat.mjs 0x<address from A>
# → prints its address, waits           # → opens the DM, type away
```

Both directions strict-parse every message through `@open-wallet-messaging/core`: plain text
renders as chat, OWM envelopes render by kind name, unknown kinds fall back
to readable text — nothing is ever silently dropped. That's the whole
philosophy, and it's five lines in `chat.mjs` (`render()`).

## rung 2 — the SMS ceremony (two terminals)

**Terminal A** (the initiator):

```
$ node host.mjs +15551234567
──────────────────────────────────────────────
  your wallet
  address : 0xA11c…
  inboxId : 83f0…
──────────────────────────────────────────────
relay: up at http://127.0.0.1:54321 (spawned locally)

  export OWM_RENDEZVOUS_URL=http://127.0.0.1:54321     ← paste into terminal B

════════════════════════════════════
  PAIRING CODE:   18-panda-mocha-quilt
════════════════════════════════════
📱 SMS (mock — set TWILIO_* env vars to really send) → +15551234567: Reply-less secure contact setup: open your wallet and enter code 18-panda-mocha-quilt

waiting for the other side to enter the code…

  SAS — both screens must show EXACTLY this:

      🐢 🍇 0417

does the other screen show the same? [y/n] y
✔ contact verified
  address : 0xB0b5…
  inboxId : 91ab…

chat is live — type a line and press enter; Ctrl-C to leave.
you ›
```

**Terminal B** (the recipient — they got the code by SMS):

```
$ export OWM_RENDEZVOUS_URL=http://127.0.0.1:54321
$ node join.mjs 18-panda-mocha-quilt
code accepted — running the key exchange…

  SAS — both screens must show EXACTLY this:

      🐢 🍇 0417

does the other screen show the same? [y/n] y
✔ contact verified
waiting for the host to open the chat…
Host › 👋 secured via OWM
you ›
```

If the two SAS displays ever differ: answer `n`. The exchange aborts —
that's the system working, not failing.

> **Two machines?** The locally-spawned relay binds `127.0.0.1`, so it only
> works for two terminals on one machine. Across machines, run the relay
> somewhere both can reach (`cargo run -p owm-rendezvous` in `rust/`, with
> `OWM_RENDEZVOUS_ADDR=0.0.0.0:8080` or behind a reverse proxy) and set
> `OWM_RENDEZVOUS_URL` on both sides.

## really sending the SMS (Twilio)

The easy way: there's a `.env` file right here in this folder (gitignored,
so your credentials never end up in a commit). Open it, paste your three
values, done — every script loads it automatically:

```sh
# examples/wallet-chat/.env
TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_FROM=+15005550006                 # an SMS-capable number you own
```

(Plain `export` in your shell works too and takes precedence over `.env`.
Fresh clone without a `.env`? Copy `.env.example`.)

```sh
node host.mjs +15551234567               # now the code really goes out
```

- **Trial accounts** can only text numbers you've verified in the Twilio
  console (Phone Numbers → Verified Caller IDs) — verify the recipient
  first or the API returns an error.
- **Cost:** one ordinary SMS per pairing. That's the entire bill.
- The auth token is used for the API call and never printed or logged.
- No Twilio npm package — it's one form-encoded `fetch` in `wallet.mjs`.

## how the security actually works

The SMS carries only a pairing code — never an address, never a key.
Both wallets feed that code into SPAKE2 (a password-authenticated key
exchange), which turns the weak code into a full-strength encryption key —
and grants anyone who intercepted the SMS **exactly one** online guess at
it. A wrong guess doesn't degrade anything: it breaks the handshake loudly
(`scx-abort`) while both humans are watching. Each side then sends a
contact card signed over *this exchange's* transcript, so a genuine card
captured from any other exchange fails verification here. Finally both
screens show the same short SAS (two emoji + four digits) — you compare out
loud, and a machine-in-the-middle cannot make the two screens match.
Only after all of that does the wallet open the XMTP DM to the inboxId
from the verified card — the SMS never carried anything worth stealing.
Full ceremony: [`spec/WM-3-scx.md`](../../spec/WM-3-scx.md).

## tips

- **Keep your address stable:** every script accepts `--key 0x<hex>` (or
  `OWM_WALLET_KEY`). Without it a fresh key is generated — and printed, so
  you can pin it next run.
- **`OWM_RENDEZVOUS_URL`** — point host and join at any reachable
  `owm-rendezvous`; nothing is spawned when it's set (and Rust isn't
  needed at all).
- **`XMTP_ENV`** — `dev` by default; set `production` or `local` to move
  networks (both sides must match).
- The pairing code and the SAS are the only things a human ever
  transcribes; both were designed for saying out loud (EFF short wordlist,
  emoji + digits).

## troubleshooting

- **"no cargo on PATH"** — install Rust (<https://rustup.rs>), or run a
  relay elsewhere and set `OWM_RENDEZVOUS_URL`.
- **"run npm install in this folder first"** — exactly that; this example
  has its own `node_modules` (the XMTP SDK ships native bindings).
- **"this code was already used"** — pairing codes are strictly one-shot;
  a second claim is refused by design. Ask the host for a fresh code.
- **join.mjs can't reach the relay** — the host's spawned relay is
  local-only; check you exported `OWM_RENDEZVOUS_URL` in *this* terminal,
  and that the host is still running (mailboxes expire after ~15 minutes).
- **Firewalled networks** — the XMTP dev network needs outbound HTTPS/gRPC;
  the relay is plain HTTP on its printed port. If `demo.mjs` stalls at the
  DM step, it's almost always egress filtering.
- **SAS mismatch** — abort (answer `n`), get a fresh code, start over.
  There is deliberately no "proceed anyway".
