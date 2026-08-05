# web-chat — wallet-to-wallet chat in a real browser, today

A minimal web messenger you can open on two phones (the MetaMask app's
in-app browser) or two desktop browsers (MetaMask extension) and chat
wallet-to-wallet over the real XMTP `dev` network — end-to-end encrypted
(MLS), no server of ours in the middle. Plus a one-liner that texts the
link to the phones — and **rooms**: private admin-only MLS groups with
channel-drop invite links, so two phones and a laptop make a 3-way chat
(the Phase 1 reference-messenger slice).

This is the seed of the Phase 1 reference web messenger: one HTML page, one
JS file, no framework — small enough to read in one sitting, real enough to
actually use.

## 3-command quickstart

```sh
npm install                                # in this folder (repo root too, once)
npm run dev -- --host                      # HTTPS dev server on your LAN IP
node send-invites.mjs https://<lan-ip>:5173 +61491570006 +61491570156
```

The dev server prints its Network URL (e.g. `https://192.168.1.20:5173/`) —
that's the `<lan-ip>` to text. Without Twilio credentials, `send-invites.mjs`
prints a clearly-marked mock line instead of sending (credentials go in
`.env` here, or it reuses `../wallet-chat/.env`).

Tip: append `#peer=0x<their-address>` to the URL you send and the chat opens
straight into the right DM. The address rides the URL **fragment**, never a
query string — fragments are not sent to servers and stay out of access logs.

## The phone ritual (MetaMask app)

1. Open the **MetaMask app** → tap the **browser** tab (globe icon).
2. Paste / open the URL from the SMS.
3. Accept the **self-signed certificate warning** (the dev server's HTTPS is
   locally generated — that's expected on a LAN).
4. Tap **Connect wallet** — MetaMask asks for your account.
5. **Sign** the XMTP prompt (one `personal_sign`; this creates or loads your
   XMTP identity — it costs nothing and touches no funds).
6. The banner shows your address + inboxId + `network dev`. Paste the other
   phone's 0x address and **Open chat** — or just wait: when the other side
   messages you first, the chat opens by itself.

Do the same on the second phone, then type. That's it.

## The 3-way room ritual

1. On the host device: connect, name the room, **Start a room**. An
   AdminOnly MLS group is created and an invite link appears — the invite
   token rides the URL **fragment only** (never a query string; refused at
   parse otherwise). The door closes after 2 h or 10 admits.
2. Text the link to the phones (`node send-invites.mjs <url> +61… +61…`
   sends it, mock-printing without Twilio credentials). Each phone opens it
   in the MetaMask app's browser, connects, and taps **Knock to join** —
   the join request rides an encrypted DM to the host.
3. The host's client (tab must stay open) checks the token against the
   `@open-wallet-messaging/core` invite state machine, admits, and replies. Joiners land in
   the room — and, MLS forward secrecy being what it is, they cannot read
   anything sent before their welcome.

In the room, bubbles are labeled with the sender's short inboxId. Everything
else (strict parse, ping chips, render-or-fallback) works exactly as in DMs.

## Desktop (MetaMask extension)

Open the same URL in Chrome/Brave/Firefox with the MetaMask extension →
**Connect wallet** → sign once → chat. No wallet installed? **Use a burner
wallet** generates a throwaway dev-network key locally (shown once with a
copy button; stored in localStorage; never fund it).

## Same Wi-Fi vs anywhere

> **Same Wi-Fi (zero setup):** `npm run dev -- --host` and text the
> `https://<lan-ip>:5173` URL. Both phones must be on the same network as
> your machine. Expect the certificate warning (self-signed).
>
> **Anywhere (public HTTPS tunnel, no cert warning):**
>
> ```sh
> npm run dev                                  # localhost is fine for a tunnel
> cloudflared tunnel --url https://localhost:5173 --no-tls-verify
> # …or with ngrok:
> ngrok http https://localhost:5173
> ```
>
> Text the printed `https://….trycloudflare.com` / `….ngrok.app` URL instead.
> Real certificate, works on any network — including phones on cellular data.

## What the code teaches

Every inbound message is strict-parsed through `@open-wallet-messaging/core`'s `parseMessage`
— `renderBody()` in [`src/main.js`](src/main.js) is the entire
render-or-fallback philosophy in ~10 lines: plain text renders as chat, a
valid OWM envelope renders as a labeled chip (kind + JSON — try the **ping**
button, it sends a real `wm-ping`), unknown kinds and invalid payloads are
surfaced visibly. Nothing is ever silently dropped.

## Verifying it yourself

```sh
node e2e.mjs        # drives two copies in your installed Chrome, burner mode,
                    # exchanges real messages on the XMTP dev network
```

Passing as of 2026-07-14: 10/10 — identity creation in-browser, DM open by
address, two texts each way delivered, `wm-ping` chip and unknown-kind
fallback rendered. (Requires Google Chrome and network access.)

## Troubleshooting

- **"This page needs a secure context"** — the XMTP SDK's storage and
  WebCrypto require HTTPS (or `localhost`). Always use the `https://` URL;
  on a LAN, accept the certificate warning once per device.
- **Blank page / storage errors in the MetaMask in-app browser** — the SDK
  stores its encrypted DB in OPFS inside a Web Worker. Recent iOS/Android
  WebViews support this, but we have **not** tested every device: if OPFS
  fails, the app automatically retries with **in-memory storage** (banner
  shows `storage memory` — messages last only for that session). If the
  WebView can't run the SDK at all, the honest fallback is opening the URL
  in **Safari/Chrome on the phone** with a **burner wallet** — same chat,
  just not your MetaMask identity. You can also force in-memory mode by
  adding `#mem` to the URL.
- **One tab per browser** — the SDK's OPFS database allows a single
  connection; a second tab of this app in the same browser will fall back to
  in-memory storage or fail. Use different browsers/devices for two
  identities (the e2e script uses isolated browser profiles for this).
- **"has no XMTP identity yet"** — the other side hasn't connected yet.
  Open the page on their device first (Connect + sign), then retry.
- **Messages stall** — the dev network needs outbound HTTPS/gRPC; hotel and
  corporate networks that block it are the usual culprit. The status line at
  the bottom reports every step and every error in plain language.
- **`SecretReuseError` in the console** — harmless duplicate-decrypt noise
  when history sync overlaps the live stream; delivery is unaffected.
- **No COOP/COEP headers needed** — verified against the SDK bundle (no
  `SharedArrayBuffer`); plain HTTPS is enough.

## Files

| File | What it is |
|---|---|
| `index.html` + `src/main.js` + `src/style.css` | the whole app — vanilla JS, ~300 lines |
| `vite.config.js` | HTTPS on the LAN (`@vitejs/plugin-basic-ssl`), worker/wasm dev-server config |
| `send-invites.mjs` | zero-dep Twilio SMS (mock without credentials) — numbers from argv only |
| `e2e.mjs` | two-browser live proof over the real dev network |
