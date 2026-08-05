# listening-party — a private concert between friends, today

**OWM-STAGE Tier 1 end-to-end in a browser** — and, under the concert
costume, the Phase 1 **reference-messenger slice**: an admin-only MLS room
created in the browser, a channel-drop door link (token in the `#t=`
fragment only), a join-request DM gated by the `@open-wallet-messaging/core` invite state
machine, and MLS-enforced eviction.

There is **no audio streaming at all**. The DJ's `wm-playback-sync` beacons
(kind 541) say *"track T was at `positionMs` when the wall clock read
`atMs`"* — every phone renders the same deterministic synthesized track
locally (see `src/tracks.js`) and stays inside ~350 ms. The tracks are
synthesized from scores in this repo, so they're licensing-clean by
construction. Chat, cues (kind 542) and reactions ride the same E2EE room.

## 3-command quickstart

```sh
npm install                     # in this folder
npm run dev -- --host           # HTTPS dev server on your LAN IP
node ../web-chat/send-invites.mjs "<door link>" +61491570006
```

Open the printed `https://<lan-ip>:5173` URL on your machine → **Connect
wallet** (or burner) → name the party → **Start the party**. Copy the door
link and text it to your friends (same Wi-Fi; for anywhere, see the tunnel
note in `../web-chat/README.md`). Accept the self-signed-cert warning on
phones — expected on a LAN.

## The demo script — three moments to show off

1. **The latecomer lands mid-song.** Start playing, then have a friend tap
   the same link two minutes in. They knock, the invite state machine
   redeems their ticket, the DJ's client admits them — and because MLS
   forward secrecy means they *cannot* read anything sent before their
   welcome, the DJ re-sends the stage state on admit. They land at the
   right second of the right track.
2. **The cryptographic bouncer.** DJ taps ✕ next to a guest. That's
   `removeMembers` — the MLS epoch rotates, and the next beacon is
   mathematically unreadable to them. Their client notices (`isActive` →
   false) and shows the bounced screen. Nobody "muted" them; the *room*
   closed on them.
3. **The vibe check.** Everyone reads the room fingerprint (top right —
   2 emoji + 4 digits, a SAS over the sorted member list, the same idiom
   as SCX — WM-3 §5). Same on every screen = same room, no impostor.
4. **The tip jar that can't be hijacked.** DJ taps **💰 open tip
   jar** — a `wm-broadcast-request` (546) signed over the receive
   addresses. Guests see the golden jar because the signature verifies AND
   the sender is the room's performer. Paste the same JSON into chat from
   a guest account and it renders as an inert warning chip — no button, no
   jar. That asymmetry is the OWM-PAY anti-poisoning render rule, live.
   ("I tipped" receipts are self-reported on this funds-free dev demo — a
   real client settles via a 544 intent and posts a verifiable 545.)

## What's honest here

- **Sync trusts NTP.** Phones are NTP-synced to within tens of ms; drift
  correction re-anchors only past 350 ms. Friends in separate homes never
  notice; two phones on one table may hear a tiny flam — that's the
  documented Tier 1 trade-off, not a bug to hide.
- **The door link is bearer** within its `maxUses`/TTL bounds — exactly the
  invite-link trade-off, chosen on purpose for a friends' party. The invite
  state machine (uses, expiry, revocation) is the gate.
- **The analog hole is real.** A guest can always record their own device's
  audio. Eviction and privacy are cryptographic; DRM is not pretended.
- **Auto-admit on a valid ticket.** The WM-4 `request` join policy gates
  unknown claimants behind a manual admit; this demo auto-admits any valid
  token holder to keep the party moving. The state machine is identical;
  the click is elided.
- The join request/result ride as 400-range JSON (their strict SPECS are a
  known TODO); every other message is a strict-validated OWM envelope —
  unknown kinds render visibly as chips, never dropped.
