#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
# OWM live smoke — self-bootstrapping (Node >= 20). Installs @xmtp/node-sdk
# + viem into live/node_modules on first run, then drives the real XMTP dev
# network. No state outside this directory + a temp db dir.
#
# Stage 1: smoke.mjs      — rooms/invites/ping-pong on the XMTP dev network.
# Stage 2: scx_smoke.mjs  — SCX over a locally built owm-rendezvous
#          relay, then XMTP with the exchanged contact. Needs cargo; if cargo
#          is absent that stage SKIPs itself loudly and exits 0.
# Stage 3: auth_smoke.mjs — OWM-AUTH 2FA + OWM-GRANT ceremonies
#          (kinds 530-534) riding a real DM on the XMTP dev network. Pure
#          XMTP + JS — no cargo, never skips.
# Stage 4: stage_smoke.mjs — listening-party beacons (kinds 540-542) in
#          a real MLS room — latecomer forward secrecy + eviction-deafening.
#          Pure XMTP + JS — no cargo, never skips.
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -d node_modules/@xmtp/node-sdk ]; then
  echo "— bootstrapping live-smoke deps (first run) —"
  npm install --no-audit --no-fund
fi
echo "═══ live stage 1: XMTP dev smoke ═══"
node smoke.mjs
echo ""
echo "═══ live stage 2: SCX rendezvous smoke ═══"
node scx_smoke.mjs
echo ""
echo "═══ live stage 3: OWM-AUTH / OWM-GRANT smoke ═══"
node auth_smoke.mjs
echo ""
echo "═══ live stage 4: OWM-STAGE listening-party smoke ═══"
node stage_smoke.mjs
