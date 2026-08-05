// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OWM listening party — OWM-STAGE Tier 1 end-to-end in a browser, and,
// underneath the concert costume, the Phase 1 reference-messenger slice: an
// admin-only MLS room in the browser, a channel-drop door link (token
// fragment-only), a join-request DM gated by the @open-wallet-messaging/core invite state
// machine, and MLS-enforced eviction.
//
// Sync model (Tier 1): the DJ's wm-playback-sync beacons say "track T was at
// positionMs when the wall clock read atMs". Listeners trust NTP-synced
// device clocks, start anywhere mid-set, and re-anchor only if drift
// exceeds DRIFT_MS — there is no audio streaming at all; every client
// renders the same deterministic score locally (see tracks.js).

import { Client, IdentifierKind, GroupPermissionsOptions } from '@xmtp/browser-sdk';
import { toBytes, stringToHex } from 'viem';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import {
  parseMessage, buildWmStageConfig, buildWmPlaybackSync, buildWmStageCue,
  createInvite, inviteStatus, isAdmissible, redeem, buildInviteLink, parseInviteLink,
  deriveSas, randomNonce,
  canonicalBroadcastRequest, buildWmBroadcastRequest, verifyBroadcastRequest,
  signPersonalMessage,
} from '../../../packages/owm-core/src/index.js';
import { TRACKS, trackById, createPlayer } from './tracks.js';

const $ = (id) => document.getElementById(id);
const short = (a) => `${a.slice(0, 6)}…${a.slice(-4)}`;
const mmss = (ms) => `${Math.floor(ms / 60000)}:${String(Math.floor(ms / 1000) % 60).padStart(2, '0')}`;

const BURNER_KEY_SLOT = 'owm-party:burner-key';
const INVITE_SLOT = (roomId) => `owm-party:invite:${roomId}`;
const BEACON_EVERY_MS = 5000;
const DRIFT_MS = 350;
const DOOR_TTL_MS = 2 * 60 * 60 * 1000; // doors close in 2h

let client = null;
let myAddress = null; // the address we connected with (burner or injected)
let connectKind = null; // 'wallet' | 'burner' — decides how we sign
let performerInbox = null; // who the pay UI may trust (546 role binding)
let tipJarEnv = null; // the open jar (dj: for re-send on admit)
let pendingJar = null; // guest: jar seen before the stage config named a performer
let party = null; // the party group conversation
let isDj = false;
let player = null; // WebAudio player (created on user gesture)
let audioCtx = null;
let pendingBeacon = null; // last beacon seen before the audio unlock tap
let lastBeacon = null;
let lastBeaconAt = 0;
let lastSeq = -1; // guest: highest beacon seq applied
let seq = 0; // dj: outgoing beacon/config sequence
let djState = 'paused';
let djHeldMs = 0; // position while paused
let names = {}; // inboxId -> display name (from join requests; dj only)
const seen = new Set();

// --- door link (query holds the address, ONLY the fragment holds the token) --
let door = null;
try {
  const parsed = parseInviteLink(location.href);
  if (parsed.roomId && parsed.token) door = parsed;
} catch (err) {
  // A token in the query string is refused at parse — never weaken this.
  document.body.innerHTML = `<p style="padding:2rem">${err.message}</p>`;
  throw err;
}

// --- status / toasts / floats ------------------------------------------------

function status(msg, isError = false) {
  const el = $('status');
  el.textContent = msg;
  el.classList.toggle('error', isError);
  if (isError) console.error('[owm-party]', msg);
}

function humanError(err) {
  const m = String(err?.message ?? err);
  if (/user rejected|denied|4001/i.test(m)) return 'Signature request declined — try again.';
  if (/secure context|crypto\.subtle|getDirectory/i.test(m)) return 'This page needs https — re-open the https:// link and accept the certificate warning.';
  if (/network|fetch|Failed to fetch|timed? ?out/i.test(m)) return `Network problem talking to the XMTP dev network — ${m}`;
  return m;
}

function toast(msg) {
  const div = document.createElement('div');
  div.className = 'toast';
  div.textContent = msg;
  $('toasts').appendChild(div);
  setTimeout(() => div.remove(), 4200);
}

function floatEmoji(emoji) {
  const span = document.createElement('span');
  span.className = 'floater';
  span.textContent = emoji;
  span.style.left = `${10 + Math.random() * 80}%`;
  $('float-layer').appendChild(span);
  setTimeout(() => span.remove(), 3400);
}

const EMOJI_ONLY = /^\p{Extended_Pictographic}{1,3}$/u;

// --- identities (same shape as ../web-chat) ----------------------------------

async function injectedSigner() {
  const [address] = await window.ethereum.request({ method: 'eth_requestAccounts' });
  return {
    address,
    signer: {
      type: 'EOA',
      getIdentifier: () => ({ identifier: address.toLowerCase(), identifierKind: IdentifierKind.Ethereum }),
      signMessage: async (message) => toBytes(await window.ethereum.request({
        method: 'personal_sign', params: [stringToHex(message), address],
      })),
    },
  };
}

function burnerSigner() {
  let key = localStorage.getItem(BURNER_KEY_SLOT);
  if (!key) {
    key = generatePrivateKey();
    localStorage.setItem(BURNER_KEY_SLOT, key);
    $('burner-key').textContent = key;
    $('burner-reveal').hidden = false;
  }
  const account = privateKeyToAccount(key);
  return {
    address: account.address,
    signer: {
      type: 'EOA',
      getIdentifier: () => ({ identifier: account.address.toLowerCase(), identifierKind: IdentifierKind.Ethereum }),
      signMessage: async (message) => toBytes(await account.signMessage({ message })),
    },
  };
}

async function connect(kind) {
  $('btn-mm').disabled = true;
  $('btn-burner').disabled = true;
  try {
    status(kind === 'wallet' ? 'Requesting your wallet address…' : 'Loading burner identity…');
    const { address, signer } = kind === 'wallet' ? await injectedSigner() : burnerSigner();
    myAddress = address;
    connectKind = kind;
    status('Creating/loading your XMTP identity — approve the signature if prompted…');
    const base = { env: 'dev', appVersion: 'owm-listening-party/0.0.1' };
    try {
      client = await Client.create(signer, base);
    } catch (err) {
      console.warn('persistent storage failed, retrying in-memory:', err);
      client = await Client.create(signer, { ...base, dbPath: null });
    }
    $('me-address').textContent = short(address);
    $('me-inbox').textContent = short(client.inboxId);
    $('banner').hidden = false;
    $('connect').hidden = true;
    await startStream();
    if (door) {
      $('knock').hidden = false;
      $('knock-line').textContent = `You're invited${door.name ? ` to “${door.name}”` : ''} — mode ${door.mode}.`;
      status('Connected. Knock when you\'re ready.');
    } else {
      $('host').hidden = false;
      status('Connected. Name your party and open the doors.');
    }
  } catch (err) {
    status(humanError(err), true);
    $('btn-mm').disabled = !window.ethereum;
    $('btn-burner').disabled = false;
  }
}

// --- receiving ---------------------------------------------------------------

async function startStream() {
  await client.conversations.streamAllMessages({
    onValue: (msg) => { handleIncoming(msg).catch((e) => console.warn(e)); },
    onError: (e) => status(`Stream hiccup (auto-retrying): ${humanError(e)}`, true),
    onRestart: () => status('Message stream reconnected.'),
  });
  // Belt-and-braces poller: LOCAL reads only for the open party (no
  // party.sync() — a second concurrent decrypt burns the one-time MLS
  // ratchet secret; see ../web-chat). conversations.sync() is safe: it
  // fetches new WELCOMES, which is how a guest learns they were admitted.
  setInterval(async () => {
    if (!client) return;
    try {
      if (party) for (const m of await party.messages()) await handleIncoming(m);
      else await client.conversations.sync();
    } catch { /* transient — next tick retries */ }
  }, 7000);
}

async function handleIncoming(msg) {
  if (seen.has(msg.id)) return;
  seen.add(msg.id);
  if (typeof msg.content !== 'string') return; // group_updated etc.
  const mine = msg.senderInboxId === client.inboxId;

  if (party && msg.conversationId === party.id) {
    const p = parseMessage(msg.content);
    if (p.ok && p.kind === 'wm-stage-config') return applyConfig(p.body);
    if (p.ok && p.kind === 'wm-playback-sync') return mine ? undefined : applyBeacon(p.body);
    if (p.ok && p.kind === 'wm-broadcast-request') return handleTipJar(p.body, msg.senderInboxId);
    if (p.ok && p.kind === 'wm-stage-cue') {
      if (!mine) toast(`${p.body.cue === 'encore' ? '🎶 encore!' : '🙋 hand up'} — ${nameOf(msg.senderInboxId)}`);
      return;
    }
    if (p.plain) {
      if (EMOJI_ONLY.test(msg.content.trim())) return floatEmoji(msg.content.trim());
      return chatBubble(msg.content, mine, nameOf(msg.senderInboxId));
    }
    return chatBubble(msg.content, mine, nameOf(msg.senderInboxId), p); // envelope chip
  }

  // Not the party: on the DJ side, a DM may carry a join request.
  if (isDj && !mine) {
    let body;
    try { body = JSON.parse(msg.content); } catch { return; }
    if (body?._kind === 'group-join-request') await handleJoinRequest(body, msg);
  }
}

// --- DJ: host + door gate ----------------------------------------------------

async function hostParty() {
  const name = $('party-name').value.trim() || 'OWM listening party';
  const capacity = Math.max(1, Math.min(200, Number($('party-capacity').value) || 12));
  $('btn-host').disabled = true;
  try {
    status('Creating the venue (admin-only MLS room)…');
    party = await client.conversations.createGroup([], {
      permissions: GroupPermissionsOptions.AdminOnly,
      groupName: name,
    });
    isDj = true;
    performerInbox = client.inboxId;
    const invite = createInvite({
      roomId: party.id, label: name, now: Date.now(), ttlMs: DOOR_TTL_MS, maxUses: capacity,
    });
    localStorage.setItem(INVITE_SLOT(party.id), JSON.stringify(invite));
    const link = buildInviteLink({
      origin: location.origin, roomId: party.id, adminInboxId: client.inboxId,
      name, mode: 'stage', token: invite.token,
    });
    $('invite-link').textContent = link;
    $('btn-copy-link').onclick = async () => {
      try { await navigator.clipboard.writeText(link); $('btn-copy-link').textContent = 'copied ✓'; }
      catch { status('Clipboard blocked — long-press the link to copy.', true); }
    };
    $('host').hidden = true;
    $('share').hidden = false;
    enterStage({ title: name });
    updateInviteUses();
    status('Doors open. Share the link, pick a track, hit play.');
  } catch (err) {
    status(humanError(err), true);
    $('btn-host').disabled = false;
  }
}

function loadInvite() {
  const raw = localStorage.getItem(INVITE_SLOT(party.id));
  return raw ? JSON.parse(raw) : null;
}

function updateInviteUses() {
  const invite = loadInvite();
  if (!invite) return;
  $('invite-uses').textContent = ` Door: ${inviteStatus(invite, Date.now())}, ${invite.uses}/${invite.maxUses} used.`;
}

async function handleJoinRequest(body, msg) {
  if (!party || body.groupId !== party.id) return;
  const invite = loadInvite();
  const requester = String(body.requester ?? '');
  const dm = await client.conversations.getConversationById(msg.conversationId);
  const reply = (ok, reason) => dm?.sendText(JSON.stringify({
    _kind: 'group-join-result', v: 1, groupId: party.id, ok, ...(reason ? { reason } : {}),
  })).catch(() => {});
  if (!invite || body.token !== invite.token || !isAdmissible(invite, Date.now(), requester)) {
    const why = !invite || body.token !== invite.token ? 'bad token'
      : inviteStatus(invite, Date.now());
    toast(`🚫 door refused ${short(requester)} (${why})`);
    return reply(false, why);
  }
  try {
    localStorage.setItem(INVITE_SLOT(party.id), JSON.stringify(redeem(invite, Date.now(), requester)));
    await party.addMembersByIdentifiers([{ identifier: requester, identifierKind: IdentifierKind.Ethereum }]);
    if (body.name) { names = { ...names, [requester.toLowerCase()]: body.name }; }
    await reply(true);
    toast(`🎉 ${body.name || short(requester)} is in`);
    updateInviteUses();
    refreshMembers();
    // MLS forward secrecy: the newcomer cannot read anything sent before
    // their welcome — re-send the stage state so they land mid-song.
    await sendConfig();
    await sendBeacon();
    if (tipJarEnv) await party.sendText(JSON.stringify(tipJarEnv)).catch(() => {});
  } catch (err) {
    status(`Admit failed — ${humanError(err)}`, true);
  }
}

// --- guest: knock + wait for the welcome -------------------------------------

async function knock() {
  $('btn-knock').disabled = true;
  const displayName = $('guest-name').value.trim();
  try {
    $('knock-status').textContent = 'Knocking — sending the join request over an encrypted DM…';
    const dm = await client.conversations.createDm(door.adminInboxId);
    await dm.sendText(JSON.stringify({
      _kind: 'group-join-request', v: 1, groupId: door.roomId, token: door.token,
      requester: myAddress.toLowerCase(),
      ...(displayName ? { name: displayName } : {}), mode: door.mode,
    }));
    $('knock-status').textContent = 'Waiting on the doorstep — the DJ\'s client checks your ticket…';
    const found = await waitForWelcome(door.roomId, 120_000);
    if (!found) {
      $('knock-status').textContent = 'No welcome after 2 minutes — is the DJ\'s tab still open?';
      $('btn-knock').disabled = false;
      return;
    }
    party = found;
    $('knock').hidden = true;
    enterStage({ title: door.name || 'the party' });
    $('btn-enter').hidden = false; // audio needs one tap (autoplay policy)
    status('You\'re in. Tap to enter the party — E2EE room, dev network.');
  } catch (err) {
    $('knock-status').textContent = humanError(err);
    $('btn-knock').disabled = false;
  }
}

async function waitForWelcome(roomId, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await client.conversations.sync();
      const conv = await client.conversations.getConversationById(roomId);
      if (conv) return conv;
    } catch { /* transient */ }
    await new Promise((r) => setTimeout(r, 2500));
  }
  return null;
}

// --- the stage ---------------------------------------------------------------

function enterStage({ title }) {
  $('stage').hidden = false;
  $('stage-title').textContent = title;
  if (isDj) {
    $('dj-controls').hidden = false;
    $('members').hidden = false;
    for (const t of TRACKS) {
      const opt = document.createElement('option');
      opt.value = t.id;
      opt.textContent = `${t.title} · ${t.bpm} bpm`;
      $('track-pick').appendChild(opt);
    }
    $('stage-sub').textContent = 'you are the DJ';
    setInterval(sendBeacon, BEACON_EVERY_MS);
    setInterval(refreshMembers, 6000);
    refreshMembers();
  } else {
    $('cues').hidden = false;
    $('stage-sub').textContent = 'audience';
    setInterval(checkStillInside, 5000);
    setInterval(refreshMembers, 8000);
  }
  setInterval(tickPosition, 500);
  setInterval(() => {
    if (!isDj && lastBeacon?.state === 'playing' && Date.now() - lastBeaconAt > 3 * BEACON_EVERY_MS) {
      $('stage-sub').textContent = 'signal lost — waiting for the DJ…';
    }
  }, 3000);
}

function applyConfig(body) {
  if (body.seq < 0) return;
  if (body.title) $('stage-title').textContent = body.title;
  performerInbox = body.performers[0] ?? performerInbox;
  if (!isDj) $('stage-sub').textContent = `audience · DJ ${short(performerInbox ?? '?')}`;
  if (pendingJar) { const j = pendingJar; pendingJar = null; handleTipJar(j.body, j.sender); }
}

function nameOf(inboxId) {
  return names[inboxId?.toLowerCase?.()] ?? (inboxId ? short(inboxId) : '?');
}

function ensureAudio() {
  if (!audioCtx) {
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    player = createPlayer(audioCtx);
  }
  if (audioCtx.state === 'suspended') audioCtx.resume();
}

// Guest sync core: "track T was at positionMs when the wall clock read atMs".
function applyBeacon(body) {
  lastBeacon = body;
  lastBeaconAt = Date.now();
  if (body.seq <= lastSeq) return; // stale or duplicate beacon
  lastSeq = body.seq;
  if (!player) { pendingBeacon = body; return; } // before the unlock tap
  const track = trackById(body.trackId);
  if (!track) return; // future track this build doesn't know — ignore loudly?
  if (body.state === 'paused') {
    player.stop();
    setNowPlaying(track.title, body.positionMs, false);
    return;
  }
  const target = body.positionMs + (Date.now() - body.atMs);
  const drifted = player.playing && player.track?.id === track.id
    && Math.abs(player.positionMs() - target) > DRIFT_MS;
  if (!player.playing || player.track?.id !== track.id || drifted) {
    player.play(track, target);
  }
  setNowPlaying(track.title, target, true);
}

function setNowPlaying(title, posMs, playing) {
  $('np-track').textContent = title;
  $('np-pos').textContent = mmss(posMs);
  $('now-playing').classList.toggle('playing', playing);
  $('now-playing').classList.toggle('idle', !playing);
}

function tickPosition() {
  if (player?.playing) $('np-pos').textContent = mmss(player.positionMs());
}

async function checkStillInside() {
  if (!party) return;
  try {
    if (!(await party.isActive())) bounced();
  } catch { /* transient */ }
}

function bounced() {
  player?.stop();
  audioCtx?.suspend();
  $('stage').hidden = true;
  $('bounced').hidden = false;
  status('Removed from the room — MLS epoch rotated.', true);
}

// --- DJ controls -------------------------------------------------------------

async function sendConfig() {
  if (!party || !isDj) return;
  seq += 1;
  const env = buildWmStageConfig({
    mode: 'listening-party', title: $('stage-title').textContent,
    performers: [client.inboxId], seq, ts: Date.now(),
  });
  await party.sendText(JSON.stringify(env)).catch((e) => console.warn(e));
}

async function sendBeacon() {
  if (!party || !isDj || !player?.track) return;
  seq += 1;
  const env = buildWmPlaybackSync({
    trackId: player.track.id,
    positionMs: djState === 'playing' ? player.positionMs() : Math.round(djHeldMs),
    state: djState,
    atMs: Date.now(),
    seq,
  });
  await party.sendText(JSON.stringify(env)).catch((e) => console.warn(e));
}

async function djPlay() {
  ensureAudio();
  const track = trackById($('track-pick').value) ?? TRACKS[0];
  const resume = player.track?.id === track.id ? djHeldMs : 0;
  player.play(track, resume);
  djState = 'playing';
  $('btn-play').hidden = true;
  $('btn-pause').hidden = false;
  setNowPlaying(track.title, resume, true);
  await sendConfig();
  await sendBeacon();
}

async function djPause() {
  djHeldMs = player.positionMs();
  player.stop();
  djState = 'paused';
  $('btn-play').hidden = false;
  $('btn-pause').hidden = true;
  setNowPlaying(player.track.title, djHeldMs, false);
  await sendBeacon();
}

async function refreshMembers() {
  if (!party) return;
  try {
    const members = await party.members();
    renderFingerprint(members);
    if (!isDj) return;
    const ul = $('member-list');
    ul.replaceChildren();
    for (const m of members) {
      if (m.inboxId === client.inboxId) continue;
      const li = document.createElement('li');
      const addr = m.accountIdentifiers?.[0]?.identifier ?? '';
      const label = document.createElement('span');
      label.textContent = `${nameOf(addr || m.inboxId)} `;
      const role = document.createElement('span');
      role.className = 'role';
      role.textContent = short(m.inboxId);
      const btn = document.createElement('button');
      btn.className = 'bounce';
      btn.textContent = '✕';
      btn.title = 'bounce (MLS removeMembers — they are cryptographically out)';
      btn.onclick = async () => {
        try {
          await party.removeMembers([m.inboxId]);
          toast(`⛔ bounced ${nameOf(addr || m.inboxId)}`);
          refreshMembers();
          await sendBeacon(); // next epoch — the bounced can't read this one
        } catch (err) { status(humanError(err), true); }
      };
      li.append(label, role, btn);
      ul.appendChild(li);
    }
  } catch { /* transient */ }
}

// Room fingerprint (the SCX SAS idiom, WM-3 §5): SAS over the sorted member
// list. Everyone in the real room shows the same 2 emoji + 4 digits; an
// impostor room won't.
async function renderFingerprint(members) {
  const ids = members.map((m) => m.inboxId).sort().join('\n');
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`owm-party-fp-v1\n${ids}`));
  const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
  $('fingerprint').textContent = deriveSas(hex).display;
}

// --- tip jar (the first wm-broadcast-request consumer) ---------------------

// EIP-191 over the OWM-PAY canonical, via whichever identity we hold: the
// burner signs locally; an injected wallet signs through personal_sign
// (identical digest — MetaMask returns r||s||v with v = 27/28).
async function signCanonical(payload) {
  if (connectKind === 'burner') {
    return signPersonalMessage(payload, localStorage.getItem(BURNER_KEY_SLOT));
  }
  const sig = await window.ethereum.request({
    method: 'personal_sign', params: [stringToHex(payload), myAddress],
  });
  return sig.replace(/^0x/, '').toLowerCase();
}

async function openTipJar() {
  if (!party || !isDj) return;
  $('btn-jar').disabled = true;
  try {
    const ts = Date.now();
    const fields = {
      nonce: randomNonce(),
      purpose: 'donation', // open amount — it's a tip jar
      asset: 'USDC',
      // Illustrative CAIP-10 target — a real client lists these from the
      // DJ's 543 settlement card.
      targets: [`eip155:1:${myAddress.toLowerCase()}`],
      memo: `${$('stage-title').textContent} — tip the DJ`,
      requester: myAddress,
      ts,
      exp: ts + DOOR_TTL_MS,
    };
    const sig = await signCanonical(canonicalBroadcastRequest(fields));
    tipJarEnv = buildWmBroadcastRequest({ ...fields, sig });
    const id = await party.sendText(JSON.stringify(tipJarEnv));
    seen.add(id);
    handleTipJar(tipJarEnv, client.inboxId);
    $('btn-jar').hidden = true;
    toast('💰 tip jar is open');
  } catch (err) {
    status(`Tip jar failed — ${humanError(err)}`, true);
    $('btn-jar').disabled = false;
  }
}

// The OWM-PAY render rule, verbatim: pay UI ONLY when the signature verifies
// AND the sender holds the performer role. Anything else renders as an
// inert bad chip — no button, no jar. That asymmetry IS the anti-poisoning.
function handleTipJar(body, sender) {
  if (!performerInbox) { pendingJar = { body, sender }; return; }
  const v = verifyBroadcastRequest(body, Date.now());
  if (!v.ok || sender !== performerInbox) {
    chatBubble(JSON.stringify(body), false, nameOf(sender), {
      kind: 'wm-broadcast-request',
      error: v.ok ? 'signer lacks the performer role' : v.error,
    });
    toast('🚫 unverified payment request — ignored');
    return;
  }
  $('jar-memo').textContent = body.memo ?? 'tip the performer';
  const target = body.targets[0];
  $('jar-target').textContent = target.length > 40 ? `${target.slice(0, 24)}…${target.slice(-6)}` : target;
  $('jar-target').dataset.full = target;
  $('tipjar').hidden = false;
}

// --- chat + cues + reactions -------------------------------------------------

function chatBubble(text, mine, who, parsedEnvelope) {
  const div = document.createElement('div');
  div.className = mine ? 'bubble mine' : 'bubble';
  if (parsedEnvelope) {
    const chip = document.createElement('div');
    chip.className = 'chip' + (parsedEnvelope.unknown || parsedEnvelope.error ? ' bad' : '');
    const kind = document.createElement('span');
    kind.className = 'kind';
    kind.textContent = parsedEnvelope.unknown ? `unknown OWM kind “${parsedEnvelope.kind}”`
      : parsedEnvelope.error ? `invalid ${parsedEnvelope.kind}` : `OWM ${parsedEnvelope.kind}`;
    const pre = document.createElement('pre');
    pre.textContent = text;
    chip.append(kind, pre);
    div.appendChild(chip);
  } else {
    div.textContent = text;
  }
  const meta = document.createElement('span');
  meta.className = 'meta';
  meta.textContent = mine ? 'you' : who;
  div.appendChild(meta);
  $('messages').appendChild(div);
  $('messages').scrollTop = $('messages').scrollHeight;
}

async function sendDraft() {
  const text = $('draft').value.trim();
  if (!text || !party) return;
  $('draft').value = '';
  try {
    const id = await party.sendText(text);
    seen.add(id);
    if (EMOJI_ONLY.test(text)) floatEmoji(text);
    else chatBubble(text, true, 'you');
  } catch (err) {
    $('draft').value = text;
    status(`Send failed — ${humanError(err)}`, true);
  }
}

// --- wire up -----------------------------------------------------------------

if (!window.ethereum) { $('btn-mm').disabled = true; $('mm-hint').hidden = false; }
$('btn-mm').addEventListener('click', () => connect('wallet'));
$('btn-burner').addEventListener('click', () => connect('burner'));
$('btn-copy-key').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('burner-key').textContent); $('btn-copy-key').textContent = 'copied ✓'; }
  catch { status('Clipboard blocked — long-press the key to copy it.', true); }
});
$('host-form').addEventListener('submit', (e) => { e.preventDefault(); hostParty(); });
$('btn-knock').addEventListener('click', knock);
$('btn-enter').addEventListener('click', () => {
  ensureAudio();
  $('btn-enter').hidden = true;
  if (pendingBeacon) { const b = pendingBeacon; pendingBeacon = null; lastSeq = -1; applyBeacon(b); }
  status('You\'re at the party. 🎧');
});
$('btn-play').addEventListener('click', djPlay);
$('btn-pause').addEventListener('click', djPause);
$('btn-jar').addEventListener('click', openTipJar);
$('btn-copy-target').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('jar-target').dataset.full); $('btn-copy-target').textContent = 'copied ✓'; }
  catch { status('Clipboard blocked — long-press the address to copy.', true); }
});
$('btn-tipped').addEventListener('click', async () => {
  if (!party) return;
  floatEmoji('🪙');
  // Honest by design: no fabricated tx reference on a funds-free dev demo.
  // A real client settles via 544 and posts a verifiable 545 instead.
  const id = await party.sendText('🪙 tipped the jar (self-reported)').catch(() => null);
  if (id) seen.add(id);
});
$('composer').addEventListener('submit', (e) => { e.preventDefault(); sendDraft(); });
for (const btn of document.querySelectorAll('.react')) {
  btn.addEventListener('click', async () => {
    if (!party) return;
    floatEmoji(btn.textContent);
    const id = await party.sendText(btn.textContent).catch(() => null);
    if (id) seen.add(id);
  });
}
for (const btn of document.querySelectorAll('.cue')) {
  btn.addEventListener('click', async () => {
    if (!party) return;
    const env = buildWmStageCue({ cue: btn.dataset.cue, ts: Date.now() });
    const id = await party.sendText(JSON.stringify(env)).catch(() => null);
    if (id) seen.add(id);
    toast(btn.dataset.cue === 'encore' ? 'encore requested 🎶' : 'hand raised 🙋');
  });
}
