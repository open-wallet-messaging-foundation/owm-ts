// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OWM web chat — a minimal real messenger, and the seed of the Phase 1
// reference web app. One page, no framework:
//
//   1. connect an identity — the injected wallet (MetaMask mobile in-app
//      browser or desktop extension) signs once via personal_sign to
//      create/load the XMTP identity; or a burner key does the same locally
//   2. open a DM by pasting a 0x address (or arrive via a #peer=0x… link) —
//      or START A ROOM: an admin-only MLS group with a channel-drop invite
//      link (token in the URL fragment only), knock-to-join gated by the
//      @open-wallet-messaging/core invite state machine. Two phones + a laptop = a private
//      3-way room. This is the Phase 1 reference-messenger slice.
//   3. chat over the real XMTP dev network, streamed live
//
// The OWM part is deliberately tiny: every inbound message goes through
// @open-wallet-messaging/core parseMessage — see renderBody() below for the entire
// render-or-fallback philosophy in ~10 lines.

import { Client, IdentifierKind, GroupPermissionsOptions } from '@xmtp/browser-sdk';
import { toBytes, stringToHex } from 'viem';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import {
  parseMessage, buildPing,
  createInvite, inviteStatus, isAdmissible, redeem,
  buildInviteLink, parseInviteLink,
} from '../../../packages/owm-core/src/index.js';

const $ = (id) => document.getElementById(id);
const short = (a) => `${a.slice(0, 6)}…${a.slice(-4)}`;

// URL fragment only — never a query string (an OWM invariant: fragments are
// not sent to the server and don't land in access logs).
const fragment = new URLSearchParams(location.hash.slice(1));
const peerPrefill = fragment.get('peer');
const forceMemory = fragment.has('mem'); // #mem forces the in-memory DB

// A room invite link? (query holds room metadata, ONLY the fragment holds
// the token — a token in the query string is refused at parse, hard.)
let door = null;
try {
  const parsed = parseInviteLink(location.href);
  if (parsed.roomId && parsed.token) door = parsed;
} catch (err) {
  document.body.innerHTML = `<p style="padding:2rem">${err.message}</p>`;
  throw err;
}

const BURNER_KEY_SLOT = 'owm-web-chat:burner-key';
const INVITE_SLOT = (roomId) => `owm-web-chat:invite:${roomId}`;
const DOOR_TTL_MS = 2 * 60 * 60 * 1000; // doors close after 2h
const DOOR_MAX_USES = 10;

let client = null; // XMTP client once connected
let myAddress = null;
let current = null; // the open conversation (DM or room)
let currentIsRoom = false;
let hostedRoom = null; // the group we created (host side)
const seen = new Set(); // message ids already rendered (dedupes stream+poll)

// --- status line -------------------------------------------------------------

function status(msg, isError = false) {
  const el = $('status');
  el.textContent = msg;
  el.classList.toggle('error', isError);
  if (isError) console.error('[owm-web-chat]', msg);
}

// Turn SDK/wallet errors into a sentence a human can act on.
function humanError(err) {
  const m = String(err?.message ?? err);
  if (/user rejected|denied|4001/i.test(m)) return 'Signature request declined — tap Connect to try again.';
  if (/secure context|crypto\.subtle|getDirectory/i.test(m)) {
    return 'This page needs a secure context (https). Re-open it via the https:// link and accept the certificate warning.';
  }
  if (/network|fetch|Failed to fetch|timed? ?out/i.test(m)) return `Network problem talking to the XMTP dev network — ${m}`;
  return m;
}

// --- rendering ---------------------------------------------------------------

// The whole OWM philosophy in one function: STRICT-parse every inbound
// message. Plain text renders as chat; a valid OWM envelope renders as a
// labeled chip; an unknown kind or an invalid payload is surfaced visibly —
// nothing is ever silently dropped.
function renderBody(text) {
  const p = parseMessage(text);
  if (p.ok) return chip(`OWM ${p.kind}`, JSON.stringify(p.body, null, 2)); // known kind, strictly valid
  if (p.plain) return textNode(text); // ordinary chat text
  if (p.unknown) return chip(`unknown OWM kind “${p.kind}”`, text, true); // future/vendor kind
  return chip(`invalid ${p.kind} (${p.error})`, text, true); // known kind, bad payload
}

function textNode(text) {
  const span = document.createElement('span');
  span.textContent = text;
  return span;
}

function chip(label, body, bad = false) {
  const div = document.createElement('div');
  div.className = bad ? 'chip bad' : 'chip';
  const kind = document.createElement('span');
  kind.className = 'kind';
  kind.textContent = label;
  const pre = document.createElement('pre');
  pre.textContent = body;
  div.append(kind, pre);
  return div;
}

function appendBubble(node, { mine, meta }) {
  const div = document.createElement('div');
  div.className = mine ? 'bubble mine' : 'bubble';
  div.appendChild(node);
  if (meta) {
    const m = document.createElement('span');
    m.className = 'meta';
    m.textContent = meta;
    div.appendChild(m);
  }
  const box = $('messages');
  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}

// Render one DecodedMessage if it belongs to the open conversation and is new.
function maybeRender(msg) {
  if (!current || msg.conversationId !== current.id) return;
  if (seen.has(msg.id)) return;
  seen.add(msg.id);
  const mine = msg.senderInboxId === client.inboxId;
  const when = msg.sentAt instanceof Date ? msg.sentAt.toLocaleTimeString() : '';
  // In a room, name the speaker (short inboxId) — in a DM the time is enough.
  const meta = currentIsRoom && !mine ? `${short(msg.senderInboxId)} · ${when}` : when;
  if (typeof msg.content === 'string') {
    // Room plumbing (join-request/-result JSON) is not chat — skip it.
    if (isRoomPlumbing(msg.content)) return;
    appendBubble(renderBody(msg.content), { mine, meta });
  } else if (typeof msg.fallback === 'string') {
    // Non-text content type we don't handle — show its fallback, visibly.
    appendBubble(textNode(`[${msg.fallback}]`), { mine, meta });
    $('messages').lastChild.classList.add('fallback');
  }
  // membership_change etc. carry no renderable content — skip quietly.
}

function isRoomPlumbing(text) {
  if (!text.startsWith('{')) return false;
  try {
    const k = JSON.parse(text)?._kind;
    return k === 'group-join-request' || k === 'group-join-result';
  } catch { return false; }
}

// --- identities ---------------------------------------------------------------

// XMTP browser-sdk signer for the injected wallet: one personal_sign per
// identity operation (MetaMask shows the prompt).
async function injectedSigner() {
  const [address] = await window.ethereum.request({ method: 'eth_requestAccounts' });
  return {
    address,
    signer: {
      type: 'EOA',
      getIdentifier: () => ({ identifier: address.toLowerCase(), identifierKind: IdentifierKind.Ethereum }),
      signMessage: async (message) => {
        const sig = await window.ethereum.request({
          method: 'personal_sign',
          params: [stringToHex(message), address],
        });
        return toBytes(sig);
      },
    },
  };
}

// Burner: a throwaway key in localStorage. Shown ONCE when first generated —
// never logged, never sent anywhere.
function burnerSigner() {
  let key = localStorage.getItem(BURNER_KEY_SLOT);
  const fresh = !key;
  if (fresh) {
    key = generatePrivateKey();
    localStorage.setItem(BURNER_KEY_SLOT, key);
    $('burner-key').textContent = key;
    $('burner-reveal').hidden = false;
  }
  const account = privateKeyToAccount(key);
  return {
    address: account.address,
    fresh,
    signer: {
      type: 'EOA',
      getIdentifier: () => ({ identifier: account.address.toLowerCase(), identifierKind: IdentifierKind.Ethereum }),
      signMessage: async (message) => toBytes(await account.signMessage({ message })),
    },
  };
}

// --- connect -----------------------------------------------------------------

async function connect(kind) {
  $('btn-mm').disabled = true;
  $('btn-burner').disabled = true;
  try {
    status(kind === 'wallet' ? 'Requesting your wallet address…' : 'Loading burner identity…');
    const { address, signer } = kind === 'wallet' ? await injectedSigner() : burnerSigner();
    myAddress = address;

    status('Creating/loading your XMTP identity — approve the signature prompt if one appears…');
    const base = { env: 'dev', appVersion: 'owm-web-chat/0.0.1' };
    let storage;
    try {
      client = await Client.create(signer, forceMemory ? { ...base, dbPath: null } : base);
      storage = forceMemory ? 'memory (#mem)' : 'persistent (OPFS)';
    } catch (err) {
      // Some WebViews can't run the SDK's OPFS-backed storage. Retry with an
      // in-memory DB (dbPath: null) so chat still works for this session.
      console.warn('persistent storage failed, retrying in-memory:', err);
      status('Persistent storage unavailable here — retrying with in-memory storage…');
      client = await Client.create(signer, { ...base, dbPath: null });
      storage = 'memory (session only)';
    }

    $('me-address').textContent = short(address);
    $('me-address').dataset.full = address;
    $('me-inbox').textContent = short(client.inboxId);
    $('me-inbox').dataset.full = client.inboxId;
    $('me-storage').textContent = storage;
    $('banner').hidden = false;
    $('connect').hidden = true;
    // Show the next step IMMEDIATELY — the stream setup below can take a
    // moment and the user (or the e2e) must not click into a hidden section.
    if (door) {
      $('knock').hidden = false;
      $('knock-line').textContent = `You're invited${door.name ? ` to “${door.name}”` : ' to a room'}. The token rode the URL fragment; knock and the host's client checks it.`;
    } else {
      $('newchat').hidden = false;
    }
    // Keep the one-time burner key reveal visible after connect.
    if (!$('burner-reveal').hidden) $('newchat').before($('burner-reveal'));

    await startStream();
    startPolling();

    if (door) {
      status('Connected. Knock to join the room.');
    } else if (peerPrefill) {
      $('peer').value = peerPrefill;
      status(`Link carried a peer address — opening the chat with ${short(peerPrefill)}…`);
      await openDmByAddress(peerPrefill);
    } else {
      status('Connected. Paste a 0x address, start a room — or wait to be messaged.');
    }
  } catch (err) {
    status(humanError(err), true);
    $('btn-mm').disabled = !window.ethereum;
    $('btn-burner').disabled = false;
  }
}

// --- receiving ----------------------------------------------------------------

// Live stream of every new message; the poller below is a belt-and-braces
// safety net on flaky connections (dedupe by message id makes overlap free).
async function startStream() {
  status('Starting the live message stream…');
  await client.conversations.streamAllMessages({
    onValue: (msg) => { handleIncoming(msg).catch((e) => console.warn(e)); },
    onError: (e) => status(`Stream hiccup (auto-retrying): ${humanError(e)}`, true),
    onRestart: () => status('Message stream reconnected.'),
  });
}

async function handleIncoming(msg) {
  const mine = msg.senderInboxId === client?.inboxId;

  // Host side: a DM may carry a knock (join request) for our room.
  if (hostedRoom && !mine && typeof msg.content === 'string'
      && msg.conversationId !== hostedRoom.id && msg.content.startsWith('{')) {
    let body;
    try { body = JSON.parse(msg.content); } catch { body = null; }
    if (body?._kind === 'group-join-request') return handleJoinRequest(body, msg);
  }

  // Guest side, waiting on the doorstep: the host's verdict arrives as a DM.
  if (door && !mine && typeof msg.content === 'string' && msg.content.startsWith('{')) {
    let body;
    try { body = JSON.parse(msg.content); } catch { body = null; }
    if (body?._kind === 'group-join-result' && !body.ok) {
      $('knock-status').textContent = `The door refused you: ${body.reason ?? 'no reason given'}.`;
      $('btn-knock').disabled = false;
      return;
    }
  }

  if (!current && !door && !hostedRoom) {
    // First contact: someone opened a DM with us — open it on our side too.
    const conv = await client.conversations.getConversationById(msg.conversationId);
    if (conv) await openConversation(conv);
  }
  maybeRender(msg);
}

function startPolling() {
  setInterval(async () => {
    if (!client) return;
    try {
      if (!current) {
        if (door || hostedRoom) return; // knocking/hosting — nothing to auto-open
        await client.conversations.sync();
        for (const dm of await client.conversations.listDms()) {
          await dm.sync();
          if ((await dm.messages()).length > 0) { await openConversation(dm); break; }
        }
      } else {
        // Read the LOCAL db only — no current.sync() here. The stream
        // worker is already decrypting new envelopes; a second concurrent
        // decrypt of the same message burns its one-time MLS ratchet secret
        // (SecretReuseError) and can drop the message for good.
        for (const m of await current.messages()) maybeRender(m);
      }
    } catch { /* transient network errors — the next tick retries */ }
  }, 7000);
}

// --- conversations --------------------------------------------------------------

async function openConversation(conv, { room = false, roomName = '' } = {}) {
  current = conv;
  currentIsRoom = room;
  $('chat').hidden = false;
  $('messages').replaceChildren();
  seen.clear();
  if (room) {
    let count = '';
    try { count = ` · ${(await conv.members()).length} members`; } catch { /* best-effort */ }
    $('peer-line').textContent = `room “${roomName || 'unnamed'}”${count} — MLS forward secrecy: joiners can't read what came before their welcome`;
  } else {
    const peerInbox = await conv.peerInboxId().catch(() => '(unknown)');
    $('peer-line').textContent = `chatting with inbox ${peerInbox}`;
  }
  try {
    await conv.sync();
    for (const m of await conv.messages()) maybeRender(m);
  } catch { /* history sync is best-effort; the stream still delivers */ }
  $('draft').focus();
  status(room
    ? 'Room open — messages are end-to-end encrypted to every member (XMTP MLS, dev network).'
    : 'Chat open — messages are end-to-end encrypted (XMTP MLS, dev network).');
}

async function openDmByAddress(raw) {
  const addr = raw.trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) {
    status('That is not a 0x… address (40 hex chars needed).', true);
    return;
  }
  if (addr.toLowerCase() === $('me-address').dataset.full?.toLowerCase()) {
    status('That is your own address — paste the OTHER device’s address.', true);
    return;
  }
  try {
    status(`Checking whether ${short(addr)} is reachable on XMTP…`);
    const id = { identifier: addr.toLowerCase(), identifierKind: IdentifierKind.Ethereum };
    const reachable = await client.canMessage([id]);
    if (![...reachable.values()].every(Boolean)) {
      status(`${short(addr)} has no XMTP identity yet — open this page on that device and connect first.`, true);
      return;
    }
    status('Opening the encrypted DM…');
    const dm = await client.conversations.createDmWithIdentifier(id);
    await openConversation(dm);
  } catch (err) {
    status(humanError(err), true);
  }
}

// --- rooms: host + door gate --------------------------------------------------

async function startRoom() {
  const name = $('room-name').value.trim() || 'OWM room';
  $('btn-room').disabled = true;
  try {
    status('Creating the room (admin-only MLS group)…');
    hostedRoom = await client.conversations.createGroup([], {
      permissions: GroupPermissionsOptions.AdminOnly,
      groupName: name,
    });
    const invite = createInvite({
      roomId: hostedRoom.id, label: name, now: Date.now(),
      ttlMs: DOOR_TTL_MS, maxUses: DOOR_MAX_USES,
    });
    localStorage.setItem(INVITE_SLOT(hostedRoom.id), JSON.stringify(invite));
    const link = buildInviteLink({
      origin: location.origin, roomId: hostedRoom.id, adminInboxId: client.inboxId,
      name, mode: 'call', token: invite.token,
    });
    $('room-link').textContent = link;
    $('room-share').hidden = false;
    updateDoorLine();
    await openConversation(hostedRoom, { room: true, roomName: name });
    status('Room open. Share the link; this tab must stay open to admit knocks.');
  } catch (err) {
    status(humanError(err), true);
    $('btn-room').disabled = false;
  }
}

function loadInvite() {
  const raw = hostedRoom && localStorage.getItem(INVITE_SLOT(hostedRoom.id));
  return raw ? JSON.parse(raw) : null;
}

function updateDoorLine() {
  const invite = loadInvite();
  if (!invite) return;
  $('room-door').textContent = `Door: ${inviteStatus(invite, Date.now())} · ${invite.uses}/${invite.maxUses} used · closes in ${Math.round((invite.expiresAt - Date.now()) / 60000)} min.`;
}

async function handleJoinRequest(body, msg) {
  if (!hostedRoom || body.groupId !== hostedRoom.id) return;
  const invite = loadInvite();
  const requester = String(body.requester ?? '');
  const dm = await client.conversations.getConversationById(msg.conversationId);
  const reply = (ok, reason) => dm?.sendText(JSON.stringify({
    _kind: 'group-join-result', v: 1, groupId: hostedRoom.id, ok, ...(reason ? { reason } : {}),
  })).catch(() => {});
  if (!invite || body.token !== invite.token || !isAdmissible(invite, Date.now(), requester)) {
    const why = !invite || body.token !== invite.token ? 'bad token' : inviteStatus(invite, Date.now());
    status(`Door refused ${short(requester)} (${why}).`);
    return reply(false, why);
  }
  try {
    localStorage.setItem(INVITE_SLOT(hostedRoom.id), JSON.stringify(redeem(invite, Date.now(), requester)));
    await hostedRoom.addMembersByIdentifiers([{ identifier: requester, identifierKind: IdentifierKind.Ethereum }]);
    await reply(true);
    updateDoorLine();
    status(`Admitted ${short(requester)} — the room now has ${(await hostedRoom.members()).length} members.`);
    if (current?.id === hostedRoom.id) {
      let count = '';
      try { count = ` · ${(await hostedRoom.members()).length} members`; } catch { /* best-effort */ }
      $('peer-line').textContent = `room “${$('room-name').value.trim() || 'OWM room'}”${count} — MLS forward secrecy: joiners can't read what came before their welcome`;
    }
  } catch (err) {
    status(`Admit failed — ${humanError(err)}`, true);
  }
}

// --- rooms: guest knock + wait for the welcome --------------------------------

async function knock() {
  $('btn-knock').disabled = true;
  try {
    $('knock-status').textContent = 'Knocking — sending the join request over an encrypted DM…';
    const dm = await client.conversations.createDm(door.adminInboxId);
    await dm.sendText(JSON.stringify({
      _kind: 'group-join-request', v: 1, groupId: door.roomId, token: door.token,
      requester: myAddress.toLowerCase(), mode: door.mode,
    }));
    $('knock-status').textContent = 'Waiting on the doorstep — the host’s client checks your token…';
    const room = await waitForWelcome(door.roomId, 120_000);
    if (!room) {
      $('knock-status').textContent = 'No welcome after 2 minutes — is the host’s tab still open?';
      $('btn-knock').disabled = false;
      return;
    }
    $('knock').hidden = true;
    await openConversation(room, { room: true, roomName: door.name });
  } catch (err) {
    $('knock-status').textContent = humanError(err);
    $('btn-knock').disabled = false;
  }
}

// The welcome arrives out-of-band (MLS welcome via sync) — poll until the
// group with our roomId shows up in the local store.
async function waitForWelcome(roomId, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await client.conversations.sync();
      const conv = await client.conversations.getConversationById(roomId);
      if (conv) return conv;
    } catch { /* transient — retry */ }
    await new Promise((r) => setTimeout(r, 2000));
  }
  return null;
}

// --- sending ---------------------------------------------------------------------

async function sendDraft() {
  const text = $('draft').value.trim();
  if (!text || !current) return;
  $('draft').value = '';
  try {
    status('Sending…');
    const id = await current.sendText(text);
    // The stream can echo our own message back BEFORE sendText resolves —
    // only append the optimistic bubble if the echo hasn't rendered it.
    if (!seen.has(id)) {
      seen.add(id);
      appendBubble(renderBody(text), { mine: true, meta: new Date().toLocaleTimeString() });
    }
    status('Sent.');
  } catch (err) {
    $('draft').value = text; // don't lose the draft
    status(`Send failed — ${humanError(err)}`, true);
  }
}

// Send a real OWM envelope (wm-ping, kind 500) so the other side's chip
// rendering has something to chew on.
async function sendPing() {
  if (!current) return;
  try {
    const ping = buildPing({ purpose: 'attention', ts: Date.now() });
    const id = await current.sendText(JSON.stringify(ping));
    if (!seen.has(id)) {
      seen.add(id);
      appendBubble(renderBody(JSON.stringify(ping)), { mine: true, meta: new Date().toLocaleTimeString() });
    }
    status('wm-ping sent.');
  } catch (err) {
    status(`Ping failed — ${humanError(err)}`, true);
  }
}

// --- wire up the page ---------------------------------------------------------------

if (!window.ethereum) {
  $('btn-mm').disabled = true;
  $('mm-hint').hidden = false;
}
$('btn-mm').addEventListener('click', () => connect('wallet'));
$('btn-burner').addEventListener('click', () => connect('burner'));
$('btn-copy-key').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText($('burner-key').textContent);
    $('btn-copy-key').textContent = 'copied ✓';
  } catch {
    status('Clipboard blocked — long-press the key to copy it manually.', true);
  }
});
$('open-form').addEventListener('submit', (e) => { e.preventDefault(); openDmByAddress($('peer').value); });
$('room-form').addEventListener('submit', (e) => { e.preventDefault(); startRoom(); });
$('btn-copy-link').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText($('room-link').textContent);
    $('btn-copy-link').textContent = 'copied ✓';
  } catch {
    status('Clipboard blocked — long-press the link to copy it manually.', true);
  }
});
$('btn-knock').addEventListener('click', knock);
$('composer').addEventListener('submit', (e) => { e.preventDefault(); sendDraft(); });
$('btn-ping').addEventListener('click', sendPing);
if (peerPrefill) $('peer').value = peerPrefill;
