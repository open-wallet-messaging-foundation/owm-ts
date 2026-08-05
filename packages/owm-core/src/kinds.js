// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// OWM kind registry — mirrors ../../../api/kinds.json (the normative copy).
// Numeric code <-> kebab-case wire name. Ranges 1–399 are grandfathered from
// the founding registry and imported before v0 freeze.

export const KIND = Object.freeze({
  GroupRoomCreate: 400,
  GroupJoinRequest: 401,
  GroupJoinResult: 402,
  GroupMemberAdded: 403,
  GroupMemberRemoved: 404,
  GroupInviteRevoked: 405,

  WmPing: 500,
  WmPong: 501,
  WmKnock: 502,
  ScxPakeA: 510,
  ScxPakeB: 511,
  WmContactCard: 512,
  ScxConfirm: 513,
  ScxAbort: 514,
  WmSenderAttestation: 515,
  WmSignedAnnouncement: 516,
  WmInvite: 517,
  WmInviteResponse: 518,
  WmIntro: 519,
  NotifySubscribe: 520,
  NotifyUnsubscribe: 521,
  NotifyKnock: 522,
  NotifyReceipt: 523,
  OwmIdentityKey: 524,
  OwmfMsg: 525,
  OwmfFile: 526,
  OwmBinding: 527,
  OwmBindingAttest: 528,
  WmAuthChallenge: 530,
  WmAuthResponse: 531,
  WmGrantRequest: 532,
  WmGrant: 533,
  WmGrantRevoke: 534,
  WmApprovalRequest: 535,
  WmApprovalSig: 536,
  WmApprovalResult: 537,
  WmDuressAlert: 538,
  WmLivenessCheckin: 539,
  WmStageConfig: 540,
  WmPlaybackSync: 541,
  WmStageCue: 542,
  WmSettlementCard: 543,
  WmTxIntent: 544,
  WmTxReference: 545,
  WmBroadcastRequest: 546,
  WmCallAttestation: 547,

  OwmKvSet: 550,
  OwmKvGet: 551,
  OwmKvDelete: 552,
  OwmKvList: 553,
  OwmKvReveal: 554,
  OwmKvPointer: 555,

  OwmAttestation: 580,
  OwmPresentation: 590,
  OwmTransfer: 600,

  Ack: 900,
  Error: 999,
});

export const WIRE = Object.freeze({
  [KIND.GroupRoomCreate]: 'group-room-create',
  [KIND.GroupJoinRequest]: 'group-join-request',
  [KIND.GroupJoinResult]: 'group-join-result',
  [KIND.GroupMemberAdded]: 'group-member-added',
  [KIND.GroupMemberRemoved]: 'group-member-removed',
  [KIND.GroupInviteRevoked]: 'group-invite-revoked',
  [KIND.WmPing]: 'wm-ping',
  [KIND.WmPong]: 'wm-pong',
  [KIND.WmKnock]: 'wm-knock',
  [KIND.ScxPakeA]: 'scx-pake-a',
  [KIND.ScxPakeB]: 'scx-pake-b',
  [KIND.WmContactCard]: 'wm-contact-card',
  [KIND.ScxConfirm]: 'scx-confirm',
  [KIND.ScxAbort]: 'scx-abort',
  [KIND.WmSenderAttestation]: 'wm-sender-attestation',
  [KIND.WmSignedAnnouncement]: 'wm-signed-announcement',
  [KIND.WmInvite]: 'wm-invite',
  [KIND.WmInviteResponse]: 'wm-invite-response',
  [KIND.WmIntro]: 'wm-intro',
  [KIND.NotifySubscribe]: 'notify-subscribe',
  [KIND.NotifyUnsubscribe]: 'notify-unsubscribe',
  [KIND.NotifyKnock]: 'notify-knock',
  [KIND.NotifyReceipt]: 'notify-receipt',
  [KIND.OwmIdentityKey]: 'owm-identity-key',
  [KIND.OwmfMsg]: 'owmf-msg',
  [KIND.OwmfFile]: 'owmf-file',
  [KIND.OwmBinding]: 'owm-binding',
  [KIND.OwmBindingAttest]: 'owm-binding-attest',
  [KIND.WmAuthChallenge]: 'wm-auth-challenge',
  [KIND.WmAuthResponse]: 'wm-auth-response',
  [KIND.WmGrantRequest]: 'wm-grant-request',
  [KIND.WmGrant]: 'wm-grant',
  [KIND.WmGrantRevoke]: 'wm-grant-revoke',
  [KIND.WmApprovalRequest]: 'wm-approval-request',
  [KIND.WmApprovalSig]: 'wm-approval-sig',
  [KIND.WmApprovalResult]: 'wm-approval-result',
  [KIND.WmDuressAlert]: 'wm-duress-alert',
  [KIND.WmLivenessCheckin]: 'wm-liveness-checkin',
  [KIND.WmStageConfig]: 'wm-stage-config',
  [KIND.WmPlaybackSync]: 'wm-playback-sync',
  [KIND.WmStageCue]: 'wm-stage-cue',
  [KIND.WmSettlementCard]: 'wm-settlement-card',
  [KIND.WmTxIntent]: 'wm-tx-intent',
  [KIND.WmTxReference]: 'wm-tx-reference',
  [KIND.WmBroadcastRequest]: 'wm-broadcast-request',
  [KIND.WmCallAttestation]: 'wm-call-attestation',
  [KIND.OwmKvSet]: 'owm-kv-set',
  [KIND.OwmKvGet]: 'owm-kv-get',
  [KIND.OwmKvDelete]: 'owm-kv-delete',
  [KIND.OwmKvList]: 'owm-kv-list',
  [KIND.OwmKvReveal]: 'owm-kv-reveal',
  [KIND.OwmKvPointer]: 'owm-kv-pointer',
  [KIND.OwmAttestation]: 'owm-attestation',
  [KIND.OwmPresentation]: 'owm-presentation',
  [KIND.OwmTransfer]: 'owm-transfer',
  [KIND.Ack]: 'ack',
  [KIND.Error]: 'error',
});

const WIRE_TO_CODE = Object.freeze(
  Object.fromEntries(Object.entries(WIRE).map(([code, wire]) => [wire, Number(code)])),
);

export function wireName(code) {
  return WIRE[code] ?? null;
}

export function kindCode(wire) {
  return WIRE_TO_CODE[wire] ?? null;
}

// 500–799 is the OWM core-primitive range (500–549 original sequential block;
// 550+ themed sub-bands, e.g. 550–559 kv / personal store).
export function isOwmKind(code) {
  return Number.isInteger(code) && code >= 500 && code <= 799;
}

// Vendor-private range: numeric 1000+, wire names must carry a `vnd.` prefix.
export function isVendorKind(code, wire) {
  return Number.isInteger(code) && code >= 1000 && typeof wire === 'string' && wire.startsWith('vnd.');
}

export const PING_PURPOSES = Object.freeze([
  'attention',
  'pre-payment',
  'security-alert',
  'liveness-probe',
  'call',
]);

// Actor axis: what KIND of participant a contact card / intro
// describes. Orthogonal to `guest` (assurance tier ≠ species). Honesty is
// by convention — the enforceable bit is a principal-signed grant (533),
// which policy gates on; the enum only makes the claim expressible.
export const ACTOR_TYPES = Object.freeze(['human', 'agent', 'service']);

// OWM-PAY (WM-4): the CLOSED settlement-intent core. Every commerce kind compiles
// down to these five shapes — they are what gets validated, simulated,
// approved, and audited. Extending this list is a spec change, not a
// convenience.
export const SETTLEMENT_METHODS = Object.freeze([
  'transfer', 'token-transfer', 'contract-call', 'typed-sign', 'batch',
]);

export const BROADCAST_PURPOSES = Object.freeze(['donation', 'ticket', 'payment']);
