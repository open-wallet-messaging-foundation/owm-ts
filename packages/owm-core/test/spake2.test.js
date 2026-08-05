// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import test from 'node:test';
import assert from 'node:assert/strict';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import {
  deriveW, spake2Start, spake2Finish, constantTimeEqual,
  SPAKE2_M_HEX, SPAKE2_N_HEX,
} from '../src/spake2.js';

// RFC 9382 Appendix B test vectors (SPAKE2-P256-SHA256-HKDF-HMAC), verbatim.
const VECTORS = [
  {
    name: "A='server', B='client'",
    idA: 'server',
    idB: 'client',
    w: '2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f',
    x: '43dd0fd7215bdcb482879fca3220c6a968e66d70b1356cac18bb26c84a78d729',
    y: 'dcb60106f276b02606d8ef0a328c02e4b629f84f89786af5befb0bc75b6e66be',
    pA: '04a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c',
    pB: '0406557e482bd03097ad0cbaa5df82115460d951e3451962f1eaf4367a420676d09857ccbc522686c83d1852abfa8ed6e4a1155cf8f1543ceca528afb591a1e0b7',
    tt: '06000000000000007365727665720600000000000000636c69656e74410000000000000004a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c41000000000000000406557e482bd03097ad0cbaa5df82115460d951e3451962f1eaf4367a420676d09857ccbc522686c83d1852abfa8ed6e4a1155cf8f1543ceca528afb591a1e0b741000000000000000412af7e89717850671913e6b469ace67bd90a4df8ce45c2af19010175e37eed69f75897996d539356e2fa6a406d528501f907e04d97515fbe83db277b715d332520000000000000002ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f',
    ke: '0e0672dc86f8e45565d338b0540abe69',
    ka: '15bdf72e2b35b5c9e5663168e960a91b',
    kcA: '00c12546835755c86d8c0db7851ae86f',
    kcB: 'a9fa3406c3b781b93d804485430ca27a',
    cA: '58ad4aa88e0b60d5061eb6b5dd93e80d9c4f00d127c65b3b35b1b5281fee38f0',
    cB: 'd3e2e547f1ae04f2dbdbf0fc4b79f8ecff2dff314b5d32fe9fcef2fb26dc459b',
  },
  {
    name: "A='', B='client'",
    idA: '',
    idB: 'client',
    w: '0548d8729f730589e579b0475a582c1608138ddf7054b73b5381c7e883e2efae',
    x: '403abbe3b1b4b9ba17e3032849759d723939a27a27b9d921c500edde18ed654b',
    y: '903023b6598908936ea7c929bd761af6039577a9c3f9581064187c3049d87065',
    pA: '04a897b769e681c62ac1c2357319a3d363f610839c4477720d24cbe32f5fd85f44fb92ba966578c1b712be6962498834078262caa5b441ecfa9d4a9485720e918a',
    pB: '04e0f816fd1c35e22065d5556215c097e799390d16661c386e0ecc84593974a61b881a8c82327687d0501862970c64565560cb5671f696048050ca66ca5f8cc7fc',
    ke: '642f05c473c2cd79909f9a841e2f30a7',
    ka: '0bf89b18180af97353ba198789c2b963',
    kcA: 'c6be376fc7cd1301fd0a13adf3e7bffd',
    kcB: 'b7243f4ae60440a49b3f8cab3c1fba07',
    cA: '47d29e6666af1b7dd450d571233085d7a9866e4d49d2645e2df975489521232b',
    cB: '3313c5cefc361d27fb16847a91c2a73b766ffa90a4839122a9b70a2f6bd1d6df',
  },
  {
    name: "A='server', B=''",
    idA: 'server',
    idB: '',
    w: '626e0cdc7b14c9db3e52a0b1b3a768c98e37852d5db30febe0497b14eae8c254',
    x: '07adb3db6bc623d3399726bfdbfd3d15a58ea776ab8a308b00392621291f9633',
    y: 'b6a4fc8dbb629d4ba51d6f91ed1532cf87adec98f25dd153a75accafafedec16',
    pA: '04f88fb71c99bfffaea370966b7eb99cd4be0ff1a7d335caac4211c4afd855e2e15a873b298503ad8ba1d9cbb9a392d2ba309b48bfd7879aefd0f2cea6009763b0',
    pB: '040c269d6be017dccb15182ac6bfcd9e2a14de019dd587eaf4bdfd353f031101e7cca177f8eb362a6e83e7d5e729c0732e1b528879c086f39ba0f31a9661bd34db',
    ke: '005184ff460da2ce59062c87733c299c',
    ka: '3521297d736598fc0a1127600efa1afb',
    kcA: 'f3da53604f0aeecea5a33be7bddf6edf',
    kcB: '9e3f86848736f159bd92b6e107ec6799',
    cA: 'bc9f9bbe99f26d0b2260e6456e05a86196a3307ec6663a18bf6ac825736533b2',
    cB: 'c2370e1bf813b086dff0d834e74425a06e6390f48f5411900276dcccc5a297ec',
  },
  {
    name: "A='', B=''",
    idA: '',
    idB: '',
    w: '7bf46c454b4c1b25799527d896508afd5fc62ef4ec59db1efb49113063d70cca',
    x: '8cef65df64bb2d0f83540c53632de911b5b24b3eab6cc74a97609fd659e95473',
    y: 'd7a66f64074a84652d8d623a92e20c9675c61cb5b4f6a0063e4648a2fdc02d53',
    pA: '04a65b367a3f613cf9f0654b1b28a1e3a8a40387956c8ba6063e8658563890f46ca1ef6a676598889fc28de2950ab8120b79a5ef1ea4c9f44bc98f585634b46d66',
    pB: '04589f13218822710d98d8b2123a079041052d9941b9cf88c6617ddb2fcc0494662eea8ba6b64692dc318250030c6af045cb738bc81ba35b043c3dcb46adf6f58d',
    ke: 'fc6374762ba5cf11f4b2caa08b2cd1b9',
    ka: '907ae0e26e8d6234318d91583cd74c86',
    kcA: '5dbd2f477166b7fb6d61febbd77a5563',
    kcB: '7689b4654407a5faeffdc8f18359d8a3',
    cA: 'dfb4db8d48ae5a675963ea5e6c19d98d4ea028d8e898dad96ea19a80ade95dca',
    cB: 'd0f0609d1613138d354f7e95f19fb556bf52d751947241e8c7118df5ef0ae175',
  },
];

test('RFC 9382 Appendix B vectors: shares, key schedule, confirmation MACs', () => {
  for (const v of VECTORS) {
    const w = BigInt(`0x${v.w}`);
    const a = spake2Start({ role: 'a', w, scalar: BigInt(`0x${v.x}`) });
    const b = spake2Start({ role: 'b', w, scalar: BigInt(`0x${v.y}`) });
    assert.equal(bytesToHex(a.share), v.pA, `${v.name} pA`);
    assert.equal(bytesToHex(b.share), v.pB, `${v.name} pB`);
    const fa = spake2Finish({ state: a, peerShare: b.share, idA: v.idA, idB: v.idB });
    const fb = spake2Finish({ state: b, peerShare: a.share, idA: v.idA, idB: v.idB });
    assert.ok(fa.ok && fb.ok);
    if (v.tt) assert.equal(bytesToHex(fa.transcript), v.tt, `${v.name} TT`);
    assert.equal(bytesToHex(fa.transcript), bytesToHex(fb.transcript));
    for (const [fin, side] of [[fa, 'A'], [fb, 'B']]) {
      assert.equal(bytesToHex(fin.ke), v.ke, `${v.name} ${side} Ke`);
      assert.equal(bytesToHex(fin.ka), v.ka, `${v.name} ${side} Ka`);
      assert.equal(bytesToHex(fin.kcA), v.kcA, `${v.name} ${side} KcA`);
      assert.equal(bytesToHex(fin.kcB), v.kcB, `${v.name} ${side} KcB`);
      assert.equal(bytesToHex(fin.cA), v.cA, `${v.name} ${side} cA`);
      assert.equal(bytesToHex(fin.cB), v.cB, `${v.name} ${side} cB`);
    }
    // cross-check the confirm/expect plumbing
    assert.ok(constantTimeEqual(fa.expectedPeerConfirm, fb.confirm));
    assert.ok(constantTimeEqual(fb.expectedPeerConfirm, fa.confirm));
  }
});

test('M and N are the RFC 9382 fixed points', () => {
  assert.equal(SPAKE2_M_HEX, '02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f');
  assert.equal(SPAKE2_N_HEX, '03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49');
});

test('same password agrees on Ke with random scalars', () => {
  const w = deriveW('brave-falcon-oyster');
  const a = spake2Start({ role: 'a', w });
  const b = spake2Start({ role: 'b', w });
  const fa = spake2Finish({ state: a, peerShare: b.share });
  const fb = spake2Finish({ state: b, peerShare: a.share });
  assert.ok(fa.ok && fb.ok);
  assert.equal(bytesToHex(fa.ke), bytesToHex(fb.ke));
  assert.ok(constantTimeEqual(fa.expectedPeerConfirm, fb.confirm));
});

test('wrong password: keys diverge and confirmation MACs do not verify', () => {
  const a = spake2Start({ role: 'a', w: deriveW('brave-falcon-oyster') });
  const b = spake2Start({ role: 'b', w: deriveW('brave-falcon-otter') });
  const fa = spake2Finish({ state: a, peerShare: b.share });
  const fb = spake2Finish({ state: b, peerShare: a.share });
  assert.ok(fa.ok && fb.ok); // failure only becomes VISIBLE at confirmation
  assert.notEqual(bytesToHex(fa.ke), bytesToHex(fb.ke));
  assert.ok(!constantTimeEqual(fa.expectedPeerConfirm, fb.confirm));
  assert.ok(!constantTimeEqual(fb.expectedPeerConfirm, fa.confirm));
});

test('peer share validation rejects identity, off-curve, and bad encodings', () => {
  const state = spake2Start({ role: 'a', w: deriveW('pw') });
  const bad = [
    new Uint8Array([0x00]), // SEC1 identity element
    new Uint8Array(65), // 65 zero bytes (prefix wrong AND not a point)
    hexToBytes(`04${'ff'.repeat(64)}`), // right shape, off-curve
    hexToBytes(SPAKE2_M_HEX), // valid point but compressed encoding — refused
    new Uint8Array(0),
    'not-bytes',
  ];
  for (const peerShare of bad) {
    const res = spake2Finish({ state, peerShare });
    assert.ok(!res.ok, `should reject ${peerShare?.length ?? typeof peerShare}`);
  }
});

test('a peer share crafted as exactly w*N (degenerate K) is rejected', async () => {
  const { p256 } = await import('@noble/curves/nist.js');
  const w = deriveW('pw');
  const a = spake2Start({ role: 'a', w });
  // a valid on-curve point, but pB - w*N would be the identity element
  const wN = p256.Point.fromHex(SPAKE2_N_HEX).multiply(w).toBytes(false);
  const res = spake2Finish({ state: a, peerShare: wN });
  assert.ok(!res.ok);
  assert.match(res.error, /degenerate/);
});

test('deriveW is deterministic, context-separated, and validates input', () => {
  const w1 = deriveW('brave-falcon-oyster');
  assert.equal(w1, deriveW('brave-falcon-oyster'));
  assert.notEqual(w1, deriveW('brave-falcon-oyster', 'other-context'));
  assert.notEqual(w1, deriveW('brave-falcon-otter'));
  assert.equal(typeof w1, 'bigint');
  assert.ok(w1 > 0n);
  assert.throws(() => deriveW(''));
  assert.throws(() => deriveW(42));
});

test('spake2Start validates role, w, and scalar ranges', () => {
  const w = deriveW('pw');
  assert.throws(() => spake2Start({ role: 'c', w }));
  assert.throws(() => spake2Start({ role: 'a', w: 0n }));
  assert.throws(() => spake2Start({ role: 'a', w: 'ff' }));
  assert.throws(() => spake2Start({ role: 'a', w, scalar: 0n }));
});

test('constantTimeEqual semantics', () => {
  const a = hexToBytes('00112233');
  assert.ok(constantTimeEqual(a, hexToBytes('00112233')));
  assert.ok(!constantTimeEqual(a, hexToBytes('00112234')));
  assert.ok(!constantTimeEqual(a, hexToBytes('001122')));
  assert.ok(!constantTimeEqual(a, '00112233'));
  assert.ok(constantTimeEqual(new Uint8Array(0), new Uint8Array(0)));
});
