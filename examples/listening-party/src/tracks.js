// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
// Deterministic WebAudio chip-tune tracks + a beacon-drivable player.
//
// Why synthesized: every client renders IDENTICAL audio from the same score
// shipped with the page, so the demo needs no media files, no attachment
// plumbing, and no licensing question (we authored the scores — CC0 by
// construction). The OWM-STAGE sync model doesn't care where audio comes from:
// wm-playback-sync says "track T was at positionMs when the wall clock read
// atMs", and this player can start at ANY offset — which is exactly what a
// latecomer needs.
//
// Patterns are step predicates over a 64-step (4-bar) loop of 16th notes;
// the absolute step index k grows without bound, so positionMs is unbounded
// and the loop repeats — a "set", not a 3-minute file.

const noteHz = (midi) => 440 * 2 ** ((midi - 69) / 12);

export const TRACKS = [
  {
    id: 'neon-tide',
    title: 'Neon Tide',
    bpm: 96,
    steps: 64,
    // one chord per bar (16 steps), cycling
    chords: [[57, 60, 64], [53, 57, 60], [55, 60, 64], [55, 59, 62]], // Am F C G
    roots: [45, 41, 48, 43],
    kick: (i) => i % 16 === 0 || i % 16 === 10,
    snare: (i) => i % 16 === 8,
    hat: (i) => i % 4 === 2,
    bass: (i) => i % 16 === 0 || i % 16 === 6 || i % 16 === 12,
    arp: (i) => i % 4 === 0,
    arpOctave: 12,
    padGain: 0.05,
  },
  {
    id: 'block-party',
    title: 'Block Party',
    bpm: 122,
    steps: 64,
    chords: [[50, 53, 57, 60], [50, 53, 55, 59], [48, 52, 55, 59], [48, 52, 57, 60]], // Dm7 G7 Cmaj7 Am7
    roots: [38, 43, 36, 33],
    kick: (i) => i % 8 === 0 || i % 16 === 14,
    snare: (i) => i % 16 === 8,
    hat: (i) => i % 2 === 0,
    bass: (i) => [0, 3, 6, 10, 12].includes(i % 16),
    arp: (i) => [0, 3, 6, 11].includes(i % 8),
    arpOctave: 12,
    padGain: 0.035,
  },
  {
    id: 'satoshi-sunset',
    title: 'Satoshi Sunset',
    bpm: 84,
    steps: 64,
    chords: [[52, 55, 59], [48, 52, 55], [55, 59, 62], [50, 54, 57]], // Em C G D
    roots: [40, 36, 43, 38],
    kick: (i) => i % 16 === 0,
    snare: (i) => i % 32 === 24,
    hat: (i) => i % 8 === 4,
    bass: (i) => i % 16 === 0 || i % 16 === 10,
    arp: (i) => i % 8 === 2 || i % 8 === 6,
    arpOctave: 24,
    padGain: 0.07,
  },
];

export const trackById = (id) => TRACKS.find((t) => t.id === id) ?? null;

export function createPlayer(ctx) {
  // master chain: voices -> master gain -> gentle limiter -> speakers
  const master = ctx.createGain();
  master.gain.value = 0.85;
  const limiter = ctx.createDynamicsCompressor();
  limiter.threshold.value = -12;
  limiter.ratio.value = 8;
  master.connect(limiter).connect(ctx.destination);

  // one shared echo line for the lead (space without per-voice cost)
  const echoIn = ctx.createGain();
  const delay = ctx.createDelay(1);
  delay.delayTime.value = 0.28;
  const feedback = ctx.createGain();
  feedback.gain.value = 0.32;
  const echoTone = ctx.createBiquadFilter();
  echoTone.type = 'lowpass';
  echoTone.frequency.value = 2400;
  echoIn.connect(delay);
  delay.connect(echoTone);
  echoTone.connect(feedback).connect(delay);
  echoTone.connect(master);

  const noiseBuf = (() => {
    const buf = ctx.createBuffer(1, ctx.sampleRate * 0.25, ctx.sampleRate);
    const data = buf.getChannelData(0);
    for (let i = 0; i < data.length; i++) data[i] = Math.random() * 2 - 1;
    return buf; // noise is percussive texture — sample-level determinism doesn't matter for sync
  })();

  function env(t, peak, attack, decay) {
    const g = ctx.createGain();
    g.gain.setValueAtTime(0.0001, t);
    g.gain.linearRampToValueAtTime(peak, t + attack);
    g.gain.exponentialRampToValueAtTime(0.0001, t + attack + decay);
    g.connect(master);
    return g;
  }

  function kick(t) {
    const o = ctx.createOscillator();
    o.frequency.setValueAtTime(150, t);
    o.frequency.exponentialRampToValueAtTime(48, t + 0.12);
    o.connect(env(t, 0.5, 0.002, 0.16));
    o.start(t);
    o.stop(t + 0.2);
  }

  function noiseHit(t, peak, dur, filterType, freq) {
    const src = ctx.createBufferSource();
    src.buffer = noiseBuf;
    const f = ctx.createBiquadFilter();
    f.type = filterType;
    f.frequency.value = freq;
    src.connect(f).connect(env(t, peak, 0.001, dur));
    src.start(t);
    src.stop(t + dur + 0.02);
  }

  function bassVoice(t, midi, dur) {
    const o = ctx.createOscillator();
    o.type = 'triangle';
    o.frequency.value = noteHz(midi);
    const f = ctx.createBiquadFilter();
    f.type = 'lowpass';
    f.frequency.value = 700;
    o.connect(f).connect(env(t, 0.3, 0.008, dur));
    o.start(t);
    o.stop(t + dur + 0.05);
  }

  function lead(t, midi, dur) {
    const o = ctx.createOscillator();
    o.type = 'square';
    o.frequency.value = noteHz(midi);
    const g = env(t, 0.09, 0.004, dur);
    o.connect(g);
    const send = ctx.createGain();
    send.gain.value = 0.5;
    g.connect(send).connect(echoIn);
    o.start(t);
    o.stop(t + dur + 0.05);
  }

  function pad(t, chord, dur, peak) {
    for (const midi of chord) {
      for (const detune of [-5, 5]) {
        const o = ctx.createOscillator();
        o.type = 'sawtooth';
        o.frequency.value = noteHz(midi);
        o.detune.value = detune;
        const f = ctx.createBiquadFilter();
        f.type = 'lowpass';
        f.frequency.value = 1100;
        const g = ctx.createGain();
        g.gain.setValueAtTime(0.0001, t);
        g.gain.linearRampToValueAtTime(peak, t + 0.25);
        g.gain.setValueAtTime(peak, t + dur - 0.4);
        g.gain.exponentialRampToValueAtTime(0.0001, t + dur + 0.6);
        o.connect(f).connect(g).connect(master);
        o.start(t);
        o.stop(t + dur + 0.7);
      }
    }
  }

  let track = null;
  let anchor = 0; // ctx.currentTime at which position was 0
  let nextStep = 0;
  let timer = null;

  function scheduleStep(k, spb) {
    const t = anchor + k * spb;
    const i = k % track.steps;
    const bar = Math.floor(i / 16);
    const chord = track.chords[bar % track.chords.length];
    if (track.kick(i)) kick(t);
    if (track.snare(i)) noiseHit(t, 0.18, 0.1, 'bandpass', 1800);
    if (track.hat(i)) noiseHit(t, 0.08, 0.04, 'highpass', 6500);
    if (track.bass(i)) bassVoice(t, track.roots[bar % track.roots.length], spb * 2.5);
    if (track.arp(i)) lead(t, chord[Math.floor(k / 2) % chord.length] + track.arpOctave, spb * 1.8);
    if (i % 16 === 0) pad(t, chord, spb * 16, track.padGain);
  }

  function pump() {
    const spb = 60 / track.bpm / 4;
    const horizon = ctx.currentTime + 0.35;
    while (anchor + nextStep * spb < horizon) {
      scheduleStep(nextStep, spb);
      nextStep += 1;
    }
  }

  return {
    get playing() { return timer !== null; },
    get track() { return track; },
    positionMs() {
      if (!track) return 0;
      return Math.max(0, Math.round((ctx.currentTime - anchor) * 1000));
    },
    // Start `t` so that "now" corresponds to offsetMs into the set.
    play(t, offsetMs = 0) {
      this.stop();
      track = t;
      anchor = ctx.currentTime - offsetMs / 1000;
      const spb = 60 / t.bpm / 4;
      nextStep = Math.max(0, Math.ceil((ctx.currentTime - anchor) / spb));
      pump();
      timer = setInterval(pump, 90);
    },
    // Stop scheduling; already-scheduled voices (≤0.35 s + pad tail) ring out.
    stop() {
      if (timer) clearInterval(timer);
      timer = null;
    },
  };
}
