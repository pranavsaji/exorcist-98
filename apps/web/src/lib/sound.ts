'use client';

/**
 * Original sound effects, synthesised with the Web Audio API (no audio files,
 * no third-party assets). Muted by default; the choice is stored locally.
 */
export type Cue = 'threat' | 'done-clean' | 'done-infected' | 'boot';

const KEY = 'exorcist-98-sound';

export function soundEnabled(): boolean {
  try { return window.localStorage.getItem(KEY) === 'on'; } catch { return false; }
}

export function setSoundEnabled(on: boolean): void {
  try { window.localStorage.setItem(KEY, on ? 'on' : 'off'); } catch { /* private mode: keep it in memory only */ }
}

type Note = { freq: number; start: number; dur: number; type?: OscillatorType; gain?: number; slideTo?: number };

/** The notes for each cue. Exported so tests can check them without audio. */
export const CUES: Record<Cue, Note[]> = {
  // A falling, wobbly "ghost" moan.
  threat: [
    { freq: 520, slideTo: 260, start: 0, dur: 0.28, type: 'triangle', gain: 0.18 },
    { freq: 390, slideTo: 196, start: 0.05, dur: 0.3, type: 'sine', gain: 0.1 },
  ],
  // Two rising notes: all clear.
  'done-clean': [
    { freq: 523, start: 0, dur: 0.12, type: 'square', gain: 0.06 },
    { freq: 784, start: 0.12, dur: 0.18, type: 'square', gain: 0.06 },
  ],
  // A low three-note warning.
  'done-infected': [
    { freq: 220, start: 0, dur: 0.16, type: 'sawtooth', gain: 0.07 },
    { freq: 196, start: 0.17, dur: 0.16, type: 'sawtooth', gain: 0.07 },
    { freq: 147, start: 0.34, dur: 0.3, type: 'sawtooth', gain: 0.07 },
  ],
  boot: [
    { freq: 392, start: 0, dur: 0.1, type: 'square', gain: 0.05 },
    { freq: 523, start: 0.1, dur: 0.1, type: 'square', gain: 0.05 },
    { freq: 659, start: 0.2, dur: 0.22, type: 'square', gain: 0.05 },
  ],
};

let ctx: AudioContext | null = null;
let lastThreat = 0;

export function play(cue: Cue): void {
  if (typeof window === 'undefined' || !soundEnabled()) return;
  const now = Date.now();
  if (cue === 'threat') {
    if (now - lastThreat < 350) return; // a burst of findings is one sound, not a wall of noise
    lastThreat = now;
  }
  try {
    const Ctor = window.AudioContext ?? (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!Ctor) return;
    ctx ??= new Ctor();
    const t0 = ctx.currentTime + 0.01;
    for (const n of CUES[cue]) {
      const osc = ctx.createOscillator();
      const g = ctx.createGain();
      osc.type = n.type ?? 'sine';
      osc.frequency.setValueAtTime(n.freq, t0 + n.start);
      if (n.slideTo) osc.frequency.exponentialRampToValueAtTime(n.slideTo, t0 + n.start + n.dur);
      g.gain.setValueAtTime(0.0001, t0 + n.start);
      g.gain.exponentialRampToValueAtTime(n.gain ?? 0.1, t0 + n.start + 0.02);
      g.gain.exponentialRampToValueAtTime(0.0001, t0 + n.start + n.dur);
      osc.connect(g).connect(ctx.destination);
      osc.start(t0 + n.start);
      osc.stop(t0 + n.start + n.dur + 0.02);
    }
  } catch {
    /* audio is optional */
  }
}
