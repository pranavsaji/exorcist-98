'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { play, setSoundEnabled, soundEnabled } from '@/lib/sound';
import { ExorcismPatch } from './ExorcismPatch';
import { ReportButtons } from './ReportButtons';
import { BookIcon, GhostIcon, InfoIcon, ShieldIcon, SkullIcon } from './Icons';
import { DesktopIcon } from './DesktopIcon';
import { FindingDetail } from './FindingDetail';
import { ResultsWindow } from './ResultsWindow';
import { NextSteps } from './NextSteps';
import { ScanWindow } from './ScanWindow';
import { Taskbar } from './Taskbar';
import { Window } from './Window';
import { PossessionLab } from './PossessionLab';
import { Welcome } from './Welcome';
import { FieldReport } from './FieldReport';
import { useScan } from '@/hooks/useScan';

type WinId = 'welcome' | 'scan' | 'results' | 'detail' | 'lab' | 'field' | 'about';
type WinState = { open: boolean; minimized: boolean; z: number; x: number; y: number };

const TITLES: Record<WinId, string> = {
  welcome: 'Welcome to Exorcist 98',
  lab:     'Possession Lab - Real-Time Shield',
  field:   'Field Report - Exorcist 98 in the Wild',
  scan:    'Exorcist 98 - Full System Scan',
  results: 'Threats Found',
  detail:  'Threat Details',
  about:   'About Exorcist 98',
};
const WIDTHS: Record<WinId, number> = { welcome: 520, scan: 600, results: 480, detail: 620, lab: 980, field: 640, about: 420 };
const ICONS: Record<WinId, ReactNode> = {
  welcome: <GhostIcon size={18} />,
  lab:     <ShieldIcon size={18} />,
  field:   <BookIcon size={18} />,
  scan:    <ShieldIcon size={18} />,
  results: <SkullIcon size={18} />,
  detail:  <InfoIcon size={18} />,
  about:   <GhostIcon size={18} />,
};

const INITIAL: Record<WinId, WinState> = {
  welcome: { open: true,  minimized: false, z: 11, x: 760, y: 40 },
  lab:     { open: false, minimized: false, z: 1,  x: 110, y: 10 },
  field:   { open: false, minimized: false, z: 1,  x: 240, y: 30 },
  scan:    { open: true,  minimized: false, z: 10, x: 130, y: 16 },
  results: { open: false, minimized: false, z: 1,  x: 750, y: 16 },
  detail:  { open: false, minimized: false, z: 1,  x: 260, y: 150 },
  about:   { open: false, minimized: false, z: 1,  x: 400, y: 90 },
};
const ORDER: WinId[] = ['scan', 'results', 'detail', 'lab', 'field', 'about', 'welcome'];
const WELCOME_KEY = 'exorcist-98-welcome';

export function Desktop() {
  const { state, start, cancel } = useScan();
  const [wins, setWins] = useState<Record<WinId, WinState>>(INITIAL);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [soundOn, setSoundOn] = useState(false); // muted by default (ui.md)
  const [possessed, setPossessed] = useState(false);
  const topZ = useRef(11);

  useEffect(() => setSoundOn(soundEnabled()), []);

  // The tour shows until it is dismissed once (per browser; storage may be unavailable).
  useEffect(() => {
    let dismissed = false;
    try { dismissed = window.localStorage.getItem(WELCOME_KEY) === 'dismissed'; } catch { /* keep showing it */ }
    if (dismissed) setWins((w) => ({ ...w, welcome: { ...w.welcome, open: false } }));
  }, []);

  function dismissWelcome() {
    try { window.localStorage.setItem(WELCOME_KEY, 'dismissed'); } catch { /* private mode */ }
    setWins((w) => ({ ...w, welcome: { ...w.welcome, open: false } }));
  }

  // A ghost moan per threat (throttled in play) and a chime when a scan ends.
  useEffect(() => {
    if (state.threatSeq > 0) play('threat');
  }, [state.threatSeq]);
  const prevStatus = useRef(state.status);
  useEffect(() => {
    if (prevStatus.current === 'running' && state.status === 'done') {
      play(state.findings.length > 0 ? 'done-infected' : 'done-clean');
      // A critical threat possesses the whole desktop for a moment.
      if (state.findings.some((f) => f.finding.severity === 'critical')) {
        setPossessed(true);
        setTimeout(() => setPossessed(false), 1400);
      }
    }
    prevStatus.current = state.status;
  }, [state.status, state.findings.length]);

  function toggleSound() {
    const next = !soundOn;
    setSoundEnabled(next);
    setSoundOn(next);
    if (next) play('boot');
  }

  const focus = useCallback((id: WinId) => {
    topZ.current += 1;
    const z = topZ.current;
    setWins((w) => ({ ...w, [id]: { ...w[id], z, minimized: false } }));
  }, []);

  const open = useCallback((id: WinId) => {
    topZ.current += 1;
    const z = topZ.current;
    // W-018: keep the whole window on screen. At 1024 px the results window
    // used to open at x=750 with more than half of it past the right edge.
    const vw = typeof window === 'undefined' ? 1366 : window.innerWidth;
    const maxX = Math.max(8, vw - WIDTHS[id] - 8);
    setWins((w) => ({ ...w, [id]: { ...w[id], open: true, minimized: false, z, x: Math.min(w[id].x, maxX) } }));
  }, []);

  const close = useCallback((id: WinId) => {
    setWins((w) => ({ ...w, [id]: { ...w[id], open: false } }));
  }, []);

  const minimize = useCallback((id: WinId) => {
    setWins((w) => ({ ...w, [id]: { ...w[id], minimized: true } }));
  }, []);

  const move = useCallback((id: WinId, x: number, y: number) => {
    setWins((w) => ({ ...w, [id]: { ...w[id], x, y } }));
  }, []);

  const activeId = useMemo<WinId | null>(() => {
    let best: WinId | null = null;
    for (const id of ORDER) {
      const w = wins[id];
      if (w.open && !w.minimized && (best === null || w.z > wins[best].z)) best = id;
    }
    return best;
  }, [wins]);

  function openLab() {
    open('lab');
  }

  function scanHaunted() {
    start({ target: 'haunted-repo' }, 'the Haunted Repo');
    setSelectedId(null);
    open('results');
    open('scan');
  }

  function scanZip(file: File) {
    start({ file }, file.name);
    setSelectedId(null);
    open('results');
    open('scan');
  }
  function scanUrl(repoUrl: string, label: string) {
    start({ repoUrl }, label);
    setSelectedId(null);
    open('results');
    open('scan');
  }

  function select(id: number) {
    setSelectedId(id);
    open('detail');
  }

  const selected = state.findings.find((f) => f.id === selectedId) ?? null;
  const openWins = ORDER.filter((id) => wins[id].open);

  function toggleFromTaskbar(id: string) {
    const wid = id as WinId;
    const w = wins[wid];
    if (w.minimized) focus(wid);
    else if (activeId === wid) minimize(wid);
    else focus(wid);
  }

  return (
    <main className="relative h-screen w-screen overflow-hidden bg-desk" data-possessed={possessed ? 'true' : 'false'}>
      <h1 className="sr-only">Exorcist 98: antivirus for AI coding agents</h1>
      <div className="desk-fog" aria-hidden="true" />
      <div className="desk-ghost" aria-hidden="true"><GhostIcon size={56} /></div>
      <div className="desk-wordmark" aria-hidden="true">
        <div className="text-4xl">EXORCIST 98</div>
        <span>ANTIVIRUS FOR AI AGENTS</span>
      </div>
      <div className="desk-scanlines" aria-hidden="true" />

      <div className="desktop-icons absolute left-2 top-2 flex flex-col gap-1">
        <DesktopIcon label="Full System Scan" icon={<ShieldIcon />} onOpen={() => open('scan')} />
        <DesktopIcon label="Scan the Haunted Repo" icon={<SkullIcon />} onOpen={scanHaunted} />
        <DesktopIcon label="Possession Lab" icon={<ShieldIcon />} onOpen={openLab} />
        <DesktopIcon label="Field Report" icon={<BookIcon />} onOpen={() => open('field')} />
        <DesktopIcon label="Virus Definitions" icon={<BookIcon />} href="/encyclopedia" />
        <DesktopIcon label="About" icon={<GhostIcon />} onOpen={() => open('about')} />
      </div>

      {ORDER.map((id) => {
        const w = wins[id];
        if (!w.open) return null;
        return (
          <Window
            key={id}
            id={id}
            title={TITLES[id]}
            icon={ICONS[id]}
            x={w.x}
            y={w.y}
            width={WIDTHS[id]}
            z={w.z}
            active={activeId === id}
            minimized={w.minimized}
            onFocus={(i) => focus(i as WinId)}
            onClose={(i) => close(i as WinId)}
            onMinimize={(i) => minimize(i as WinId)}
            onMove={(i, x, y) => move(i as WinId, x, y)}
          >
            {id === 'scan' && (
              <ScanWindow
                state={state}
                onScanUrl={scanUrl}
                onScanZip={scanZip}
                onScanHaunted={scanHaunted}
                onCancel={cancel}
                onShowResults={() => open('results')}
              />
            )}
            {id === 'results' && (
              <div className="flex flex-col gap-2">
                <ResultsWindow findings={state.findings} selectedId={selectedId} onSelect={select} scanDone={state.status === 'done'} map={state.map} />
                {state.status === 'done' && state.patch && state.findings.length > 0 && (
                  <ExorcismPatch patch={state.patch} target={state.target} />
                )}
                {state.status === 'done' && (
                  <ReportButtons findings={state.findings.map((f) => f.finding)} stats={state.stats} target={state.target} />
                )}
                {state.status === 'done' && <NextSteps />}
              </div>
            )}
            {id === 'detail' && <FindingDetail entry={selected} />}
            {id === 'lab' && <PossessionLab />}
            {id === 'field' && <FieldReport />}
            {id === 'welcome' && (
              <Welcome
                onScanHaunted={() => { scanHaunted(); }}
                onOpenLab={openLab}
                onOpenField={() => open('field')}
                onDismiss={dismissWelcome}
              />
            )}
            {id === 'about' && (
              <div className="flex flex-col gap-2 text-sm">
                <p className="m-0">
                  Exorcist 98 brings back the 90s antivirus for a new kind of computer virus:
                  text that talks to your AI coding agent.
                </p>
                <p className="m-0">
                  It scans READMEs, steering files, MCP configs, hooks and install scripts for hidden
                  instructions, poisoned tool descriptions and risky settings.
                </p>
                <p className="m-0">
                  Every sample in the Haunted Repo is defanged: it uses example.invalid addresses and
                  placeholder secrets, and nothing in it can run.
                </p>
                <p className="m-0 flex flex-wrap gap-x-3">
                  <a className="font-semibold underline" href="/encyclopedia" target="_blank" rel="noopener noreferrer">
                    Browse the Threat Encyclopedia (opens in a new tab)
                  </a>
                  <a className="font-semibold underline" href="/product">
                    What Exorcist 98 is for
                  </a>
                </p>
              </div>
            )}
          </Window>
        );
      })}

      <Taskbar
        windows={openWins.map((id) => ({
          id,
          title: TITLES[id],
          icon: ICONS[id],
          active: activeId === id,
          minimized: wins[id].minimized,
        }))}
        items={[
          { label: 'Full System Scan', icon: <ShieldIcon size={18} />, onSelect: () => open('scan') },
          { label: 'Scan the Haunted Repo', icon: <SkullIcon size={18} />, onSelect: scanHaunted },
          { label: 'Possession Lab (Real-Time Shield)', icon: <ShieldIcon size={18} />, onSelect: openLab },
          { label: 'Field Report (real repos)', icon: <BookIcon size={18} />, onSelect: () => open('field') },
          { label: 'Start here (tour)', icon: <GhostIcon size={18} />, onSelect: () => open('welcome') },
          { label: 'Virus Definitions', icon: <BookIcon size={18} />, href: '/encyclopedia' },
          { label: 'About Exorcist 98', icon: <GhostIcon size={18} />, onSelect: () => open('about') },
          { label: 'Product and plans', icon: <ShieldIcon size={18} />, href: '/product' },
        ]}
        onToggle={toggleFromTaskbar}
        soundOn={soundOn}
        onToggleSound={toggleSound}
      />
    </main>
  );
}
