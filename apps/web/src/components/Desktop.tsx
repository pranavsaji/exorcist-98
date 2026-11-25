'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { play, setSoundEnabled, soundEnabled } from '@/lib/sound';
import { parseDeepLink, shareQuery } from '@/lib/deeplink';
import { ExorcismPatch } from './ExorcismPatch';
import { ReportButtons } from './ReportButtons';
import { BookIcon, GhostIcon, InfoIcon, ShieldIcon, SkullIcon } from './Icons';
import { DesktopIcon } from './DesktopIcon';
import { FindingDetail } from './FindingDetail';
import { ResultsWindow } from './ResultsWindow';
import type { View } from './ResultsWindow';
import { ResultsSummary } from './ResultsSummary';
import { NextSteps } from './NextSteps';
import { ScanWindow } from './ScanWindow';
import { Taskbar } from './Taskbar';
import { Window } from './Window';
import { PossessionLab } from './PossessionLab';
import type { LabRequest } from './PossessionLab';
import { FieldReport } from './FieldReport';
import { BootScreen } from './BootScreen';
import { GuideGhost, GUIDE_TIPS } from './GuideGhost';
import { useScan } from '@/hooks/useScan';

type WinId = 'scan' | 'results' | 'detail' | 'lab' | 'field' | 'about';
type WinState = { open: boolean; minimized: boolean; z: number; x: number; y: number; w: number };

const TITLES: Record<WinId, string> = {
  lab:     'Possession Lab - Real-Time Shield',
  field:   'Field Report - Exorcist 98 in the Wild',
  scan:    'Exorcist 98 - Full System Scan',
  results: 'Threats Found',
  detail:  'Threat Details',
  about:   'About Exorcist 98',
};
const WIDTHS: Record<WinId, number> = { scan: 640, results: 640, detail: 640, lab: 980, field: 640, about: 440 };
const ICONS: Record<WinId, ReactNode> = {
  lab:     <ShieldIcon size={18} />,
  field:   <BookIcon size={18} />,
  scan:    <ShieldIcon size={18} />,
  results: <SkullIcon size={18} />,
  detail:  <InfoIcon size={18} />,
  about:   <GhostIcon size={18} />,
};

/** Width of the desktop-icon column; windows never start over it on a wide screen. */
const ICON_COL = 112;
const GAP = 12;

const INITIAL: Record<WinId, WinState> = {
  scan:    { open: true,  minimized: false, z: 10, x: 363, y: 56, w: WIDTHS.scan },
  results: { open: false, minimized: false, z: 1,  x: 764, y: 12, w: WIDTHS.results },
  detail:  { open: false, minimized: false, z: 1,  x: ICON_COL, y: 36, w: WIDTHS.detail },
  lab:     { open: false, minimized: false, z: 1,  x: 193, y: 10, w: WIDTHS.lab },
  field:   { open: false, minimized: false, z: 1,  x: 363, y: 40, w: WIDTHS.field },
  about:   { open: false, minimized: false, z: 1,  x: 463, y: 90, w: WIDTHS.about },
};
const ORDER: WinId[] = ['scan', 'results', 'detail', 'lab', 'field', 'about'];
const GUIDE_KEY = 'exorcist-98-welcome';
const HOW_KIRO = '/how-kiro';

function viewport(): { vw: number; vh: number } {
  return typeof window === 'undefined' ? { vw: 1366, vh: 768 } : { vw: window.innerWidth, vh: window.innerHeight };
}

/** Where a window opens: centred in the free desktop, clear of the icon column. */
function homeFor(id: WinId, vw: number, vh: number): Pick<WinState, 'x' | 'y' | 'w'> {
  const w = Math.min(WIDTHS[id], vw - 16);
  const x = Math.max(Math.min(ICON_COL, vw - w - 8), Math.round((vw - w) / 2));
  const y = id === 'scan' ? Math.max(12, Math.round((vh - 44) * 0.11)) : id === 'lab' ? 10 : id === 'about' ? 90 : 36;
  if (id === 'detail') return { x: ICON_COL, y: 36, w };
  return { x, y, w };
}

/** Once a scan starts: the scan window on the left, the results beside it. */
function tileForScan(vw: number): { scan: Pick<WinState, 'x' | 'y' | 'w'>; results: Pick<WinState, 'x' | 'y' | 'w'> } {
  const scan = { x: ICON_COL, y: 12, w: WIDTHS.scan };
  const rx = ICON_COL + WIDTHS.scan + GAP;
  const rw = Math.max(480, Math.min(WIDTHS.results, vw - rx - 8));
  return { scan, results: { x: Math.max(8, Math.min(rx, vw - rw - 8)), y: 12, w: rw } };
}

export function Desktop() {
  const { state, start, cancel } = useScan();
  const [wins, setWins] = useState<Record<WinId, WinState>>(INITIAL);
  const [ready, setReady] = useState(false);
  const [home, setHome] = useState(true);
  const [guideStep, setGuideStep] = useState<number | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [resultsView, setResultsView] = useState<View>('list');
  const [labRequest, setLabRequest] = useState<LabRequest | undefined>(undefined);
  const [prefill, setPrefill] = useState<string | undefined>(undefined);
  const [soundOn, setSoundOn] = useState(false); // muted by default (ui.md)
  const [possessed, setPossessed] = useState(false);
  const topZ = useRef(11);
  const labSeq = useRef(0);

  useEffect(() => setSoundOn(soundEnabled()), []);

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
    const { vw, vh } = viewport();
    setWins((w) => {
      const cur = w[id];
      // A window that was closed opens at its home spot; an open one stays where it was put.
      const at = cur.open ? { x: cur.x, y: cur.y, w: cur.w } : homeFor(id, vw, vh);
      // W-018: keep the whole window on screen.
      const maxX = Math.max(8, vw - at.w - 8);
      return { ...w, [id]: { ...cur, ...at, open: true, minimized: false, z, x: Math.min(at.x, maxX) } };
    });
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

  function closeGuide() {
    try { window.localStorage.setItem(GUIDE_KEY, 'dismissed'); } catch { /* private mode */ }
    setGuideStep(null);
  }

  function showGuide() {
    if (state.status !== 'running') setHome(true);
    open('scan');
    setGuideStep(0);
  }

  function openLab(req: Omit<LabRequest, 'seq'> = { tab: 'scripted' }) {
    labSeq.current += 1;
    setLabRequest({ ...req, seq: labSeq.current });
    open('lab');
  }

  /** Lay out the scan and results side by side, and put the scan in the address bar. */
  function beginScan(share: string | null) {
    setHome(false);
    if (guideStep !== null) closeGuide();
    setSelectedId(null);
    const { vw } = viewport();
    const tile = tileForScan(vw);
    topZ.current += 2;
    const z = topZ.current;
    setWins((w) => ({
      ...w,
      scan: { ...w.scan, ...tile.scan, open: true, minimized: false, z },
      results: { ...w.results, ...tile.results, open: true, minimized: false, z: z - 1 },
    }));
    if (share !== null) {
      try { window.history.replaceState(null, '', `${window.location.pathname}${share}`); } catch { /* sandboxed */ }
    }
  }

  function scanHaunted(view: View = 'list', share = shareQuery({ kind: 'haunted' })) {
    start({ target: 'haunted-repo' }, 'the Haunted Repo');
    setResultsView(view);
    beginScan(share);
  }

  function scanZip(file: File) {
    start({ file }, file.name);
    setResultsView('list');
    beginScan(shareQuery({ kind: 'zip' }));
  }

  function scanUrl(repoUrl: string, label: string) {
    start({ repoUrl }, label);
    setResultsView('list');
    beginScan(shareQuery({ kind: 'repo', url: repoUrl }));
  }

  // First load: lay out for this screen, then follow a shared link or show the guide.
  useEffect(() => {
    const { vw, vh } = viewport();
    setWins((w) => ({ ...w, scan: { ...w.scan, ...homeFor('scan', vw, vh) } }));
    setReady(true);
    const link = parseDeepLink(window.location.search);
    if (!link) {
      let dismissed = false;
      try { dismissed = window.localStorage.getItem(GUIDE_KEY) === 'dismissed'; } catch { /* keep showing it */ }
      if (!dismissed) setGuideStep(0);
      return;
    }
    switch (link.kind) {
      case 'repo':
        setPrefill(link.url);
        scanUrl(link.url, link.label);
        break;
      case 'haunted':
        scanHaunted();
        break;
      case 'lab':
        openLab({ tab: 'scripted', scenario: link.scenario, autoplay: true });
        break;
      case 'open':
        if (link.target === 'byoa') openLab({ tab: 'byoa' });
        else if (link.target === 'field') open('field');
        else scanHaunted('map', '?open=map');
        break;
    }
    // Runs once, on first load.
  }, []);

  function select(id: number) {
    setSelectedId(id);
    open('detail');
  }

  const selected = state.findings.find((f) => f.id === selectedId) ?? null;
  const openWins = ORDER.filter((id) => wins[id].open);
  const hero = home && state.status !== 'running';
  const showPatch = state.status === 'done' && state.patch !== null && state.findings.length > 0;
  const guideVisible = guideStep !== null && hero && ready && wins.scan.open && !wins.scan.minimized && activeId === 'scan';

  function toggleFromTaskbar(id: string) {
    const wid = id as WinId;
    const w = wins[wid];
    if (w.minimized) focus(wid);
    else if (activeId === wid) minimize(wid);
    else focus(wid);
  }

  const extras = (
    <nav aria-labelledby="more-title" className="hero-more">
      <p id="more-title" className="hero-more-title">More to explore</p>
      <ul className="hero-more-list">
        <li>
          <button type="button" className="chip" data-guide="lab" onClick={() => openLab({ tab: 'scripted' })}>
            <ShieldIcon size={18} /> Possession Lab
          </button>
        </li>
        <li>
          <button type="button" className="chip" onClick={() => openLab({ tab: 'byoa' })}>
            <SkullIcon size={18} /> Bring your own attack
          </button>
        </li>
        <li>
          <button type="button" className="chip" onClick={() => open('field')}>
            <BookIcon size={18} /> Field report
          </button>
        </li>
        <li>
          <a className="chip" href={HOW_KIRO} target="_blank" rel="noopener noreferrer">
            <GhostIcon size={18} /> How we used Kiro<span className="sr-only"> (opens in a new tab)</span>
          </a>
        </li>
      </ul>
    </nav>
  );

  return (
    <main
      className="relative h-screen w-screen overflow-hidden bg-desk"
      data-possessed={possessed ? 'true' : 'false'}
      data-ready={ready ? 'true' : 'false'}
    >
      <h1 className="sr-only">Exorcist 98: antivirus for AI coding agents</h1>
      <div className="desk-fog" aria-hidden="true" />
      <div className="desk-ghost" aria-hidden="true"><GhostIcon size={56} /></div>
      <div className="desk-wordmark" aria-hidden="true">
        <div className="text-4xl">EXORCIST 98</div>
        <span>ANTIVIRUS FOR AI AGENTS</span>
      </div>
      <div className="desk-scanlines" aria-hidden="true" />
      <div className="desk-vignette" aria-hidden="true" />

      <div className="desktop-icons absolute left-2 top-2 flex flex-col gap-1">
        <DesktopIcon label="Full System Scan" icon={<ShieldIcon />} onOpen={() => open('scan')} />
        <DesktopIcon label="Scan the Haunted Repo" icon={<SkullIcon />} onOpen={() => scanHaunted()} />
        <DesktopIcon label="Possession Lab" icon={<ShieldIcon />} onOpen={() => openLab()} />
        <DesktopIcon label="Field Report" icon={<BookIcon />} onOpen={() => open('field')} />
        <DesktopIcon label="Virus Definitions" icon={<BookIcon />} href="/encyclopedia" />
        <DesktopIcon label="How we used Kiro" icon={<GhostIcon />} href={HOW_KIRO} />
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
            width={w.w}
            z={w.z}
            active={activeId === id}
            minimized={w.minimized}
            revealed={ready}
            onFocus={(i) => focus(i as WinId)}
            onClose={(i) => close(i as WinId)}
            onMinimize={(i) => minimize(i as WinId)}
            onMove={(i, x, y) => move(i as WinId, x, y)}
          >
            {id === 'scan' && (
              <ScanWindow
                state={state}
                hero={hero}
                extras={extras}
                prefill={prefill}
                onHome={() => setHome(true)}
                onScanUrl={scanUrl}
                onScanZip={scanZip}
                onScanHaunted={() => scanHaunted()}
                onCancel={cancel}
                onShowResults={() => open('results')}
              />
            )}
            {id === 'results' && (
              <div className="flex flex-col gap-3">
                {state.status === 'done' && (
                  <ResultsSummary
                    findings={state.findings}
                    filesScanned={state.stats?.filesScanned ?? state.filesSeen}
                    onSelect={select}
                  />
                )}
                {state.status === 'done' && (
                  <section aria-labelledby="what-next" className="next-block">
                    <h3 id="what-next" className="next-heading">What to do next</h3>
                    {showPatch && state.patch && <ExorcismPatch patch={state.patch} target={state.target} />}
                    <ReportButtons findings={state.findings.map((f) => f.finding)} stats={state.stats} target={state.target} step={showPatch ? 2 : 1} />
                    <NextSteps step={showPatch ? 3 : 2} />
                  </section>
                )}
                <section aria-labelledby="all-threats" className="flex flex-col gap-2">
                  <h3 id="all-threats" className="next-heading">
                    {state.status === 'done' ? 'Every threat, worst first' : 'Threats so far'}
                  </h3>
                  <ResultsWindow
                    findings={state.findings}
                    selectedId={selectedId}
                    onSelect={select}
                    scanDone={state.status === 'done'}
                    map={state.map}
                    view={resultsView}
                    onViewChange={setResultsView}
                  />
                </section>
              </div>
            )}
            {id === 'detail' && <FindingDetail entry={selected} />}
            {id === 'lab' && <PossessionLab request={labRequest} />}
            {id === 'field' && <FieldReport />}
            {id === 'about' && (
              <div className="flex flex-col gap-2 text-sm">
                <p className="m-0">
                  Exorcist 98 brings back the 90s antivirus for a new kind of virus: text that gives orders to your AI
                  coding agent.
                </p>
                <p className="m-0">
                  It scans READMEs, steering files, MCP configs, hooks and install scripts. Every sample in the Haunted
                  Repo is defanged: fake addresses, placeholder secrets, nothing runs.
                </p>
                <p className="m-0 flex flex-wrap gap-x-3">
                  <a className="font-semibold underline" href="/encyclopedia" target="_blank" rel="noopener noreferrer">
                    Threat Encyclopedia (opens in a new tab)
                  </a>
                  <a className="font-semibold underline" href="/product">
                    What Exorcist 98 is for
                  </a>
                  <a className="font-semibold underline" href={HOW_KIRO} target="_blank" rel="noopener noreferrer">
                    How we used Kiro (opens in a new tab)
                  </a>
                </p>
              </div>
            )}
          </Window>
        );
      })}

      {guideVisible && guideStep !== null && (
        <GuideGhost
          step={guideStep}
          layoutKey={`${wins.scan.x},${wins.scan.y},${wins.scan.w}`}
          onNext={() => setGuideStep((s) => Math.min((s ?? 0) + 1, GUIDE_TIPS.length - 1))}
          onClose={closeGuide}
        />
      )}

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
          { label: 'Scan the Haunted Repo', icon: <SkullIcon size={18} />, onSelect: () => scanHaunted() },
          { label: 'Possession Lab (Real-Time Shield)', icon: <ShieldIcon size={18} />, onSelect: () => openLab() },
          { label: 'Bring your own attack', icon: <SkullIcon size={18} />, onSelect: () => openLab({ tab: 'byoa' }) },
          { label: 'Field Report (real repos)', icon: <BookIcon size={18} />, onSelect: () => open('field') },
          { label: 'Start here (guide)', icon: <GhostIcon size={18} />, onSelect: showGuide },
          { label: 'Virus Definitions', icon: <BookIcon size={18} />, href: '/encyclopedia' },
          { label: 'How we used Kiro', icon: <GhostIcon size={18} />, href: HOW_KIRO },
          { label: 'About Exorcist 98', icon: <GhostIcon size={18} />, onSelect: () => open('about') },
          { label: 'Product and plans', icon: <ShieldIcon size={18} />, href: '/product' },
        ]}
        onToggle={toggleFromTaskbar}
        soundOn={soundOn}
        onToggleSound={toggleSound}
      />
      <BootScreen />
    </main>
  );
}
