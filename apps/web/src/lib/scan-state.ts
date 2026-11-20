import { plainFor } from './plain';
import { SEVERITY_INFO } from './severity';
import type { ScanEventMsg, Snippet, WebFinding, WebScanStats } from './protocol';

export type LogKind = 'info' | 'file' | 'threat' | 'error';
export type LogLine = { id: number; kind: LogKind; text: string };
export type FindingEntry = { id: number; finding: WebFinding; snippet: Snippet };
export type ScanStatus = 'idle' | 'running' | 'done' | 'failed' | 'cancelled';

export type ScanState = {
  status:        ScanStatus;
  target:        string;
  log:           LogLine[];
  findings:      FindingEntry[];
  filesSeen:     number;
  /** Files the scan will look at, once the server has counted them. */
  totalFiles:    number | null;
  stats:         WebScanStats | null;
  /** Increments once per finding so the UI can retrigger the glitch effect. */
  threatSeq:     number;
  notice:        string | null;
  nextId:        number;
};

export const MAX_LOG_LINES = 400;

export const initialScanState: ScanState = {
  status: 'idle',
  target: '',
  log: [],
  findings: [],
  filesSeen: 0,
  totalFiles: null,
  stats: null,
  threatSeq: 0,
  notice: null,
  nextId: 1,
};

export type ScanAction =
  | { type: 'reset'; target: string }
  | { type: 'event'; event: ScanEventMsg }
  | { type: 'failed'; message: string }
  | { type: 'cancelled' };

function addLog(state: ScanState, kind: LogKind, text: string): Pick<ScanState, 'log' | 'nextId'> {
  const line: LogLine = { id: state.nextId, kind, text };
  const log = [...state.log, line];
  return {
    log: log.length > MAX_LOG_LINES ? log.slice(-MAX_LOG_LINES) : log,
    nextId: state.nextId + 1,
  };
}

export function scanReducer(state: ScanState, action: ScanAction): ScanState {
  switch (action.type) {
    case 'reset': {
      const base: ScanState = { ...initialScanState, status: 'running', target: action.target };
      return { ...base, ...addLog(base, 'info', `Starting scan of ${action.target}...`) };
    }
    case 'cancelled':
      return { ...state, status: 'cancelled', ...addLog(state, 'info', 'Scan cancelled.') };
    case 'failed':
      return {
        ...state,
        status: 'failed',
        notice: action.message,
        ...addLog(state, 'error', action.message),
      };
    case 'event': {
      const ev = action.event;
      switch (ev.type) {
        case 'start':
          return state;
        case 'total':
          return { ...state, totalFiles: ev.files };
        case 'file':
          return {
            ...state,
            filesSeen: state.filesSeen + 1,
            ...addLog(state, 'file', `scanning ${ev.rel}`),
          };
        case 'finding': {
          const f = ev.finding;
          const entry: FindingEntry = { id: state.nextId, finding: f, snippet: ev.snippet };
          const headline = plainFor(f.ruleId, f.title).headline;
          const text = `[${SEVERITY_INFO[f.severity].label}] ${f.ruleId} ${f.file}:${f.line}  ${headline}`;
          const logged = addLog({ ...state, nextId: state.nextId + 1 }, 'threat', text);
          return {
            ...state,
            findings: [...state.findings, entry],
            threatSeq: state.threatSeq + 1,
            ...logged,
          };
        }
        case 'error':
          return {
            ...state,
            notice: ev.file === '' ? ev.message : state.notice,
            ...addLog(state, 'error', ev.file === '' ? ev.message : `could not read ${ev.file}`),
          };
        case 'done':
          return {
            ...state,
            status: 'done',
            stats: ev.stats,
            ...addLog(
              state,
              'info',
              `Scan complete: ${ev.stats.filesScanned} files, ${ev.stats.findingsTotal} threats, ${Math.round(ev.stats.durationMs)} ms.`,
            ),
          };
        case 'fatal':
          return {
            ...state,
            status: 'failed',
            notice: ev.message,
            ...addLog(state, 'error', ev.message),
          };
      }
    }
  }
}
