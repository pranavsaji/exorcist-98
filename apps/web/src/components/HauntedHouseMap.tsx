'use client';

import { useId, useState } from 'react';
import { SeverityBadge } from './SeverityBadge';
import type { Capability, ConfigMapMsg, HauntedMapMsg, MapGhostMsg } from '@/lib/protocol';

// The Haunted House Map (m5-trifecta, REQ-03.2): the three rooms of the
// lethal trifecta, with each MCP server drawn as a ghost in the room(s) its
// powers open. The drawing is a picture; the list under it says everything
// the picture shows, in words, and is what screen readers read.

export type Room = {
  cap:   Capability;
  name:  string;
  power: string;
  /** What a ghost in this room can do, in plain words. */
  means: string;
};

export const ROOMS: readonly Room[] = [
  { cap: 'private-data',    name: 'Vault of Secrets', power: 'private data',    means: 'can read private data' },
  { cap: 'untrusted-input', name: 'Open Door',        power: 'untrusted input', means: 'reads text anyone can write' },
  { cap: 'exfiltration',    name: 'Escape Tunnel',    power: 'a way out',       means: 'can send data out' },
];

const MAX_GHOSTS_DRAWN = 4;

type Box = { x: number; y: number; w: number; h: number };
const BOX: Record<Capability, Box> = {
  'private-data':    { x: 112, y: 114, w: 176, h: 104 },
  'untrusted-input': { x: 36,  y: 264, w: 160, h: 100 },
  exfiltration:      { x: 204, y: 264, w: 160, h: 100 },
};
const BAND: Record<Capability, string> = {
  'private-data':    '#ffd93c',
  'untrusted-input': '#8dffb4',
  exfiltration:      '#e7c2ff',
};

const clip = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

/** One sentence that says what the map shows. */
export function mapSummary(c: ConfigMapMsg): string {
  if (c.trifecta) {
    return `Lethal trifecta in ${c.file}: all three rooms are haunted. ${ROOMS.map((r) => `${r.name}: ${c.legs[r.cap].join(', ')}`).join('. ')}.`;
  }
  const empty = ROOMS.filter((r) => c.legs[r.cap].length === 0).map((r) => r.name);
  return `No trifecta in ${c.file}: the ${empty.join(', ')} ${empty.length === 1 ? 'room is' : 'rooms are'} empty.`;
}

function RoomIcon({ cap, x, y }: { cap: Capability; x: number; y: number }) {
  // Small pictograms in the room's title band: a keyhole, an open door, an arrow out of an arch.
  if (cap === 'private-data') {
    return (
      <g transform={`translate(${x} ${y})`} aria-hidden="true">
        <circle cx="6" cy="5" r="3.4" fill="#120b22" />
        <path d="M4.6 6.5h2.8l1 6h-4.8z" fill="#120b22" />
      </g>
    );
  }
  if (cap === 'untrusted-input') {
    return (
      <g transform={`translate(${x} ${y})`} aria-hidden="true">
        <rect x="0.5" y="0.5" width="11" height="13" fill="none" stroke="#120b22" strokeWidth="1.4" />
        <path d="M1.2 1.2 7.5 3v10.6l-6.3-1.4z" fill="#120b22" />
      </g>
    );
  }
  return (
    <g transform={`translate(${x} ${y})`} aria-hidden="true">
      <path d="M0.8 13.5V6a5.2 5.2 0 0 1 10.4 0v7.5" fill="none" stroke="#120b22" strokeWidth="1.4" />
      <path d="M4 9.5h7M8.5 6.8 11.4 9.5 8.5 12.2" fill="none" stroke="#120b22" strokeWidth="1.6" />
    </g>
  );
}

function Ghost({ x, y, auto }: { x: number; y: number; auto: boolean }) {
  return (
    <g transform={`translate(${x} ${y})`} aria-hidden="true">
      {/* The inner group floats (CSS); the outer one holds the position. */}
      <g className="map-ghost">
        <path d="M1 13V6.2a5 5 0 0 1 10 0V13l-1.7-1.6L7.7 13 6 11.3 4.3 13l-1.6-1.6z" fill="#ffffff" stroke="#120b22" strokeWidth="1" />
        <rect x="3.4" y="5" width="1.6" height="2.4" fill="#120b22" />
        <rect x="7" y="5" width="1.6" height="2.4" fill="#120b22" />
        {auto && <path d="M10.5 0.5 8 5h2.2l-1.4 4 3.7-5H10.3l1.4-3.5z" fill="#ff3b6b" stroke="#120b22" strokeWidth="0.6" />}
      </g>
    </g>
  );
}

function RoomDrawing({ room, ghosts }: { room: Room; ghosts: MapGhostMsg[] }) {
  const b = BOX[room.cap];
  const haunted = ghosts.length > 0;
  // Four ghosts fit; with more, three and a "+N more" line.
  const shown = ghosts.length <= MAX_GHOSTS_DRAWN ? ghosts : ghosts.slice(0, MAX_GHOSTS_DRAWN - 1);
  const more = ghosts.length - shown.length;
  const maxChars = room.cap === 'private-data' ? 20 : 18;
  return (
    <g data-room={room.cap} data-haunted={haunted ? 'true' : 'false'}>
      <rect
        x={b.x} y={b.y} width={b.w} height={b.h}
        fill={haunted ? '#f4f0fa' : '#3a2d55'}
        stroke={haunted ? '#120b22' : '#b6a9d6'}
        strokeWidth="2"
        strokeDasharray={haunted ? undefined : '5 4'}
      />
      <rect x={b.x + 1} y={b.y + 1} width={b.w - 2} height="20" fill={haunted ? BAND[room.cap] : '#4b3d6b'} />
      <text x={b.x + 8} y={b.y + 15} fontSize="11" fontWeight="800" letterSpacing="0.06em" fill={haunted ? '#120b22' : '#f4f0fa'}>
        {room.name.toUpperCase()}
      </text>
      {haunted && <RoomIcon cap={room.cap} x={b.x + b.w - 18} y={b.y + 4} />}
      {!haunted && (
        <>
          <text x={b.x + b.w / 2} y={b.y + 56} fontSize="11" textAnchor="middle" fill="#f4f0fa">no ghost here</text>
          <text x={b.x + b.w / 2} y={b.y + 72} fontSize="10" textAnchor="middle" fill="#d9d0ec">this room is sealed</text>
        </>
      )}
      {shown.map((g, i) => (
        <g key={`${g.kind}:${g.name}`}>
          <Ghost x={b.x + 8} y={b.y + 27 + i * 17} auto={g.autoApproved} />
          <text x={b.x + 26} y={b.y + 38 + i * 17} fontSize="11" fill="#120b22" fontFamily="ui-monospace, Menlo, Consolas, monospace">
            {clip(g.name, maxChars)}
          </text>
        </g>
      ))}
      {more > 0 && (
        <text x={b.x + 26} y={b.y + 38 + shown.length * 17} fontSize="10" fontStyle="italic" fill="#120b22">
          +{more} more (see list)
        </text>
      )}
    </g>
  );
}

function HouseDrawing({ config, titleId, descId }: { config: ConfigMapMsg; titleId: string; descId: string }) {
  const inRoom = (cap: Capability) => config.ghosts.filter((g) => g.capabilities.includes(cap));
  const lethal = config.trifecta;
  return (
    <svg
      className="map-svg"
      viewBox="0 0 400 384"
      role="img"
      aria-labelledby={`${titleId} ${descId}`}
      data-trifecta={lethal ? 'true' : 'false'}
    >
      <title id={titleId}>{`Haunted House Map of ${config.file}`}</title>
      <desc id={descId}>{mapSummary(config)}</desc>
      <defs>
        <marker id={`${titleId}-arrow`} viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0 0 10 5 0 10z" fill="#ff7a9c" />
        </marker>
      </defs>
      {/* Night sky, moon, house. */}
      <rect x="0" y="0" width="400" height="384" fill="#1a1030" />
      <circle cx="350" cy="34" r="16" fill="#f4f0fa" />
      <circle cx="357" cy="29" r="14" fill="#1a1030" />
      <circle cx="54" cy="30" r="1.4" fill="#f4f0fa" />
      <circle cx="92" cy="54" r="1" fill="#f4f0fa" />
      <circle cx="300" cy="16" r="1.2" fill="#f4f0fa" />
      <rect x="292" y="38" width="20" height="44" fill="#2b1d4a" stroke="#120b22" strokeWidth="2" />
      <polygon points="16,104 200,20 384,104" fill="#3a2560" stroke="#120b22" strokeWidth="2" />
      <circle cx="200" cy="72" r="13" fill={lethal ? '#ff3b6b' : '#ffd93c'} stroke="#120b22" strokeWidth="2" />
      <path d="M200 59v26M187 72h26" stroke="#120b22" strokeWidth="2" />
      <rect x="24" y="104" width="352" height="272" fill="#2b1d4a" stroke="#120b22" strokeWidth="2" />

      {ROOMS.map((r) => <RoomDrawing key={r.cap} room={r} ghosts={inRoom(r.cap)} />)}

      {lethal ? (
        <g data-trifecta-path="true">
          {/* 1: orders come in through the Open Door, 2: the Vault is read, 3: data leaves by the Escape Tunnel. */}
          <path d="M116 264 C116 240 124 230 140 220" fill="none" stroke="#ff7a9c" strokeWidth="2.5" strokeDasharray="6 4" markerEnd={`url(#${titleId}-arrow)`} />
          <path d="M260 220 C276 230 284 240 284 262" fill="none" stroke="#ff7a9c" strokeWidth="2.5" strokeDasharray="6 4" markerEnd={`url(#${titleId}-arrow)`} />
          <path d="M364 330 H394" fill="none" stroke="#ff7a9c" strokeWidth="2.5" strokeDasharray="6 4" markerEnd={`url(#${titleId}-arrow)`} />
          <text x="44" y="240" fontSize="10" fontWeight="700" fill="#ffd1dc">1 orders in</text>
          <text x="292" y="240" fontSize="10" fontWeight="700" fill="#ffd1dc">2 secrets out</text>
          <text x="200" y="252" fontSize="10" fontWeight="800" textAnchor="middle" fill="#ffd1dc" letterSpacing="0.08em">LETHAL TRIFECTA</text>
        </g>
      ) : (
        <text x="200" y="246" fontSize="10" fontWeight="700" textAnchor="middle" fill="#d9d0ec">not all three rooms are haunted</text>
      )}
    </svg>
  );
}

function GhostLine({ g }: { g: MapGhostMsg }) {
  const labels = [...new Set(g.reasons.map((r) => r.label))];
  return (
    <li>
      <span className="font-mono font-semibold">{g.name}</span>
      {g.kind === 'ability' && ' (built-in ability)'}
      {labels.length > 0 && `: ${labels.join('; ')}`}
      {g.autoApproved && (
        <>
          {' '}
          <span className="map-auto">AUTO-APPROVED</span> runs without asking you
        </>
      )}
    </li>
  );
}

function ConfigView({ config }: { config: ConfigMapMsg }) {
  const base = useId().replace(/:/g, '');
  const quiet = config.ghosts.filter((g) => g.capabilities.length === 0);
  return (
    <div className="flex flex-col gap-2">
      <p className="m-0 flex flex-wrap items-center gap-2 text-sm" data-testid="map-status">
        {config.trifecta && config.severity ? (
          <>
            <SeverityBadge severity={config.severity} />
            <strong>Lethal trifecta: all three rooms are haunted.</strong>
            <span>One poisoned page, issue or message could make your AI read secrets and send them out (EX-023).</span>
          </>
        ) : (
          <>
            <span className="sev sev-clean" data-severity="clean">
              <svg width="12" height="12" viewBox="0 0 16 16" aria-hidden="true" focusable="false" data-shape="check">
                <path d="M3 8.5l3.2 3.2L13 5" fill="none" stroke="currentColor" strokeWidth="2.4" />
              </svg>
              NO TRIFECTA
            </span>
            <span>{mapSummary(config).replace(/^No trifecta in [^:]+: /, 'Not a trifecta: ')}</span>
          </>
        )}
      </p>
      <div className="map-frame">
        <HouseDrawing config={config} titleId={`${base}-t`} descId={`${base}-d`} />
      </div>
      <p className="m-0 text-xs">
        A ghost is an MCP server (or a built-in ability the config allows). A lightning mark on a ghost, and
        &ldquo;AUTO-APPROVED&rdquo; in the list, means some of its tools run without asking you.
      </p>
      <ul className="map-list m-0 list-none p-0" aria-label={`Rooms of the Haunted House Map, ${config.file}`}>
        {ROOMS.map((r) => {
          const ghosts = config.ghosts.filter((g) => g.capabilities.includes(r.cap));
          return (
            <li key={r.cap} className="bevel-in p-2" data-room={r.cap}>
              <span className="font-bold">{r.name}</span> ({r.power}, {r.means}):{' '}
              {ghosts.length === 0 ? (
                <span>empty</span>
              ) : (
                <ul className="m-0 mt-1 pl-5">
                  {ghosts.map((g) => <GhostLine key={`${g.kind}:${g.name}`} g={g} />)}
                </ul>
              )}
            </li>
          );
        })}
        {quiet.length > 0 && (
          <li className="bevel-in p-2" data-room="none">
            <span className="font-bold">Quiet ghosts</span> (no risky powers found):{' '}
            <span className="font-mono">{quiet.map((g) => g.name).join(', ')}</span>
          </li>
        )}
      </ul>
    </div>
  );
}

/** Configs with a trifecta first, then by file. */
export function orderConfigs(configs: readonly ConfigMapMsg[]): ConfigMapMsg[] {
  return [...configs].sort((a, b) => Number(b.trifecta) - Number(a.trifecta) || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
}

export function HauntedHouseMap({ map }: { map: HauntedMapMsg }) {
  const configs = orderConfigs(map.configs);
  const [index, setIndex] = useState(0);
  const selectId = useId();
  const current = configs[Math.min(index, configs.length - 1)];
  if (!current) return <p className="m-0 text-sm">No MCP configs were found, so there is no house to map.</p>;
  const lethal = configs.filter((c) => c.trifecta).length;
  return (
    <section className="flex flex-col gap-2" aria-labelledby={`${selectId}-h`}>
      <h3 id={`${selectId}-h`} className="m-0 text-sm font-bold">
        Haunted House Map
      </h3>
      <p className="m-0 text-sm">
        {configs.length} MCP config{configs.length === 1 ? '' : 's'} found; {lethal} form{lethal === 1 ? 's' : ''} the lethal
        trifecta: private data, untrusted input and a way out in one agent session.
      </p>
      {configs.length > 1 && (
        <label htmlFor={selectId} className="flex flex-wrap items-center gap-2 text-sm font-semibold">
          Config file
          <select
            id={selectId}
            className="field max-w-full"
            value={Math.min(index, configs.length - 1)}
            onChange={(e) => setIndex(Number(e.target.value))}
          >
            {configs.map((c, i) => (
              <option key={c.file} value={i}>
                {c.file} {c.trifecta ? `(LETHAL TRIFECTA, ${(c.severity ?? 'high').toUpperCase()})` : '(no trifecta)'}
              </option>
            ))}
          </select>
        </label>
      )}
      <ConfigView key={current.file} config={current} />
    </section>
  );
}
