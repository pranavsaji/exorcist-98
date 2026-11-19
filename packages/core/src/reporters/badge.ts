import type { Finding, Severity } from '../types.js';

// Browser-safe: no Node imports.

export type BadgeStatus = { label: string; message: string; color: string; worst: Severity | 'clean' };

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];
const COLORS: Record<Severity | 'clean', string> = {
  clean: '#2e9e5b', critical: '#b0123b', high: '#c2410c', medium: '#8a6d00', low: '#2563a8',
};

/** "exorcised" when nothing is found; otherwise "possessed" with the worst level and a count. */
export function badgeStatus(findings: readonly Pick<Finding, 'severity'>[]): BadgeStatus {
  const worst = ORDER.find((s) => findings.some((f) => f.severity === s)) ?? 'clean';
  if (worst === 'clean') return { label: 'Exorcist 98', message: 'exorcised', color: COLORS.clean, worst };
  const n = findings.filter((f) => f.severity === worst).length;
  return { label: 'Exorcist 98', message: `possessed: ${n} ${worst}`, color: COLORS[worst], worst };
}

const esc = (s: string): string =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

// Approximate width of 11px Verdana-like text; good enough for a badge.
const textWidth = (s: string): number => Math.round([...s].length * 6.6 + 10);

/** A self-contained SVG badge (no external fonts or images). */
export function toBadgeSvg(findings: readonly Pick<Finding, 'severity'>[]): string {
  const b = badgeStatus(findings);
  const lw = textWidth(b.label);
  const mw = textWidth(b.message);
  const w = lw + mw;
  const title = `${b.label}: ${b.message}`;
  return [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${esc(title)}">`,
    `<title>${esc(title)}</title>`,
    `<rect width="${lw}" height="20" fill="#23163d"/>`,
    `<rect x="${lw}" width="${mw}" height="20" fill="${b.color}"/>`,
    `<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">`,
    `<text x="${lw / 2}" y="14">${esc(b.label)}</text>`,
    `<text x="${lw + mw / 2}" y="14">${esc(b.message)}</text>`,
    '</g></svg>',
    '',
  ].join('\n');
}
