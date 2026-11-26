import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { SeverityBadge } from '@/components/SeverityBadge';
import { ProgressBar } from '@/components/ProgressBar';
import { ResultsWindow } from '@/components/ResultsWindow';
import { FindingDetail } from '@/components/FindingDetail';
import { ScanWindow } from '@/components/ScanWindow';
import { initialScanState } from '@/lib/scan-state';
import type { FindingEntry } from '@/lib/scan-state';
import type { Severity } from '@/lib/protocol';

const entry = (id: number, severity: Severity, ruleId = 'EX-001'): FindingEntry => ({
  id,
  finding: {
    source: 'signature', ruleId, title: 'Hidden Unicode instructions', severity,
    file: 'a.md', line: 3, col: 5, span: '\\u200B', owasp: ['LLM01:2025 Prompt Injection'], fix: 'Remove it.',
  },
  snippet: { lines: [
    { n: 2, before: 'before', match: '', after: '' },
    { n: 3, before: 'ab', match: '[U+200B]', after: 'cd' },
  ] },
});

describe('SeverityBadge', () => {
  it.each([
    ['critical', 'CRITICAL', 'diamond'],
    ['high', 'HIGH', 'triangle'],
    ['medium', 'MEDIUM', 'square'],
    ['low', 'LOW', 'circle'],
  ] as const)('%s shows a text label and a %s shape, not only colour', (sev, label, shape) => {
    const html = renderToStaticMarkup(<SeverityBadge severity={sev} />);
    expect(html).toContain(label);
    expect(html).toContain(`data-shape="${shape}"`);
    expect(html).toContain('aria-hidden="true"');
  });

  it('clean has its own label and shape', () => {
    const html = renderToStaticMarkup(<SeverityBadge severity="clean" />);
    expect(html).toContain('CLEAN');
    expect(html).toContain('data-shape="check"');
  });
});

describe('ProgressBar', () => {
  it('is an accessible progressbar and indeterminate while running', () => {
    const html = renderToStaticMarkup(<ProgressBar status="running" threatSeq={0} />);
    expect(html).toContain('role="progressbar"');
    expect(html).toContain('aria-label="Scanning"');
    expect(html).not.toContain('aria-valuenow');
  });

  it('reports 100 when done and glitches only after a threat while running', () => {
    expect(renderToStaticMarkup(<ProgressBar status="done" threatSeq={2} />)).toContain('aria-valuenow="100"');
    expect(renderToStaticMarkup(<ProgressBar status="running" threatSeq={1} />)).toContain('data-possessed="true"');
    expect(renderToStaticMarkup(<ProgressBar status="running" threatSeq={0} />)).toContain('data-possessed="false"');
  });
});

describe('ResultsWindow', () => {
  it('shows an empty state', () => {
    expect(renderToStaticMarkup(<ResultsWindow findings={[]} selectedId={null} onSelect={() => undefined} />)).toContain('No threats yet');
  });

  it('lists worst first with plain-language headlines, file and line', () => {
    const html = renderToStaticMarkup(
      <ResultsWindow findings={[entry(1, 'low'), entry(2, 'critical'), entry(3, 'medium')]} selectedId={null} onSelect={() => undefined} />,
    );
    expect(html.indexOf('CRITICAL')).toBeLessThan(html.indexOf('MEDIUM'));
    expect(html.indexOf('MEDIUM')).toBeLessThan(html.indexOf('LOW'));
    expect(html).toContain('This file hides instructions for your AI');
    expect(html).toContain('a.md:3');
    expect(html).toContain('3 threats found');
  });

  it('shows several hits of one rule on one line as one row, and says clean after a clean scan', () => {
    const e = entry(1, 'high');
    const twin = { ...entry(2, 'high'), finding: { ...entry(2, 'high').finding, col: 9 } };
    const html = renderToStaticMarkup(<ResultsWindow findings={[e, twin]} selectedId={null} onSelect={() => undefined} />);
    expect(html.match(/<li>/g)?.length).toBe(1);
    expect(html).toContain('2 places on this line');
    expect(renderToStaticMarkup(<ResultsWindow findings={[]} selectedId={null} onSelect={() => undefined} scanDone />)).toContain('Clean. No threats found');
    expect(renderToStaticMarkup(<ResultsWindow findings={[]} selectedId={null} onSelect={() => undefined} />)).toContain('No threats yet');
  });

  it('marks the selected row', () => {
    const html = renderToStaticMarkup(<ResultsWindow findings={[entry(7, 'high')]} selectedId={7} onSelect={() => undefined} />);
    expect(html).toContain('aria-current="true"');
  });
});

describe('FindingDetail', () => {
  it('leads with the plain sentence, then technical details, with the span highlighted', () => {
    const html = renderToStaticMarkup(<FindingDetail entry={entry(1, 'critical')} />);
    expect(html.indexOf('This file hides instructions for your AI')).toBeLessThan(html.indexOf('Technical details'));
    expect(html).toContain('<mark class="hit">[U+200B]</mark>');
    expect(html).toContain('line 3, column 5');
    expect(html).toContain('EX-001');
    expect(html).toContain('LLM01:2025 Prompt Injection');
    expect(html).toContain('Remove it.');
    expect(html).toContain('/encyclopedia/EX-001');
  });

  it('shows rationale and confidence for heuristic findings', () => {
    const e = entry(1, 'high');
    const h: FindingEntry = {
      ...e,
      finding: { ...e.finding, source: 'heuristic', rationale: 'Looks like an injection.', confidence: 'high' },
    };
    const html = renderToStaticMarkup(<FindingDetail entry={h} />);
    expect(html).toContain('Looks like an injection.');
    expect(html).toContain('Confidence');
  });

  it('M5-REQ-03.4: shows the Ouija board with the decoded message, escaped as text', () => {
    const e = entry(2, 'critical', 'EX-021');
    const withDecoded: FindingEntry = {
      ...e,
      finding: { ...e.finding, decoded: 'DEFANGED: <img src=x onerror=alert(1)> placeholder' },
    };
    const html = renderToStaticMarkup(<FindingDetail entry={withDecoded} />);
    expect(html).toContain('Ouija board');
    expect(html).toContain('The invisible text says:');
    // Attacker text is rendered as text, never as HTML.
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(html).not.toContain('<img');
    expect(html).toContain('variation selectors');
  });

  it('the Ouija panel is named by its visible heading, and the message box by its visible label', () => {
    const e = entry(7, 'critical');
    const html = renderToStaticMarkup(<FindingDetail entry={{ ...e, finding: { ...e.finding, decoded: 'hello' } }} />);
    expect(html).toMatch(/<section class="ouija" aria-labelledby="ouija-7"/);
    expect(html).toMatch(/<h4 id="ouija-7" class="ouija-title">Ouija board<\/h4>/);
    expect(html).toMatch(/<p id="ouija-says-7" class="ouija-says">The invisible text says:<\/p>/);
    expect(html).toMatch(/<pre class="ouija-message" tabindex="0" aria-labelledby="ouija-says-7">hello<\/pre>/);
    // Board decoration (letters, YES/NO, GOOD BYE, planchette) is hidden from screen readers.
    const decor = html.match(/aria-hidden="true"[^>]*>[^<]*(YES|NO|GOOD BYE)/g) ?? [];
    expect(decor).toHaveLength(3);
    expect(html).toContain('Spelled in invisible Unicode tag characters.');
  });

  it('control, bidi and invisible characters in the message are shown as markers, not obeyed', () => {
    const e = entry(4, 'critical', 'EX-021');
    const decoded = 'red\u001B[31m \u202Eevil\u200B\nline two';
    const html = renderToStaticMarkup(<FindingDetail entry={{ ...e, finding: { ...e.finding, decoded } }} />);
    expect(html).toContain('red[U+001B][31m [U+202E]evil[U+200B]\nline two');
    expect(html).not.toMatch(/[\u001B\u202E\u200B]/);
  });

  it('shows no Ouija board when the finding has no decoded message', () => {
    const html = renderToStaticMarkup(<FindingDetail entry={entry(3, 'critical')} />);
    expect(html).not.toContain('Ouija board');
  });

  it('shows a prompt when nothing is selected (empty state)', () => {
    expect(renderToStaticMarkup(<FindingDetail entry={null} />)).toContain('Pick a threat');
  });
});

describe('ScanWindow', () => {
  const noop = () => undefined;
  const base = { onScanUrl: noop, onScanHaunted: noop, onCancel: noop, onShowResults: noop, onScanZip: noop };

  it('first screen (hero): one big line, a primary Haunted Repo button, the URL field and a .zip upload, no log yet', () => {
    const html = renderToStaticMarkup(<ScanWindow state={initialScanState} {...base} hero extras={<p>EXTRAS</p>} />);
    expect(html).toContain('Your AI agent obeys what it reads.');
    expect(html).toContain('Exorcist 98 checks it first.');
    expect(html).toMatch(/<button type="button" class="btn btn-primary btn-hero" data-guide="haunted">.*Scan the Haunted Repo<\/button>/);
    expect(html).toContain('GitHub repository to scan');
    expect(html).toMatch(/<label for="[^"]+" class="btn zip-label"[^>]*>Upload a .zip<\/label>/);
    expect(html).toContain('EXTRAS');
    expect(html).not.toContain('role="log"');
    // Exactly one primary action on the first screen.
    expect(html.match(/btn-primary/g)).toHaveLength(1);
  });

  it('after a scan starts: a polite log region, Cancel and View results, and no hero', () => {
    const html = renderToStaticMarkup(<ScanWindow state={{ ...initialScanState, status: 'done' }} {...base} extras={<p>EXTRAS</p>} />);
    expect(html).toContain('GitHub repository to scan');
    expect(html).toContain('Scan the Haunted Repo');
    expect(html).toContain('role="log"');
    expect(html).toContain('aria-live="polite"');
    expect(html).not.toContain('obeys what it reads');
    expect(html).not.toContain('EXTRAS');
  });

  it('disables Scan while running and enables Cancel', () => {
    const running = { ...initialScanState, status: 'running' as const };
    const html = renderToStaticMarkup(<ScanWindow state={running} {...base} />);
    expect(html).toMatch(/<button type="submit" class="btn" disabled="">Scan<\/button>/);
    expect(html).not.toMatch(/<button type="button" class="btn" disabled="">Cancel<\/button>/);
  });
});

describe('ResultsSummary', () => {
  it('gives a verdict in words and shape, counts by level and the top three different threats, worst first', async () => {
    const { ResultsSummary } = await import('@/components/ResultsSummary');
    const f = [entry(1, 'low', 'EX-010'), entry(2, 'critical', 'EX-001'), entry(3, 'critical', 'EX-001'), entry(4, 'high', 'EX-005'), entry(5, 'medium', 'EX-008')];
    const html = renderToStaticMarkup(<ResultsSummary findings={f} filesScanned={22} onSelect={() => undefined} />);
    expect(html).toContain('POSSESSED');
    expect(html).toMatch(/Infection level: <span class="sev sev-critical" data-severity="critical"><svg[^>]*data-shape="diamond"/);
    expect(html).toContain('5 threats in 1 file (of 22 scanned)');
    expect(html).toContain('Top threats');
    const top = html.slice(html.indexOf('summary-top'));
    expect(top.match(/<button/g)).toHaveLength(3);
    // One per rule, worst first: EX-001 (critical), EX-005 (high), EX-008 (medium); never EX-001 twice.
    expect(top.indexOf('data-severity="critical"')).toBeLessThan(top.indexOf('data-severity="high"'));
    expect(top.indexOf('data-severity="high"')).toBeLessThan(top.indexOf('data-severity="medium"'));
    expect(top).not.toContain('data-severity="low"');
    // The gauge is decoration; the words carry the meaning.
    expect(html).toMatch(/<div class="gauge" aria-hidden="true" data-level="critical">/);
  });

  it('says CLEAN, with a check shape, after a clean scan', async () => {
    const { ResultsSummary, verdictFor } = await import('@/components/ResultsSummary');
    const html = renderToStaticMarkup(<ResultsSummary findings={[]} filesScanned={3} onSelect={() => undefined} />);
    expect(html).toContain('CLEAN');
    expect(html).toContain('data-shape="check"');
    expect(html).toContain('No threats in 3 files.');
    expect(html).not.toContain('Top threats');
    expect(verdictFor('medium').word).toBe('HAUNTED');
  });
});

describe('Possession Lab: Bring Your Own Attack tab (m5-byoa)', () => {
  it('renders two tabs, with the scripted one selected and its panel shown', async () => {
    const { PossessionLab } = await import('@/components/PossessionLab');
    const html = renderToStaticMarkup(<PossessionLab />);
    expect(html).toContain('role="tablist"');
    expect(html).toMatch(/role="tab"[^>]*aria-selected="true"[^>]*>Scripted attacks</);
    expect(html).toMatch(/role="tab"[^>]*aria-selected="false"[^>]*>Bring your own attack</);
    expect(html).toMatch(/id="lab-panel-byoa"[^>]*hidden/);
  });

  it('the form has a labelled textarea capped at 20,000 characters, four placements and six samples', async () => {
    const { ByoaLab } = await import('@/components/ByoaLab');
    const html = renderToStaticMarkup(<ByoaLab />);
    expect(html).toMatch(/<label for="byoa-text"[^>]*>Text to check \(up to 20,000 characters\)<\/label>/);
    expect(html).toMatch(/<textarea id="byoa-text"[^>]*maxLength="20000"/);
    expect((html.match(/type="radio"/g) ?? []).length).toBe(4);
    for (const label of ['A README / rules file the agent reads', 'An MCP tool description', 'A tool result', 'Tool call arguments (JSON)']) expect(html).toContain(label);
    expect((html.match(/byoa-sample"/g) ?? []).length).toBe(6);
    expect(html).toContain('<legend');
  });
});

describe('Possession Lab: The Hidden Page (m8-incidents)', () => {
  it('opens on the hidden-web-text attack from a deep link, with the attack group labelled', async () => {
    const { PossessionLab } = await import('@/components/PossessionLab');
    const html = renderToStaticMarkup(<PossessionLab initial="hidden-web-text" request={{ tab: 'scripted', scenario: 'hidden-web-text', seq: 1 }} />);
    expect(html).toContain('role="group" aria-label="Choose an attack"');
    expect(html).toContain('Summoning the attack');
  });
});

describe('Possession Lab: The Settings Tamper (m11-config-tamper)', () => {
  it('CT-19: opens on attack 9 from a deep link, with native buttons and the attack group labelled', async () => {
    const { PossessionLab } = await import('@/components/PossessionLab');
    const html = renderToStaticMarkup(<PossessionLab initial="settings-tamper" request={{ tab: 'scripted', scenario: 'settings-tamper', seq: 1 }} />);
    expect(html).toContain('role="group" aria-label="Choose an attack"');
    expect(html).toContain('Summoning the attack');
  });
  it('CT-19: the attack buttons are real buttons (keyboard reachable), and the result is stated in text, not colour', async () => {
    const { readFileSync } = await import('node:fs');
    const src = readFileSync(new URL('../components/PossessionLab.tsx', import.meta.url), 'utf8');
    expect(src).toMatch(/<button key=\{s\.id\} type="button"/);
    expect(src).toContain('Infection level: ');
    expect(src).toContain('Result: protected.');
    expect(src).toContain('Result: compromised.');
  });
});
