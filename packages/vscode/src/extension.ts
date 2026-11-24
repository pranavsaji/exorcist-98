/**
 * Exorcist 98 for Kiro (and VS Code): the editor glue. Everything that decides
 * anything lives in the pure modules (roles, scanner, diagnostics, hidden,
 * fixes); this file wires them to editor events.
 *
 * Safety: the extension only reads files. It never runs a program, a task or
 * a script from the workspace, never loads code from it, and makes no network
 * request (the encyclopedia links open in your browser only when you click
 * them). It runs in Restricted Mode too, where VS Code and Kiro ignore the
 * workspace's values for the settings that could switch it off or hide
 * findings (`capabilities.untrustedWorkspaces.restrictedConfigurations`).
 */
import * as vscode from 'vscode';
import type { FileRole, Finding, Severity } from '@exorcist-98/core';
import { countGhosts, ruleIdOf, statusText, toDiagnostic, toRange, toWorkspaceEdit } from './adapter.js';
import { LineIndex, toDiagnosticSpec } from './diagnostics.js';
import { HIDDEN_FIX_TITLE, HIDDEN_RULES, SINGLE_FIX_RULES, exorciseHidden, exorciseOne, singleFixTitle } from './fixes.js';
import type { Exorcism } from './fixes.js';
import { hiddenRuns, hoverMarkdown, runAt } from './hidden.js';
import type { HiddenRun } from './hidden.js';
import { WORKSPACE_EXCLUDE, WORKSPACE_INCLUDE, agentRelativePath, compileGlobs, decideScan } from './roles.js';
import type { GlobMatcher } from './roles.js';
import { GhostScanner, HARD_LIMIT_CHARS, isSeverity, meetsThreshold } from './scanner.js';

const CHANGE_DEBOUNCE_MS = 400;
const WATCH_DEBOUNCE_MS = 600;
/** The workspace scan looks at no more than this many candidate files. */
const MAX_WORKSPACE_FILES = 20_000;
/** Bytes read to tell a binary file (a NUL byte) from text, as the CLI's walker does. */
const BINARY_PROBE = 512;
/** Schemes scanned: real files, remote files and the editor's user data (user-level MCP configs). Not git: or diff views. */
const SCHEMES = new Set(['file', 'vscode-remote', 'vscode-vfs', 'vscode-userdata']);

type Settings = {
  enable: boolean;
  extra: GlobMatcher[];
  extraGlobs: string[];
  invalidGlobs: string[];
  minimumSeverity: Severity;
  showHidden: boolean;
  scanOnStartup: boolean;
};

type Entry = { version: number; text: string; rel: string; role: FileRole; runs: HiddenRun[]; index: LineIndex };

function readSettings(): Settings {
  const c = vscode.workspace.getConfiguration('exorcist98');
  const raw = c.get<unknown>('extraGlobs', []);
  const extraGlobs = Array.isArray(raw) ? raw.filter((g): g is string => typeof g === 'string') : [];
  const { patterns, invalid } = compileGlobs(extraGlobs);
  const min = c.get<unknown>('minimumSeverity', 'low');
  return {
    enable: c.get<boolean>('enable', true) !== false,
    extra: patterns,
    extraGlobs,
    invalidGlobs: invalid,
    minimumSeverity: isSeverity(min) ? min : 'low',
    showHidden: c.get<boolean>('showHiddenCharacters', true) !== false,
    scanOnStartup: c.get<boolean>('scanWorkspaceOnStartup', true) !== false,
  };
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const log = vscode.window.createOutputChannel('Exorcist 98');
  context.subscriptions.push(log);

  let scanner: GhostScanner;
  try {
    scanner = await GhostScanner.load(context.asAbsolutePath('dist/definitions'));
  } catch (err) {
    const msg = `Exorcist 98 could not load its virus definitions, so nothing is scanned: ${String(err).split('\n')[0]}`;
    log.appendLine(msg);
    void vscode.window.showErrorMessage(msg);
    return;
  }
  log.appendLine(`Loaded ${scanner.definitions.length} virus definitions. Workspace trusted: ${vscode.workspace.isTrusted}.`);

  let settings = readSettings();
  const collection = vscode.languages.createDiagnosticCollection('exorcist98');
  const entries = new Map<string, Entry>();
  const timers = new Map<string, ReturnType<typeof setTimeout>>();
  const decoration = vscode.window.createTextEditorDecorationType({
    before: {
      color: new vscode.ThemeColor('exorcist98.hiddenCharacterForeground'),
      backgroundColor: new vscode.ThemeColor('exorcist98.hiddenCharacterBackground'),
      border: '1px solid',
      borderColor: new vscode.ThemeColor('exorcist98.hiddenCharacterForeground'),
      margin: '0 1px',
      fontStyle: 'normal',
      fontWeight: 'bold',
      // The usual way to give injected text a size and rounded corners.
      textDecoration: 'none; font-size: 0.85em; border-radius: 3px; padding: 0 2px',
    },
    overviewRulerColor: new vscode.ThemeColor('exorcist98.hiddenCharacterForeground'),
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    rangeBehavior: vscode.DecorationRangeBehavior.ClosedClosed,
  });
  const status = vscode.window.createStatusBarItem('exorcist98.ghosts', vscode.StatusBarAlignment.Left, 50);
  status.name = 'Exorcist 98 ghosts';
  status.command = 'exorcist98.showProblems';
  context.subscriptions.push(collection, decoration, status);

  // ── Helpers ────────────────────────────────────────────────────────────────

  const keyOf = (uri: vscode.Uri): string => uri.toString();

  /** The path the classifier sees: workspace-relative, or from the last agent folder for files outside the workspace. */
  function relOf(uri: vscode.Uri): string | null {
    if (!SCHEMES.has(uri.scheme)) return null;
    if (vscode.workspace.getWorkspaceFolder(uri)) return vscode.workspace.asRelativePath(uri, false);
    return agentRelativePath(uri.scheme === 'file' ? uri.fsPath : uri.path);
  }

  function updateStatus(): void {
    if (!settings.enable) { status.hide(); return; }
    const n = countGhosts(collection);
    const s = statusText(n, vscode.workspace.isTrusted);
    status.text = s.text;
    status.tooltip = s.tooltip;
    status.backgroundColor = n.errors > 0
      ? new vscode.ThemeColor('statusBarItem.errorBackground')
      : n.warnings > 0 ? new vscode.ThemeColor('statusBarItem.warningBackground') : undefined;
    status.show();
  }

  function decorate(editor: vscode.TextEditor): void {
    const e = entries.get(keyOf(editor.document.uri));
    if (!settings.enable || !settings.showHidden || !e || e.version !== editor.document.version) {
      editor.setDecorations(decoration, []);
      return;
    }
    editor.setDecorations(decoration, e.runs.map((r) => ({
      range: toRange(e.index, r.start, r.end),
      renderOptions: { before: { contentText: r.label } },
    })));
  }

  function redecorate(uri?: vscode.Uri): void {
    for (const ed of vscode.window.visibleTextEditors) {
      if (!uri || keyOf(ed.document.uri) === keyOf(uri)) decorate(ed);
    }
  }

  function forget(uri: vscode.Uri): void {
    collection.delete(uri);
    entries.delete(keyOf(uri));
  }

  /** Scan text and publish its diagnostics. Returns how many were published. */
  function publish(uri: vscode.Uri, text: string, rel: string, role: FileRole, version: number | null): number {
    const findings = scanner.scan(text, rel, role);
    const index = new LineIndex(text);
    const runs = hiddenRuns(text);
    const diags = findings
      .filter((f) => meetsThreshold(f.severity, settings.minimumSeverity))
      .map((f) => toDiagnostic(toDiagnosticSpec(f, index, runs)));
    collection.set(uri, diags);
    if (version !== null) entries.set(keyOf(uri), { version, text, rel, role, runs, index });
    return diags.length;
  }

  function scanDocument(doc: vscode.TextDocument): void {
    if (!settings.enable) return;
    const rel = relOf(doc.uri);
    if (rel === null) return;
    const text = doc.getText();
    const d = decideScan(rel, settings.extra, text);
    if (d.scan !== true) { forget(doc.uri); redecorate(doc.uri); return; }
    try {
      publish(doc.uri, text, rel, d.role, doc.version);
    } catch (err) {
      log.appendLine(`Could not scan ${rel}: ${String(err)}`);
      forget(doc.uri);
    }
    redecorate(doc.uri);
    updateStatus();
  }

  /** Scan a file from disk (not open in an editor). Read-only. */
  async function scanFile(uri: vscode.Uri): Promise<number> {
    const rel = relOf(uri);
    if (rel === null) return 0;
    const first = decideScan(rel, settings.extra);
    if (first.scan === false) { collection.delete(uri); return 0; }
    const st = await vscode.workspace.fs.stat(uri);
    if ((st.type & vscode.FileType.File) === 0) { collection.delete(uri); return 0; }
    if (st.size > HARD_LIMIT_CHARS) {
      if (first.scan !== true) { collection.delete(uri); return 0; }
      const f = scanner.tooLarge(rel, st.size);
      const index = new LineIndex('');
      collection.set(uri, f.filter((x) => meetsThreshold(x.severity, settings.minimumSeverity)).map((x) => toDiagnostic(toDiagnosticSpec(x, index, []))));
      return f.length;
    }
    const bytes = await vscode.workspace.fs.readFile(uri);
    // A NUL byte means binary, so a file that is only a candidate is skipped.
    // A known agent file is scanned anyway: a NUL byte must not be a way to
    // hide instructions from the scanner while the agent still reads the rest.
    if (first.scan !== true && bytes.subarray(0, BINARY_PROBE).includes(0)) { collection.delete(uri); return 0; }
    const text = new TextDecoder('utf-8').decode(bytes);
    const d = first.scan === true ? first : decideScan(rel, settings.extra, text);
    if (d.scan !== true) { collection.delete(uri); return 0; }
    return publish(uri, text, rel, d.role, null);
  }

  function isOpen(uri: vscode.Uri): vscode.TextDocument | undefined {
    const k = keyOf(uri);
    return vscode.workspace.textDocuments.find((d) => keyOf(d.uri) === k && !d.isClosed);
  }

  function later(uri: vscode.Uri, ms: number, run: () => void | Promise<unknown>): void {
    const k = keyOf(uri);
    const t = timers.get(k);
    if (t) clearTimeout(t);
    timers.set(k, setTimeout(() => {
      timers.delete(k);
      new Promise((resolve) => resolve(run())).catch((err: unknown) => log.appendLine(`Scan failed for ${uri.toString(true)}: ${String(err)}`)).finally(updateStatus);
    }, ms));
  }

  let workspaceScan: Promise<void> | null = null;

  async function scanWorkspace(interactive: boolean): Promise<void> {
    if (!settings.enable) {
      if (interactive) void vscode.window.showInformationMessage('Exorcist 98 is turned off (exorcist98.enable).');
      return;
    }
    if (!vscode.workspace.workspaceFolders?.length) {
      if (interactive) void vscode.window.showInformationMessage('Exorcist 98: open a folder to scan its agent files.');
      return;
    }
    if (workspaceScan) { await workspaceScan; if (!interactive) return; }
    const run = vscode.window.withProgress(
      {
        location: interactive ? vscode.ProgressLocation.Notification : vscode.ProgressLocation.Window,
        title: 'Exorcist 98: scanning agent files',
        cancellable: interactive,
      },
      async (progress, token) => {
        const started = Date.now();
        const found = new Map<string, vscode.Uri>();
        const globs = [WORKSPACE_INCLUDE, ...settings.extraGlobs.filter((g) => !settings.invalidGlobs.includes(g)).map((g) => (g.includes('/') ? g : `**/${g}`))];
        for (const g of globs) {
          const uris = await vscode.workspace.findFiles(g, WORKSPACE_EXCLUDE, MAX_WORKSPACE_FILES, token);
          for (const u of uris) found.set(keyOf(u), u);
        }
        // Results for files that no longer exist or no longer match are dropped.
        const stale: vscode.Uri[] = [];
        collection.forEach((uri) => { if (!found.has(keyOf(uri)) && !isOpen(uri)) stale.push(uri); });
        for (const uri of stale) collection.delete(uri);
        let i = 0;
        for (const uri of found.values()) {
          if (token.isCancellationRequested) break;
          i++;
          if (i % 50 === 0) progress.report({ message: `${i} of ${found.size} files` });
          try {
            const doc = isOpen(uri);
            if (doc) scanDocument(doc);
            else await scanFile(uri);
          } catch (err) {
            log.appendLine(`Could not scan ${uri.toString(true)}: ${String(err)}`);
          }
        }
        updateStatus();
        const n = countGhosts(collection);
        log.appendLine(`Workspace scan: ${found.size} candidate files, ${n.total} ghosts in ${n.files} files, ${Date.now() - started} ms${token.isCancellationRequested ? ' (cancelled)' : ''}.`);
        return n;
      },
    );
    workspaceScan = Promise.resolve(run).then((n) => {
      if (!interactive) return;
      const msg = n.total === 0
        ? 'Exorcist 98: no ghosts found in the agent files of this workspace.'
        : `Exorcist 98: ${n.total} ghost${n.total === 1 ? '' : 's'} in ${n.files} agent file${n.files === 1 ? '' : 's'}.`;
      // Not awaited: the scan is over even while the message is open.
      void vscode.window.showInformationMessage(msg, ...(n.total > 0 ? ['Show Problems'] : [])).then((pick) => {
        if (pick === 'Show Problems') void vscode.commands.executeCommand('workbench.actions.view.problems');
      });
    }).finally(() => { workspaceScan = null; });
    await workspaceScan;
  }

  function rescanEverything(): void {
    for (const t of timers.values()) clearTimeout(t);
    timers.clear();
    if (!settings.enable) {
      collection.clear();
      entries.clear();
      redecorate();
      updateStatus();
      return;
    }
    for (const doc of vscode.workspace.textDocuments) scanDocument(doc);
    redecorate();
    updateStatus();
    if (settings.scanOnStartup) void scanWorkspace(false);
  }

  /** Fresh findings for a document (code actions always work on the current text). */
  function currentFindings(doc: vscode.TextDocument): { findings: Finding[]; rel: string; index: LineIndex; text: string } | null {
    const rel = relOf(doc.uri);
    if (rel === null) return null;
    const text = doc.getText();
    const d = decideScan(rel, settings.extra, text);
    if (d.scan !== true) return null;
    return { findings: scanner.scan(text, rel, d.role), rel, index: new LineIndex(text), text };
  }

  function editFor(doc: vscode.TextDocument, index: LineIndex, x: Exorcism): vscode.WorkspaceEdit {
    return toWorkspaceEdit(doc.uri, index, x.edits);
  }

  // ── Commands ───────────────────────────────────────────────────────────────

  context.subscriptions.push(
    vscode.commands.registerCommand('exorcist98.scanWorkspace', () => scanWorkspace(true)),
    vscode.commands.registerCommand('exorcist98.showProblems', () => vscode.commands.executeCommand('workbench.actions.view.problems')),
    vscode.commands.registerCommand('exorcist98.exorciseFile', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) { void vscode.window.showInformationMessage('Exorcist 98: open a file first.'); return; }
      const doc = editor.document;
      const rel = relOf(doc.uri) ?? 'file';
      const text = doc.getText();
      // Any open file can be exorcised on request, even one the live scan does not cover.
      const d = decideScan(rel, settings.extra, text);
      const findings = scanner.scan(text, rel, d.role);
      const x = exorciseHidden(text, rel, findings);
      if (x.edits.length === 0) {
        void vscode.window.showInformationMessage(x.notes[0] ?? 'Exorcist 98: no hidden characters to remove in this file.');
        return;
      }
      const ok = await vscode.workspace.applyEdit(editFor(doc, new LineIndex(text), x));
      if (ok) void vscode.window.showInformationMessage(`Exorcist 98: removed ${x.changeCount} hidden character${x.changeCount === 1 ? '' : 's'}. Undo restores them; the file is not saved for you.`);
    }),
  );

  // ── Quick fixes ────────────────────────────────────────────────────────────

  context.subscriptions.push(vscode.languages.registerCodeActionsProvider('*', {
    provideCodeActions(doc, _range, ctx): vscode.CodeAction[] {
      const ours = ctx.diagnostics.filter((d) => ruleIdOf(d) !== null);
      if (ours.length === 0) return [];
      const cur = currentFindings(doc);
      if (!cur) return [];
      const actions: vscode.CodeAction[] = [];
      const hiddenDiags = ours.filter((d) => HIDDEN_RULES.has(ruleIdOf(d) ?? ''));
      if (hiddenDiags.length > 0) {
        const x = exorciseHidden(cur.text, cur.rel, cur.findings);
        const a = new vscode.CodeAction(HIDDEN_FIX_TITLE, vscode.CodeActionKind.QuickFix);
        a.diagnostics = collection.get(doc.uri)?.filter((d) => HIDDEN_RULES.has(ruleIdOf(d) ?? '')) ?? hiddenDiags;
        if (x.edits.length > 0) { a.edit = editFor(doc, cur.index, x); a.isPreferred = true; }
        else a.disabled = { reason: x.notes[0] ?? 'Nothing to remove.' };
        actions.push(a);
      }
      for (const d of ours) {
        const id = ruleIdOf(d) ?? '';
        if (!SINGLE_FIX_RULES.has(id)) continue;
        const f = cur.findings.find((g) => {
          if (g.ruleId !== id) return false;
          const s = toDiagnosticSpec(g, cur.index, []).start;
          return s.line === d.range.start.line && s.character === d.range.start.character;
        });
        if (!f) continue;
        const x = exorciseOne(cur.text, cur.rel, f);
        const a = new vscode.CodeAction(singleFixTitle(id), vscode.CodeActionKind.QuickFix);
        a.diagnostics = [d];
        if (x.edits.length > 0) a.edit = editFor(doc, cur.index, x);
        else a.disabled = { reason: x.notes[0] ?? 'The core found no safe mechanical fix for this one; it needs a human.' };
        actions.push(a);
      }
      return actions;
    },
  }, { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }));

  // ── Hover: what the hidden characters are, and what they say ──────────────

  context.subscriptions.push(vscode.languages.registerHoverProvider('*', {
    provideHover(doc, pos): vscode.Hover | undefined {
      if (!settings.enable) return undefined;
      const e = entries.get(keyOf(doc.uri));
      if (!e || e.version !== doc.version || e.runs.length === 0) return undefined;
      const run = runAt(e.runs, doc.offsetAt(pos));
      if (!run) return undefined;
      const md = new vscode.MarkdownString(hoverMarkdown(run));
      md.isTrusted = false;
      md.supportHtml = false;
      return new vscode.Hover(md, toRange(e.index, run.start, run.end));
    },
  }));

  // ── Events ─────────────────────────────────────────────────────────────────

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(scanDocument),
    vscode.workspace.onDidSaveTextDocument(scanDocument),
    vscode.workspace.onDidChangeTextDocument((ev) => {
      if (ev.contentChanges.length === 0) return;
      // Until the rescan, the old markers would sit at stale offsets.
      entries.delete(keyOf(ev.document.uri));
      redecorate(ev.document.uri);
      later(ev.document.uri, CHANGE_DEBOUNCE_MS, () => scanDocument(ev.document));
    }),
    vscode.workspace.onDidCloseTextDocument((doc) => {
      entries.delete(keyOf(doc.uri));
      // A closed file's diagnostics should describe what is on disk, not the discarded buffer.
      if (doc.uri.scheme === 'file' && vscode.workspace.getWorkspaceFolder(doc.uri)) later(doc.uri, WATCH_DEBOUNCE_MS, () => scanFile(doc.uri));
      else collection.delete(doc.uri);
    }),
    vscode.window.onDidChangeVisibleTextEditors((eds) => eds.forEach(decorate)),
    vscode.workspace.onDidChangeConfiguration((ev) => {
      if (!ev.affectsConfiguration('exorcist98')) return;
      settings = readSettings();
      if (settings.invalidGlobs.length > 0) void vscode.window.showWarningMessage(`Exorcist 98: ignoring invalid globs in exorcist98.extraGlobs: ${settings.invalidGlobs.join(', ')}`);
      rescanEverything();
    }),
    vscode.workspace.onDidGrantWorkspaceTrust(() => {
      // Workspace values of the restricted settings now apply.
      settings = readSettings();
      log.appendLine('Workspace trusted: workspace settings for Exorcist 98 now apply.');
      rescanEverything();
    }),
    vscode.workspace.onDidDeleteFiles((ev) => ev.files.forEach(forget)),
    vscode.workspace.onDidRenameFiles((ev) => ev.files.forEach((f) => { forget(f.oldUri); later(f.newUri, WATCH_DEBOUNCE_MS, () => scanFile(f.newUri)); })),
  );

  // Agents write steering, specs and MCP configs while you work: files changed
  // on disk but not open in an editor are rescanned too.
  const watcher = vscode.workspace.createFileSystemWatcher(WORKSPACE_INCLUDE);
  const onDisk = (uri: vscode.Uri): void => {
    if (!settings.enable || isOpen(uri)) return;
    later(uri, WATCH_DEBOUNCE_MS, () => scanFile(uri));
  };
  context.subscriptions.push(
    watcher,
    watcher.onDidChange(onDisk),
    watcher.onDidCreate(onDisk),
    watcher.onDidDelete((uri) => { forget(uri); updateStatus(); }),
    { dispose: () => { for (const t of timers.values()) clearTimeout(t); timers.clear(); } },
  );

  rescanEverything();
}

export function deactivate(): void {
  // Everything is disposed through context.subscriptions.
}
