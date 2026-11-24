// A fake editor host for the bundle smoke test: just enough of the `vscode`
// API for dist/extension.js to activate, scan a folder on disk, publish
// diagnostics and answer code-action and hover requests. Not a full mock.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

type Listener<T> = (e: T) => unknown;
class Emitter<T> {
  private readonly ls: Array<Listener<T>> = [];
  readonly event = (l: Listener<T>): { dispose(): void } => { this.ls.push(l); return { dispose: () => undefined }; };
  fire(e: T): void { for (const l of this.ls) l(e); }
}

export class Position { constructor(readonly line: number, readonly character: number) {} }
export class Range {
  readonly start: Position; readonly end: Position;
  constructor(sl: number, sc: number, el: number, ec: number) { this.start = new Position(sl, sc); this.end = new Position(el, ec); }
}
export class Uri {
  private constructor(readonly scheme: string, readonly path: string) {}
  static file(p: string): Uri { return new Uri('file', p); }
  static parse(s: string): Uri { const m = /^([a-z-]+):(?:\/\/)?(.*)$/.exec(s); return new Uri(m?.[1] ?? 'file', m?.[2] ?? s); }
  get fsPath(): string { return this.path; }
  toString(): string { return this.scheme === 'file' ? `file://${this.path}` : `${this.scheme}:${this.path}`; }
}
export class Diagnostic {
  source?: string; code?: unknown;
  constructor(readonly range: Range, readonly message: string, readonly severity: number) {}
}
export class WorkspaceEdit {
  readonly ops: Array<{ op: string; range: Range; text?: string }> = [];
  delete(_u: Uri, range: Range): void { this.ops.push({ op: 'delete', range }); }
  replace(_u: Uri, range: Range, text: string): void { this.ops.push({ op: 'replace', range, text }); }
}
export class ThemeColor { constructor(readonly id: string) {} }
export class MarkdownString { isTrusted?: boolean; supportHtml?: boolean; constructor(readonly value: string) {} }
export class Hover { constructor(readonly contents: MarkdownString, readonly range?: Range) {} }
export class CodeAction {
  edit?: WorkspaceEdit; diagnostics?: Diagnostic[]; isPreferred?: boolean; disabled?: { reason: string };
  constructor(readonly title: string, readonly kind: string) {}
}

export type FakeDoc = {
  uri: Uri; version: number; isClosed: boolean; languageId: string;
  getText(): string; offsetAt(p: Position): number;
};

export function fakeDoc(path: string, text: string, version = 1): FakeDoc {
  const starts = [0];
  for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) starts.push(i + 1);
  return {
    uri: Uri.file(path), version, isClosed: false, languageId: 'markdown',
    getText: () => text,
    offsetAt: (p) => (starts[p.line] ?? text.length) + p.character,
  };
}

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) { if (name !== 'node_modules') out.push(...walk(p)); } else out.push(p);
  }
  return out;
}

export function createFakeVscode(root: string) {
  const diagnostics = new Map<string, Diagnostic[]>();
  const commands = new Map<string, (...a: unknown[]) => unknown>();
  const codeActionProviders: Array<{ provideCodeActions(doc: FakeDoc, r: Range, ctx: { diagnostics: Diagnostic[] }): CodeAction[] }> = [];
  const hoverProviders: Array<{ provideHover(doc: FakeDoc, p: Position): Hover | undefined }> = [];
  const executed: string[] = [];
  const messages: string[] = [];
  const statusItem = { text: '', tooltip: '', command: '', name: '', backgroundColor: undefined as unknown, show() {}, hide() {}, dispose() {} };
  const opened = new Emitter<FakeDoc>();
  const folder = { uri: Uri.file(root), name: 'w', index: 0 };
  const settings: Record<string, unknown> = {};
  const noop = new Emitter<unknown>().event;
  const textDocuments: FakeDoc[] = [];

  const api = {
    Position, Range, Uri, Diagnostic, WorkspaceEdit, ThemeColor, MarkdownString, Hover, CodeAction,
    DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
    CodeActionKind: { QuickFix: 'quickfix' },
    StatusBarAlignment: { Left: 1, Right: 2 },
    OverviewRulerLane: { Right: 4 },
    DecorationRangeBehavior: { ClosedClosed: 1 },
    ProgressLocation: { Window: 10, Notification: 15 },
    FileType: { File: 1, Directory: 2 },
    window: {
      visibleTextEditors: [] as unknown[],
      activeTextEditor: undefined as unknown,
      createOutputChannel: () => ({ appendLine: (s: string) => messages.push(`log: ${s}`), dispose() {} }),
      createTextEditorDecorationType: () => ({ dispose() {} }),
      createStatusBarItem: () => statusItem,
      showInformationMessage: async (m: string) => { messages.push(m); return undefined; },
      showWarningMessage: async (m: string) => { messages.push(m); return undefined; },
      showErrorMessage: async (m: string) => { messages.push(m); return undefined; },
      withProgress: async (_o: unknown, task: (p: unknown, t: unknown) => Promise<unknown>) =>
        task({ report() {} }, { isCancellationRequested: false, onCancellationRequested: noop }),
      onDidChangeVisibleTextEditors: noop,
    },
    workspace: {
      isTrusted: false,
      workspaceFolders: [folder],
      textDocuments,
      getConfiguration: () => ({ get: (k: string, d: unknown) => (k in settings ? settings[k] : d) }),
      getWorkspaceFolder: (u: Uri) => (u.path.startsWith(`${root}/`) ? folder : undefined),
      asRelativePath: (u: Uri) => relative(root, u.path),
      findFiles: async () => walk(root).map((p) => Uri.file(p)),
      fs: {
        stat: async (u: Uri) => ({ type: 1, size: statSync(u.path).size }),
        readFile: async (u: Uri) => new Uint8Array(readFileSync(u.path)),
      },
      applyEdit: async () => true,
      createFileSystemWatcher: () => ({ onDidChange: noop, onDidCreate: noop, onDidDelete: noop, dispose() {} }),
      onDidOpenTextDocument: opened.event,
      onDidSaveTextDocument: noop,
      onDidChangeTextDocument: noop,
      onDidCloseTextDocument: noop,
      onDidChangeConfiguration: noop,
      onDidGrantWorkspaceTrust: noop,
      onDidDeleteFiles: noop,
      onDidRenameFiles: noop,
    },
    languages: {
      createDiagnosticCollection: () => ({
        set: (u: Uri, d: Diagnostic[]) => diagnostics.set(u.toString(), d),
        get: (u: Uri) => diagnostics.get(u.toString()),
        delete: (u: Uri) => diagnostics.delete(u.toString()),
        clear: () => diagnostics.clear(),
        forEach: (cb: (u: Uri, d: Diagnostic[]) => void) => diagnostics.forEach((d, k) => cb(Uri.parse(k), d)),
        dispose() {},
      }),
      registerCodeActionsProvider: (_s: unknown, p: (typeof codeActionProviders)[number]) => { codeActionProviders.push(p); return { dispose() {} }; },
      registerHoverProvider: (_s: unknown, p: (typeof hoverProviders)[number]) => { hoverProviders.push(p); return { dispose() {} }; },
    },
    commands: {
      registerCommand: (id: string, fn: (...a: unknown[]) => unknown) => { commands.set(id, fn); return { dispose() {} }; },
      executeCommand: async (id: string) => { executed.push(id); return undefined; },
    },
  };

  return {
    api, diagnostics, commands, codeActionProviders, hoverProviders, executed, messages, statusItem, settings,
    open(doc: FakeDoc): void { textDocuments.push(doc); opened.fire(doc); },
  };
}
