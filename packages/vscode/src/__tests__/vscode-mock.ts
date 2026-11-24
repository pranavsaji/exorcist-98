// A minimal fake of the `vscode` module: only what src/adapter.ts touches.
// The editor supplies the real module at run time (it is external to the bundle).

export enum DiagnosticSeverity { Error = 0, Warning = 1, Information = 2, Hint = 3 }

export class Position {
  constructor(readonly line: number, readonly character: number) {}
}

export class Range {
  readonly start: Position;
  readonly end: Position;
  constructor(sl: number, sc: number, el: number, ec: number) {
    this.start = new Position(sl, sc);
    this.end = new Position(el, ec);
  }
}

export class Uri {
  private constructor(readonly value: string) {}
  static parse(v: string): Uri { return new Uri(v); }
  toString(): string { return this.value; }
}

export class Diagnostic {
  source?: string;
  code?: string | number | { value: string | number; target: Uri };
  constructor(readonly range: Range, readonly message: string, readonly severity: DiagnosticSeverity) {}
}

type Op = { op: 'delete' | 'replace'; uri: Uri; range: Range; text?: string };
export class WorkspaceEdit {
  readonly ops: Op[] = [];
  delete(uri: Uri, range: Range): void { this.ops.push({ op: 'delete', uri, range }); }
  replace(uri: Uri, range: Range, text: string): void { this.ops.push({ op: 'replace', uri, range, text }); }
}

export type DiagnosticCollection = { forEach(cb: (uri: Uri, d: readonly Diagnostic[]) => void): void };
