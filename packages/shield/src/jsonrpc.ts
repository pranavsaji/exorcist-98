import { z } from 'zod';

export const JsonRpcMessageSchema = z
  .object({
    jsonrpc: z.literal('2.0'),
    id: z.union([z.string(), z.number()]).optional(),
    method: z.string().optional(),
    params: z.unknown().optional(),
    result: z.unknown().optional(),
    error: z.unknown().optional(),
  })
  .passthrough();

export type JsonRpcMessage = z.infer<typeof JsonRpcMessageSchema>;
export type JsonRpcId = string | number;

export type ParsedLine =
  | { ok: true; value: unknown }
  | { ok: false; error: string };

export function parseLine(line: string): ParsedLine {
  try {
    return { ok: true, value: JSON.parse(line) as unknown };
  } catch {
    return { ok: false, error: 'not valid JSON' };
  }
}

export function errorResponse(id: JsonRpcId | null, code: number, message: string): unknown {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

/** An MCP tool result that tells the agent the call did not happen, in plain words. */
export function toolErrorResult(id: JsonRpcId, text: string): JsonRpcMessage {
  return { jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text }] } };
}

const MAX_LINE_CHARS = 16 * 1024 * 1024;

/**
 * Splits a byte stream into newline-delimited lines. Chunk boundaries may fall
 * anywhere, including inside a multi-byte character. A line longer than the cap
 * is dropped (reported once through `overflow`).
 */
export class LineSplitter {
  private readonly decoder = new TextDecoder('utf-8');
  private buffer = '';
  public overflow = false;

  push(bytes: Uint8Array): string[] {
    this.buffer += this.decoder.decode(bytes, { stream: true });
    return this.drain();
  }

  flush(): string[] {
    this.buffer += this.decoder.decode();
    const lines = this.drain();
    const rest = this.buffer.replace(/\r$/, '');
    this.buffer = '';
    if (rest.trim().length > 0) lines.push(rest);
    return lines;
  }

  private drain(): string[] {
    const lines: string[] = [];
    let nl = this.buffer.indexOf('\n');
    while (nl !== -1) {
      const line = this.buffer.slice(0, nl).replace(/\r$/, '');
      this.buffer = this.buffer.slice(nl + 1);
      if (line.trim().length > 0) lines.push(line);
      nl = this.buffer.indexOf('\n');
    }
    if (this.buffer.length > MAX_LINE_CHARS) {
      this.buffer = '';
      this.overflow = true;
    }
    return lines;
  }
}
