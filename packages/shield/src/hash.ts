import { createHash } from 'node:crypto';

/** JSON with sorted object keys and no whitespace, so equal data gives equal text. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
}

export type ToolDef = {
  name: string;
  description?: string;
  inputSchema?: unknown;
};

/** SHA-256 over the parts of a tool the agent trusts: name, description, input schema. */
export function toolFingerprint(tool: ToolDef): string {
  return createHash('sha256')
    .update(canonicalJson({ name: tool.name, description: tool.description ?? '', inputSchema: tool.inputSchema ?? {} }))
    .digest('hex');
}
