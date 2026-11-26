import { createHash } from 'node:crypto';
import { canonicalJson } from './canonical.js';

export { canonicalJson };

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
