import { normalize } from '../normalizer.js';
import { runSignatures } from './signature-engine.js';
import type { SignatureFinding, FileRole } from '../types.js';
import type { VirusDefinition } from '../definitions/schema.js';

/**
 * Scan a string that is not a file on disk, such as an MCP tool description or
 * a tool result. `label` is used as the finding's file name.
 */
export function scanText(
  text: string,
  role: FileRole,
  defs: VirusDefinition[],
  label = '(text)',
): SignatureFinding[] {
  const file = { path: label, rel: label, role, sizeBytes: text.length };
  return runSignatures(file, normalize(text, role), defs);
}
