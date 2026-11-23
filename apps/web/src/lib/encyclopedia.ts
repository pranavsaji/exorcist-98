import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { loadDefinitions } from '@exorcist-98/core';
import type { VirusDefinition } from '@exorcist-98/core';
import { definitionsDir, hauntedRepoDir } from './paths';
import { revealHidden } from './snippet';

const MAX_EXAMPLE_LINES = 40;

/** All definitions on disk, sorted by id. Adding a YAML file adds a page. */
export async function listDefinitions(): Promise<VirusDefinition[]> {
  const defs = await loadDefinitions(definitionsDir());
  return [...defs].sort((a, b) => a.id.localeCompare(b.id));
}

export async function getDefinition(id: string): Promise<VirusDefinition | null> {
  if (!/^EX-\d{3}$/.test(id)) return null;
  const defs = await listDefinitions();
  return defs.find((d) => d.id === id) ?? null;
}

export type Example = { file: string; text: string; truncated: boolean };

/**
 * The defanged example for a rule: the matching Haunted Repo fixture, with
 * hidden characters made visible. The id has already been checked against the
 * EX-NNN pattern, so it cannot be used to read other files.
 */
export async function getExample(id: string): Promise<Example | null> {
  if (!/^EX-\d{3}$/.test(id)) return null;
  const dir = hauntedRepoDir();
  const names = await readdir(dir);
  const file = names.find((n) => n.startsWith(`${id}-`));
  if (!file) return null;
  const raw = await readFile(join(dir, file), 'utf8');
  const lines = raw.split('\n');
  const truncated = lines.length > MAX_EXAMPLE_LINES;
  const text = revealHidden(lines.slice(0, MAX_EXAMPLE_LINES).join('\n'));
  return { file, text, truncated };
}

export function describeMatch(def: VirusDefinition): string {
  const parts: string[] = [];
  if (def.match.regex) parts.push('a text pattern');
  if (def.match.unicode_class?.length) parts.push(`hidden Unicode (${def.match.unicode_class.join(', ')})`);
  if (def.match.json_path) parts.push('a structure check on JSON files');
  if (def.match.analysis === 'trifecta') parts.push('a check of all the MCP servers in one config together (capabilities.yaml)');
  return parts.join(' and ');
}
