import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import yaml from 'js-yaml';
import { VirusDefinitionSchema, DefinitionLoadError } from './schema.js';
import type { VirusDefinition } from './schema.js';

/** YAML files in the definitions folder that are not virus definitions. */
export const NON_DEFINITION_FILES = new Set(['capabilities.yaml']);

export async function loadDefinitions(dir: string): Promise<VirusDefinition[]> {
  const entries = await readdir(dir);
  const yamlFiles = entries.filter((f) => f.endsWith('.yaml') && !NON_DEFINITION_FILES.has(f));

  const results: VirusDefinition[] = [];

  for (const filename of yamlFiles) {
    const file = join(dir, filename);
    const raw = await readFile(file, 'utf8');
    const parsed: unknown = yaml.load(raw);
    const result = VirusDefinitionSchema.safeParse(parsed);
    if (!result.success) {
      throw new DefinitionLoadError(file, result.error.issues);
    }
    results.push(result.data);
  }

  return results;
}
