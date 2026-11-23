import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { BUNDLED_DEFINITIONS_DATE, BUNDLED_DEFINITIONS_VERSION } from '@exorcist-98/core';
import EncyclopediaIndex from '@/app/encyclopedia/page';

describe('Virus Definitions page (m5-liveupdate)', () => {
  it('shows the version and date of the bundled definitions', async () => {
    const html = renderToStaticMarkup(await EncyclopediaIndex());
    expect(html).toContain(`Definitions version ${BUNDLED_DEFINITIONS_VERSION}`);
    expect(html).toContain(`<time dateTime="${BUNDLED_DEFINITIONS_DATE}">${BUNDLED_DEFINITIONS_DATE}</time>`);
    expect(html).toContain('/encyclopedia/EX-001');
  });

  it('reads only the bundled definitions folder, never a LiveUpdate install', async () => {
    const src = await import('node:fs').then((fs) => fs.readFileSync(new URL('../lib/encyclopedia.ts', import.meta.url), 'utf8')
      + fs.readFileSync(new URL('../lib/paths.ts', import.meta.url), 'utf8'));
    expect(src).not.toMatch(/findDefinitionsDir|findActiveInstalledSet|activeDefinitions|installedDefinitionsRoot|\.exorcist/);
  });
});
