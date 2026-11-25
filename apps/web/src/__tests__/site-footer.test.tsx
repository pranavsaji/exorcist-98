/** FF-2.8: the site footer links docs/START-HERE.md from every static page. */
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import ProductPage from '@/app/product/page';
import HowKiroPage from '@/app/how-kiro/page';
import { RetroFrame } from '@/components/RetroFrame';
import { SiteFooter, START_HERE_URL } from '@/components/SiteFooter';

const HREF = 'https://github.com/pranavsaji/exorcist-98/blob/main/docs/START-HERE.md';

describe('site footer', () => {
  it('FF-2.8 the footer link points at docs/START-HERE.md on the main branch', () => {
    expect(START_HERE_URL).toBe(HREF);
    const html = renderToStaticMarkup(<SiteFooter />);
    expect(html).toContain(`href="${HREF}"`);
    expect(html).toContain('Start here: Exorcist 98 in five minutes');
    expect(html).toContain('<footer');
  });

  it('FF-2.8 the product page, the Kiro page and a framed page (Threat Encyclopedia) all end with it', () => {
    for (const html of [renderToStaticMarkup(<ProductPage />), renderToStaticMarkup(<HowKiroPage />), renderToStaticMarkup(<RetroFrame title="x">y</RetroFrame>)]) {
      expect(html).toContain(`href="${HREF}"`);
      expect(html.indexOf('<footer')).toBeGreaterThan(html.indexOf('</main>'));
    }
  });
});
