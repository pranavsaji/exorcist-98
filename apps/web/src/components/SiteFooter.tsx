/** The link every static page ends with: a five-minute tour for someone seeing the project for the first time. */
export const START_HERE_URL = 'https://github.com/pranavsaji/exorcist-98/blob/main/docs/START-HERE.md';

export function SiteFooter() {
  return (
    <footer aria-label="Site footer" className="on-desk flex flex-wrap gap-x-4 gap-y-1 pb-4 text-sm font-semibold text-white">
      <a className="underline" href={START_HERE_URL} rel="noopener noreferrer">
        Start here: Exorcist 98 in five minutes
      </a>
      <a className="underline" href="https://github.com/pranavsaji/exorcist-98" rel="noopener noreferrer">
        Source code
      </a>
    </footer>
  );
}
