'use client';

import { download } from './ReportButtons';
import { patchFile } from '@/lib/report';
import type { ScanState } from '@/lib/scan-state';

type Props = { patch: NonNullable<ScanState['patch']>; target: string };

const plural = (n: number, one: string, many = `${one}s`): string => `${n} ${n === 1 ? one : many}`;

/**
 * The "Clean" half of a 90s antivirus: download a patch with the fixes that
 * have one safe, mechanical answer. Built on the server by the same code as
 * `exorcist exorcise`; nothing in the scanned project is changed.
 */
export function ExorcismPatch({ patch, target }: Props) {
  const file = patchFile(target, patch.patch);
  return (
    <section aria-labelledby="exorcise-heading" className="next-item flex flex-col gap-1">
      <h4 id="exorcise-heading" className="next-title">
        <span className="next-num" aria-hidden="true">1</span> Disinfect
      </h4>
      {patch.fixes > 0 ? (
        <>
          <p id="exorcise-desc" className="m-0 text-xs">
            {plural(patch.fixes, 'threat')} in {plural(patch.files, 'file')} {patch.fixes === 1 ? 'has' : 'have'} a
            safe, mechanical fix (hidden characters, smuggled comments, unpinned MCP servers). The rest needs a human.
            Apply it with <code>git apply {file.filename}</code>.
          </p>
          <div className="flex flex-wrap items-center gap-1">
            <button
              type="button"
              className="btn font-bold"
              aria-describedby="exorcise-desc"
              onClick={() => download(file.filename, file.mime, file.body)}
            >
              Download exorcism patch
            </button>
          </div>
          {patch.omitted > 0 && (
            <p className="m-0 text-xs">
              The patch is capped at 1 MB, so {plural(patch.omitted, 'more changed file')} {patch.omitted === 1 ? 'is' : 'are'} left
              out. Run <code>exorcist exorcise</code> locally for the full set.
            </p>
          )}
          {patch.skipped > 0 && (
            <p className="m-0 text-xs">
              {plural(patch.skipped, 'fixable threat')} could not be fixed safely here (a version could not be looked up)
              and {patch.skipped === 1 ? 'is' : 'are'} left for a human.
            </p>
          )}
        </>
      ) : patch.omitted > 0 ? (
        <p className="m-0 text-xs">
          The fixes for this scan make a patch larger than 1 MB, too big to download here. Run{' '}
          <code>exorcist exorcise</code> in your project to see and apply them.
        </p>
      ) : (
        <p className="m-0 text-xs">
          No threat in this scan has a safe automatic fix. Open each one for the exact line and how to fix it.
        </p>
      )}
    </section>
  );
}
