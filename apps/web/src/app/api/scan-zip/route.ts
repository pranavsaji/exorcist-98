import { DEFAULT_ZIP_LIMITS } from '@exorcist-98/core';
import { readCapped } from '@/lib/read-capped';
import { clientKey, limiter } from '@/lib/limits';
import { jsonError, scanResponse } from '@/lib/scan-response';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 120;

const ZIP_TYPES = new Set(['application/zip', 'application/x-zip-compressed', 'application/octet-stream']);
const MAX = DEFAULT_ZIP_LIMITS.maxZipBytes;
const TOO_BIG = `The ZIP file is larger than ${Math.round(MAX / 1048576)} MB. Remove node_modules, build output and assets, or run the Exorcist 98 CLI locally.`;

/** The upload's display name: a plain file name, or a neutral label. Never a path. */
function displayName(raw: string | null): string {
  let name = '';
  try { name = decodeURIComponent(raw ?? ''); } catch { name = ''; }
  name = name.split(/[\\/]/).pop() ?? '';
  return /^[A-Za-z0-9 ._()-]{1,80}\.zip$/i.test(name) ? name : 'your ZIP file';
}


/**
 * POST a ZIP of a project as the raw body (Content-Type application/zip).
 * The files are unpacked to a temporary folder, scanned and deleted; nothing
 * is kept (L-032).
 */
export async function POST(request: Request): Promise<Response> {
  const type = (request.headers.get('content-type') ?? '').split(';')[0]?.trim().toLowerCase() ?? '';
  if (!ZIP_TYPES.has(type)) return jsonError(415, 'Send the ZIP file itself, with Content-Type: application/zip.');
  const declared = Number(request.headers.get('content-length') ?? '0');
  if (declared > MAX) return jsonError(413, TOO_BIG);
  const slot = limiter.acquire('upload', clientKey(request.headers));
  if (!slot.ok) return jsonError(slot.status, slot.error, { 'Retry-After': String(slot.retryAfterSeconds) });
  let zip: Buffer | null;
  try {
    zip = await readCapped(request, MAX);
  } catch {
    slot.release();
    return jsonError(400, 'The upload was interrupted.');
  }
  if (zip === null) { slot.release(); return jsonError(413, TOO_BIG); }
  if (zip.length === 0) { slot.release(); return jsonError(400, 'The upload was empty.'); }
  return scanResponse({ kind: 'upload', display: displayName(request.headers.get('x-file-name')), zip }, slot.release);
}
