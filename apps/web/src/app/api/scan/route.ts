import { ScanRequestSchema } from '@/lib/protocol';
import { parseGithubUrl } from '@/lib/github';
import { scanTarget } from '@/lib/scan-service';
import type { ScanTarget } from '@/lib/scan-service';
import { clientKey, limiter } from '@/lib/limits';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 120;

function jsonError(status: number, message: string, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...extra },
  });
}

export async function POST(request: Request): Promise<Response> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, 'The request body must be JSON.');
  }
  const parsed = ScanRequestSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError(
      400,
      'Send either { "target": "haunted-repo" } or { "repoUrl": "https://github.com/owner/repo" }.',
    );
  }

  let target: ScanTarget;
  if ('target' in parsed.data) {
    target = { kind: 'haunted-repo', display: 'Haunted Repo' };
  } else {
    const repo = parseGithubUrl(parsed.data.repoUrl);
    if (!repo) {
      return jsonError(400, 'Only public https://github.com/owner/repo links can be scanned.');
    }
    target = {
      kind: 'github', display: `${repo.owner}/${repo.repo}${repo.ref ? `@${repo.ref}` : ''}`, owner: repo.owner, repo: repo.repo,
      ...(repo.ref ? { ref: repo.ref } : {}),
    };
  }

  // W-003: a per-visitor rate limit and a cap on scans running at once.
  const slot = limiter.acquire(target.kind, clientKey(request.headers));
  if (!slot.ok) return jsonError(slot.status, slot.error, { 'Retry-After': String(slot.retryAfterSeconds) });

  const encoder = new TextEncoder();
  const iterator = scanTarget(target)[Symbol.asyncIterator]();
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const next = await iterator.next();
        if (next.done) {
          slot.release();
          controller.close();
        } else {
          controller.enqueue(encoder.encode(`${JSON.stringify(next.value)}\n`));
        }
      } catch (err) {
        slot.release();
        throw err;
      }
    },
    async cancel() {
      slot.release();
      // Runs the generator's finally block, which removes any cloned repo.
      await iterator.return?.(undefined);
    },
  });

  return new Response(stream, {
    status: 200,
    headers: {
      'Content-Type': 'application/x-ndjson; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}
