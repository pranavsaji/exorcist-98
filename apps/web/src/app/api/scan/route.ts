import { ScanRequestSchema } from '@/lib/protocol';
import { parseGithubUrl } from '@/lib/github';
import { scanTarget } from '@/lib/scan-service';
import type { ScanTarget } from '@/lib/scan-service';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 120;

function badRequest(message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status: 400,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

export async function POST(request: Request): Promise<Response> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return badRequest('The request body must be JSON.');
  }

  const parsed = ScanRequestSchema.safeParse(body);
  if (!parsed.success) {
    return badRequest(
      'Send either { "target": "haunted-repo" } or { "repoUrl": "https://github.com/owner/repo" }.',
    );
  }

  let target: ScanTarget;
  if ('target' in parsed.data) {
    target = { kind: 'haunted-repo', display: 'Haunted Repo' };
  } else {
    const repo = parseGithubUrl(parsed.data.repoUrl);
    if (!repo) {
      return badRequest('Only public https://github.com/owner/repo links can be scanned.');
    }
    target = { kind: 'github', display: `${repo.owner}/${repo.repo}`, cloneUrl: repo.cloneUrl };
  }

  const encoder = new TextEncoder();
  const iterator = scanTarget(target)[Symbol.asyncIterator]();

  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      const next = await iterator.next();
      if (next.done) {
        controller.close();
      } else {
        controller.enqueue(encoder.encode(`${JSON.stringify(next.value)}\n`));
      }
    },
    async cancel() {
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
