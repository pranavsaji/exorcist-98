import { scanTarget } from '@/lib/scan-service';
import type { ScanTarget } from '@/lib/scan-service';

/** Stream a scan as NDJSON; `release` runs exactly once when it ends or is cancelled. */
export function scanResponse(target: ScanTarget, release: () => void): Response {
  const encoder = new TextEncoder();
  const iterator = scanTarget(target)[Symbol.asyncIterator]();
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const next = await iterator.next();
        if (next.done) {
          release();
          controller.close();
        } else {
          controller.enqueue(encoder.encode(`${JSON.stringify(next.value)}\n`));
        }
      } catch (err) {
        release();
        throw err;
      }
    },
    async cancel() {
      release();
      // Runs the generator's finally block, which removes any downloaded or uploaded files.
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

export function jsonError(status: number, message: string, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...extra },
  });
}
