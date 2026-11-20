import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { fetchGithubRepo } from '../remote/tarball.js';
import { scanRepo } from '../scanner/orchestrator.js';
import { toJson } from '../reporters/json-reporter.js';
import type { Finding, ScanStats } from '../types.js';
import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';

// ── Environment validation (checked at first call, not module load) ───────────

const EnvSchema = z.object({
  AWS_REGION:       z.string().min(1),
  // scripts/build-lambda.mjs puts definitions/ next to the bundle, which Lambda
  // unpacks to /var/task.
  DEFINITIONS_PATH: z.string().min(1).default('/var/task/definitions'),
});

// ── Request schema ────────────────────────────────────────────────────────────

// Same rule as the web app: https://github.com/<owner>/<repo>, nothing else.
const GITHUB_REPO = /^https:\/\/github\.com\/([A-Za-z0-9_.-]{1,100})\/([A-Za-z0-9_.-]{1,100}?)(?:\.git)?\/?$/;
const BodySchema = z.object({
  repoUrl: z
    .string()
    .max(200)
    .refine(u => GITHUB_REPO.test(u), {
      message: 'Only https://github.com/owner/repo URLs are accepted',
    }),
});

// ── Handler ───────────────────────────────────────────────────────────────────

export async function handler(
  event: APIGatewayProxyEventV2,
): Promise<APIGatewayProxyResultV2> {
  // Validate environment
  const env = EnvSchema.safeParse(process.env);
  if (!env.success) {
    console.error('[exorcist] missing environment variables:', env.error.format());
    return json(500, { error: 'internal' });
  }

  // Parse and validate body
  let body: unknown;
  try {
    body = JSON.parse(event.body ?? '{}');
  } catch {
    return json(400, { error: 'request body must be valid JSON' });
  }

  const parsed = BodySchema.safeParse(body);
  if (!parsed.success) {
    return json(400, { error: parsed.error.issues[0]?.message ?? 'invalid request' });
  }

  const { repoUrl } = parsed.data;
  const tmpDir = join('/tmp', randomUUID());

  try {
    // A tarball over HTTPS with size, file-count and time limits; Lambda has
    // no git binary (L-031).
    const [, owner = '', repo = ''] = GITHUB_REPO.exec(repoUrl) ?? [];
    const fetched = await fetchGithubRepo({ owner, repo, dir: tmpDir });
    if (!fetched.ok) return json(400, { error: fetched.error });

    const findings: Finding[] = [];
    let stats: ScanStats | null = null;

    for await (const ev of scanRepo(tmpDir, { definitionsDir: env.data.DEFINITIONS_PATH })) {
      if (ev.type === 'finding') findings.push(ev.finding);
      if (ev.type === 'done')    stats = ev.stats;
    }

    const report = toJson(findings, stats ?? {
      filesScanned: 0, filesSkipped: 0, findingsTotal: 0, durationMs: 0,
    }, { target: repoUrl });

    // Log summary only — never log file contents
    console.log(JSON.stringify({
      repoUrl,
      filesScanned:  stats?.filesScanned,
      findingsTotal: stats?.findingsTotal,
      durationMs:    stats?.durationMs,
    }));

    return json(200, report);
  } catch (err) {
    console.error('[exorcist] scan error:', String(err));
    return json(500, { error: 'internal' });
  } finally {
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {/* best-effort */});
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function json(statusCode: number, body: unknown): APIGatewayProxyResultV2 {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  };
}
