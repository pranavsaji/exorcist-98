import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Environment stub ──────────────────────────────────────────────────────────
// Set required env vars before the module is imported
process.env['AWS_REGION']       = 'us-east-1';
process.env['DEFINITIONS_PATH'] = '/definitions';

// Mock the tarball download so the handler never makes a real network call
vi.mock('../remote/tarball.js', () => ({
  fetchGithubRepo: vi.fn().mockImplementation(async ({ repo }: { repo: string }) =>
    repo === 'missing' ? { ok: false, error: 'That repository was not found, or it is private.' } : { ok: true, files: 1, skipped: 0 }),
}));

// Mock scanRepo so we don't need a real definitions dir
vi.mock('../scanner/orchestrator.js', () => ({
  scanRepo: async function* () {
    yield { type: 'done', stats: { filesScanned: 1, filesSkipped: 0, findingsTotal: 0, durationMs: 5 } };
  },
}));

// Mock fs/promises rm so cleanup doesn't fail in test env
vi.mock('node:fs/promises', async (importOriginal) => {
  const orig = await importOriginal<typeof import('node:fs/promises')>();
  return { ...orig, rm: vi.fn().mockResolvedValue(undefined) };
});

import { handler } from '../lambda/handler.js';
import type { APIGatewayProxyEventV2 } from 'aws-lambda';

function makeEvent(body: unknown): APIGatewayProxyEventV2 {
  return {
    body: JSON.stringify(body),
    headers: {},
    isBase64Encoded: false,
    rawPath: '/scan',
    rawQueryString: '',
    requestContext: {} as APIGatewayProxyEventV2['requestContext'],
    routeKey: 'POST /scan',
    version: '2.0',
  };
}

describe('Lambda handler', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('a non-GitHub URL returns HTTP 400', async () => {
    const result = await handler(makeEvent({ repoUrl: 'https://gitlab.com/foo/bar' }));
    expect(typeof result !== 'string' && 'statusCode' in result ? result.statusCode : null).toBe(400);
  });

  it('an invalid JSON body returns HTTP 400', async () => {
    const event = { ...makeEvent({}), body: 'not json' };
    const result = await handler(event);
    expect(typeof result !== 'string' && 'statusCode' in result ? result.statusCode : null).toBe(400);
  });

  it('a valid GitHub URL returns HTTP 200', async () => {
    const result = await handler(makeEvent({ repoUrl: 'https://github.com/owner/repo' }));
    expect(typeof result !== 'string' && 'statusCode' in result ? result.statusCode : null).toBe(200);
  });

  it('the success response has Content-Type application/json', async () => {
    const result = await handler(makeEvent({ repoUrl: 'https://github.com/owner/repo' }));
    if (typeof result !== 'string' && 'headers' in result) {
      expect(result.headers?.['Content-Type']).toBe('application/json');
    }
  });

  it('error response bodies never contain stack traces', async () => {
    const result = await handler(makeEvent({ repoUrl: 'https://gitlab.com/x' }));
    if (typeof result !== 'string' && 'body' in result) {
      expect(result.body).not.toContain('at ');
      expect(result.body).not.toContain('.ts:');
    }
  });
  it('a repository that cannot be downloaded returns HTTP 400 with a plain reason', async () => {
    const result = await handler(makeEvent({ repoUrl: 'https://github.com/owner/missing' }));
    if (typeof result !== 'string' && 'statusCode' in result) {
      expect(result.statusCode).toBe(400);
      expect(result.body).toContain('not found');
    }
  });
  it('rejects extra paths and credentials in the URL', async () => {
    for (const repoUrl of ['https://github.com/o/r/../x', 'https://u:p@github.com/o/r', 'https://github.com/o']) {
      const result = await handler(makeEvent({ repoUrl }));
      expect(typeof result !== 'string' && 'statusCode' in result ? result.statusCode : null, repoUrl).toBe(400);
    }
  });
});
