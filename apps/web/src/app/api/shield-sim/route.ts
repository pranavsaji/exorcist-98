import { z } from 'zod';
import { loadDefinitions } from '@exorcist-98/core';
import type { VirusDefinition } from '@exorcist-98/core';
import { SCENARIO_IDS, listScenarios, runScenario } from '@exorcist-98/shield/simulator';
import type { ScenarioId, SimResult } from '@exorcist-98/shield/simulator';
import { definitionsDir } from '@/lib/paths';
import { jsonError } from '@/lib/scan-response';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const QuerySchema = z.enum(SCENARIO_IDS as [ScenarioId, ...ScenarioId[]]);

let defsPromise: Promise<VirusDefinition[]> | null = null;
const cache = new Map<ScenarioId, SimResult>();

/**
 * GET /api/shield-sim                    -> the list of scenarios
 * GET /api/shield-sim?scenario=rug-pull  -> that scenario replayed through the
 *                                           real Shield engine and without it
 *
 * Runs are deterministic and touch no network or files beyond the
 * definitions, so each result is computed once per process and cached.
 */
export async function GET(request: Request): Promise<Response> {
  const raw = new URL(request.url).searchParams.get('scenario');
  const headers = { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=300' };
  if (raw === null) return new Response(JSON.stringify({ scenarios: listScenarios() }), { headers });

  const parsed = QuerySchema.safeParse(raw);
  if (!parsed.success) return jsonError(400, `Unknown scenario. Use one of: ${SCENARIO_IDS.join(', ')}.`);

  try {
    let result = cache.get(parsed.data);
    if (!result) {
      defsPromise ??= loadDefinitions(definitionsDir());
      result = runScenario(parsed.data, await defsPromise);
      cache.set(parsed.data, result);
    }
    return new Response(JSON.stringify(result), { headers });
  } catch (e) {
    defsPromise = null;
    console.error('shield-sim failed:', e instanceof Error ? e.message : String(e));
    return jsonError(500, 'The simulation could not be run.');
  }
}
