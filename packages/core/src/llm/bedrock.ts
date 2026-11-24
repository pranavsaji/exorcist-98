import type { BedrockRuntimeClient } from '@aws-sdk/client-bedrock-runtime';
import type { BedrockClient, BedrockParams, BedrockResult, ChamberClient, ChamberRequest, ChamberResult } from '../types.js';

/**
 * Default models (L-020). The original ids (Claude 3 Haiku, Claude 3.5
 * Sonnet, called directly) reached end of life on Bedrock: a real call on
 * 2026-11-20 answered "This model version has reached the end of its life".
 * Current Claude models are only offered through inference profiles, whose id
 * starts with a geography: `us.` keeps traffic in the United States, `eu.` in
 * Europe, `apac.` in Asia Pacific, `global.` anywhere.
 */
export const DEFAULT_MODELS = {
  haiku:  'anthropic.claude-haiku-4-5-20251001-v1:0',
  sonnet: 'anthropic.claude-sonnet-4-6',
} as const;

/** Kept for callers that read the old export. */
export const DEFAULT_MODEL_IDS = DEFAULT_MODELS;

const MODEL_ID_PATTERN = /^[A-Za-z0-9.:_\-\/]{3,200}$/;

/** The inference-profile geography for a region: us, eu, apac, else global. */
export function geographyFor(region: string | undefined): string {
  const r = (region ?? '').toLowerCase();
  if (r.startsWith('us-') || r.startsWith('ca-')) return 'us';
  if (r.startsWith('eu-')) return 'eu';
  if (r.startsWith('ap-')) return 'apac';
  return 'global';
}

/**
 * The Bedrock model id (or inference profile id/ARN) for a role, read at call
 * time: `EXORCIST_BEDROCK_HAIKU` for triage, `EXORCIST_BEDROCK_SONNET` for the
 * judge. A value with unexpected characters is ignored. Without an override,
 * the default model through the inference profile for `AWS_REGION`.
 */
export function modelIdFor(model: 'haiku' | 'sonnet', env: Record<string, string | undefined> = process.env): string {
  const v = env[model === 'haiku' ? 'EXORCIST_BEDROCK_HAIKU' : 'EXORCIST_BEDROCK_SONNET']?.trim();
  if (v && MODEL_ID_PATTERN.test(v)) return v;
  return `${geographyFor(env['AWS_REGION'] ?? env['AWS_DEFAULT_REGION'])}.${DEFAULT_MODELS[model]}`;
}

/** Model calls made by this process, by role (for cost reporting). */
export type CallCounts = { haiku: number; sonnet: number; failed: number };

/**
 * The real Bedrock client. The SDK is loaded the first time a call is made,
 * so programs that bundle this module (the CLI) start and work without it
 * installed until AI analysis is actually asked for.
 */
/** Explicit settings, for hosts that reserve the standard AWS variable names (Vercel). */
export type BedrockClientOptions = {
  region?: string;
  credentials?: { accessKeyId: string; secretAccessKey: string; sessionToken?: string };
};

export class BedrockClientImpl implements BedrockClient, ChamberClient {
  constructor(private readonly opts: BedrockClientOptions = {}) {}
  private client: BedrockRuntimeClient | null = null;
  private sdk: typeof import('@aws-sdk/client-bedrock-runtime') | null = null;
  readonly counts: CallCounts = { haiku: 0, sonnet: 0, failed: 0 };

  private async getClient(): Promise<BedrockRuntimeClient> {
    if (!this.client) {
      const region = this.opts.region ?? process.env['AWS_REGION'] ?? process.env['AWS_DEFAULT_REGION'];
      if (!region) throw new Error('AWS_REGION environment variable is not set');
      this.sdk = await import('@aws-sdk/client-bedrock-runtime');
      this.client = new this.sdk.BedrockRuntimeClient(this.opts.credentials ? { region, credentials: this.opts.credentials } : { region });
    }
    return this.client;
  }

  async call(params: BedrockParams): Promise<BedrockResult> {
    try {
      const client  = await this.getClient();
      const sdk     = this.sdk as typeof import('@aws-sdk/client-bedrock-runtime');
      const modelId = modelIdFor(params.model, this.opts.region ? { ...process.env, AWS_REGION: this.opts.region } : process.env);

      const body = JSON.stringify({
        anthropic_version: 'bedrock-2023-05-31',
        max_tokens:        params.maxTokens,
        messages: [{ role: 'user', content: params.prompt }],
      });

      const cmd = new sdk.InvokeModelCommand({
        modelId,
        contentType: 'application/json',
        accept:      'application/json',
        body:        new TextEncoder().encode(body),
      });

      const response = await client.send(cmd);
      const decoded  = new TextDecoder().decode(response.body);
      const parsed   = JSON.parse(decoded) as { content?: Array<{ text?: string }> };
      const raw      = parsed.content?.[0]?.text ?? '';
      this.counts[params.model]++;
      return { ok: true, raw };
    } catch (err) {
      this.counts.failed++;
      return { ok: false, error: String(err) };
    }
  }

  /**
   * One turn of a Detonation Chamber conversation (m5-detonation): the fast
   * model with fake tools offered. The response body is returned unparsed;
   * the chamber validates it. Nothing here runs a tool.
   */
  async converse(request: ChamberRequest): Promise<ChamberResult> {
    try {
      const client  = await this.getClient();
      const sdk     = this.sdk as typeof import('@aws-sdk/client-bedrock-runtime');
      const body = JSON.stringify({
        anthropic_version: 'bedrock-2023-05-31',
        max_tokens:        request.maxTokens,
        temperature:       request.temperature,
        system:            request.system,
        messages:          request.messages,
        tools:             request.tools,
      });
      const cmd = new sdk.InvokeModelCommand({
        modelId:     modelIdFor('haiku'),
        contentType: 'application/json',
        accept:      'application/json',
        body:        new TextEncoder().encode(body),
      });
      const response = await client.send(cmd);
      const parsed: unknown = JSON.parse(new TextDecoder().decode(response.body));
      this.counts.haiku++;
      return { ok: true, body: parsed };
    } catch (err) {
      this.counts.failed++;
      return { ok: false, error: String(err) };
    }
  }
}

// What the CLI's --ai needs, through `@exorcist-98/core/llm` only.
export type { BedrockClient, BedrockParams, BedrockResult, ChamberClient, ChamberRequest, ChamberResult, ChamberMessage, ChamberTool, ChamberBlock } from '../types.js';
export {
  detonate, buildChamber, decideVerdict, classifyCall, fakeToolResult, parseTurn, makeEnvironment, maskSecrets, isSecretPath,
  PLACEMENTS, MAX_TURNS, MAX_OUTPUT_TOKENS, MAX_DETONATED_CHARS, CHAMBER_TOOLS,
} from './detonation.js';
export type { Placement, FakeEnvironment, AttemptedCall, DetonationReport, DetonationVerdict, DetonateOptions, Chamber, ParsedTurn, HarmKind } from './detonation.js';
export { MAX_SPANS_PER_FILE, judgeText, MAX_JUDGED_CHARS } from '../scanner/heuristic-engine.js';
export type { TextVerdict } from '../scanner/heuristic-engine.js';
