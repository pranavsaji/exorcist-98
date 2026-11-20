import { BedrockRuntimeClient, InvokeModelCommand } from '@aws-sdk/client-bedrock-runtime';
import type { BedrockClient, BedrockParams, BedrockResult } from '../types.js';

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

export class BedrockClientImpl implements BedrockClient {
  private client: BedrockRuntimeClient | null = null;

  private getClient(): BedrockRuntimeClient {
    if (!this.client) {
      const region = process.env['AWS_REGION'];
      if (!region) throw new Error('AWS_REGION environment variable is not set');
      this.client = new BedrockRuntimeClient({ region });
    }
    return this.client;
  }

  async call(params: BedrockParams): Promise<BedrockResult> {
    try {
      const client  = this.getClient();
      const modelId = modelIdFor(params.model);

      const body = JSON.stringify({
        anthropic_version: 'bedrock-2023-05-31',
        max_tokens:        params.maxTokens,
        messages: [{ role: 'user', content: params.prompt }],
      });

      const cmd = new InvokeModelCommand({
        modelId,
        contentType: 'application/json',
        accept:      'application/json',
        body:        new TextEncoder().encode(body),
      });

      const response = await client.send(cmd);
      const decoded  = new TextDecoder().decode(response.body);
      const parsed   = JSON.parse(decoded) as { content?: Array<{ text?: string }> };
      const raw      = parsed.content?.[0]?.text ?? '';
      return { ok: true, raw };
    } catch (err) {
      return { ok: false, error: String(err) };
    }
  }
}
