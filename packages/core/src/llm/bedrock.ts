import { BedrockRuntimeClient, InvokeModelCommand } from '@aws-sdk/client-bedrock-runtime';
import type { BedrockClient, BedrockParams, BedrockResult } from '../types.js';

/** Defaults; older model versions can be retired, so each can be overridden. */
export const DEFAULT_MODEL_IDS = {
  haiku:  'anthropic.claude-3-haiku-20240307-v1:0',
  sonnet: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
} as const;

const MODEL_ID_PATTERN = /^[A-Za-z0-9.:_\-\/]{3,200}$/;

/**
 * The Bedrock model id (or inference profile id/ARN) for a role, read at call
 * time: `EXORCIST_BEDROCK_HAIKU` for triage, `EXORCIST_BEDROCK_SONNET` for the
 * judge. A value with unexpected characters is ignored.
 */
export function modelIdFor(model: 'haiku' | 'sonnet', env: Record<string, string | undefined> = process.env): string {
  const v = env[model === 'haiku' ? 'EXORCIST_BEDROCK_HAIKU' : 'EXORCIST_BEDROCK_SONNET']?.trim();
  return v && MODEL_ID_PATTERN.test(v) ? v : DEFAULT_MODEL_IDS[model];
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
