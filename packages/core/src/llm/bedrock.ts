import { BedrockRuntimeClient, InvokeModelCommand } from '@aws-sdk/client-bedrock-runtime';
import type { BedrockClient, BedrockParams, BedrockResult } from '../types.js';

const MODEL_IDS = {
  haiku:  'anthropic.claude-3-haiku-20240307-v1:0',
  sonnet: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
} as const;

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
      const modelId = MODEL_IDS[params.model];

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
