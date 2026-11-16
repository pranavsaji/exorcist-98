import type { BedrockClient, BedrockParams, BedrockResult } from '../../types.js';

/**
 * FakeBedrockClient for use in tests only.
 * Responses are consumed from the front of the queue in order.
 * If the queue is exhausted, returns { ok: false, error: 'no more responses' }.
 */
export class FakeBedrockClient implements BedrockClient {
  public readonly calls: BedrockParams[] = [];

  constructor(private readonly responses: BedrockResult[] = []) {}

  async call(params: BedrockParams): Promise<BedrockResult> {
    this.calls.push(params);
    const next = this.responses.shift();
    return next ?? { ok: false, error: 'no more responses' };
  }
}
