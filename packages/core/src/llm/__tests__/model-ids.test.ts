import { describe, expect, it } from 'vitest';
import { DEFAULT_MODEL_IDS, modelIdFor } from '../bedrock.js';

describe('L-020 Bedrock model ids are configurable', () => {
  it('uses the defaults when nothing is set', () => {
    expect(modelIdFor('haiku', {})).toBe(DEFAULT_MODEL_IDS.haiku);
    expect(modelIdFor('sonnet', {})).toBe(DEFAULT_MODEL_IDS.sonnet);
  });

  it('accepts model ids, inference profile ids and ARNs from the environment', () => {
    expect(modelIdFor('haiku', { EXORCIST_BEDROCK_HAIKU: 'us.anthropic.claude-3-5-haiku-20241022-v1:0' })).toBe('us.anthropic.claude-3-5-haiku-20241022-v1:0');
    const arn = 'arn:aws:bedrock:us-west-2:000000000000:inference-profile/us.anthropic.example-v1:0';
    expect(modelIdFor('sonnet', { EXORCIST_BEDROCK_SONNET: arn })).toBe(arn);
  });

  it('ignores empty or odd values', () => {
    for (const bad of ['', '   ', 'model id with spaces', 'x;rm -rf /', 'a'.repeat(201)]) {
      expect(modelIdFor('haiku', { EXORCIST_BEDROCK_HAIKU: bad })).toBe(DEFAULT_MODEL_IDS.haiku);
    }
  });
});
