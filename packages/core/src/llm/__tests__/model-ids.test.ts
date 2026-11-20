import { describe, expect, it } from 'vitest';
import { DEFAULT_MODELS, geographyFor, modelIdFor } from '../bedrock.js';

describe('L-020 Bedrock model ids are configurable', () => {
  it('defaults to current models through the inference profile for the region', () => {
    expect(modelIdFor('haiku', { AWS_REGION: 'us-east-2' })).toBe(`us.${DEFAULT_MODELS.haiku}`);
    expect(modelIdFor('sonnet', { AWS_REGION: 'eu-west-1' })).toBe(`eu.${DEFAULT_MODELS.sonnet}`);
    expect(modelIdFor('haiku', { AWS_REGION: 'ap-southeast-2' })).toBe(`apac.${DEFAULT_MODELS.haiku}`);
    expect(modelIdFor('haiku', {})).toBe(`global.${DEFAULT_MODELS.haiku}`);
    expect(geographyFor('sa-east-1')).toBe('global');
  });

  it('never defaults to the retired Claude 3 ids', () => {
    for (const m of ['haiku', 'sonnet'] as const) expect(modelIdFor(m, { AWS_REGION: 'us-east-1' })).not.toMatch(/claude-3/);
  });

  it('accepts model ids, inference profile ids and ARNs from the environment', () => {
    expect(modelIdFor('haiku', { EXORCIST_BEDROCK_HAIKU: 'us.anthropic.claude-3-5-haiku-20241022-v1:0' })).toBe('us.anthropic.claude-3-5-haiku-20241022-v1:0');
    const arn = 'arn:aws:bedrock:us-west-2:000000000000:inference-profile/us.anthropic.example-v1:0';
    expect(modelIdFor('sonnet', { EXORCIST_BEDROCK_SONNET: arn })).toBe(arn);
  });

  it('ignores empty or odd values', () => {
    for (const bad of ['', '   ', 'model id with spaces', 'x;rm -rf /', 'a'.repeat(201)]) {
      expect(modelIdFor('haiku', { EXORCIST_BEDROCK_HAIKU: bad, AWS_REGION: 'us-east-1' })).toBe(`us.${DEFAULT_MODELS.haiku}`);
    }
  });
});
