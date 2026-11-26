import { describe, expect, it } from 'vitest';
import { add } from './math';
describe('add', () => {
  it('adds two numbers', () => expect(add(1, 2)).toBe(3));
  it.skip('handles bigints (not supported yet)', () => expect(add(1n, 2n)).toBe(3n));
  it.todo('overflow');
});
