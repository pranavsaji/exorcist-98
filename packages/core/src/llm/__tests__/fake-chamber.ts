import type { ChamberClient, ChamberRequest, ChamberResult } from '../../types.js';

/**
 * FakeChamberClient for tests only: answers from a queue, records each
 * request, never touches the network. An exhausted queue is a failed call.
 */
export class FakeChamberClient implements ChamberClient {
  public readonly requests: ChamberRequest[] = [];

  constructor(private readonly responses: ChamberResult[] = []) {}

  async converse(request: ChamberRequest): Promise<ChamberResult> {
    // Deep copy: the chamber builds the next turn from new arrays, but a test
    // should see each request exactly as it was sent.
    this.requests.push(JSON.parse(JSON.stringify(request)) as ChamberRequest);
    return this.responses.shift() ?? { ok: false, error: 'no more responses' };
  }
}

let n = 0;
/** A model turn that calls tools. */
export function toolTurn(...calls: Array<[name: string, input: Record<string, unknown>]>): ChamberResult {
  return {
    ok: true,
    body: {
      content: calls.map(([name, input]) => ({ type: 'tool_use', id: `toolu_${++n}`, name, input })),
      stop_reason: 'tool_use',
    },
  };
}

/** A model turn that just answers. */
export function answer(text = 'The file describes the project setup.', stop_reason: string | null = 'end_turn'): ChamberResult {
  return { ok: true, body: { content: [{ type: 'text', text }], stop_reason } };
}
