export type ShapeCheck = { id: string; name: string; ok: boolean; detail: string };
export type ShapeResult = { ok: boolean; checks: ShapeCheck[]; dir: string | undefined };
export type McpResponse = { result?: { protocolVersion?: string; serverInfo?: { name?: string; version?: string }; tools?: { name: string }[] } };
export const EXPECTED_TOOLS: readonly string[];
export function cleanEnv(home: string): Record<string, string>;
export function judgeMcpAnswers(responses: Map<number, McpResponse>, expectedVersion: string): ShapeCheck[];
export function runPublishedShapeCheck(options?: { root?: string; build?: boolean; keep?: boolean; log?: (message: string) => void }): Promise<ShapeResult>;
