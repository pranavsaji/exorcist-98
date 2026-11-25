import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { homedir } from 'node:os';
import { delimiter } from 'node:path';
import { RootsListChangedNotificationSchema } from '@modelcontextprotocol/sdk/types.js';
import { approvalMessage, explainFindingTool, findDefinitionsDir, quarantineTool, scanMcpConfigTool, scanRepoTool, usableRoots } from './tools.js';
import type { Ctx, ToolText } from './tools.js';

const VERSION = '0.2.0';

const ctx: Ctx = {
  cwd: process.cwd(),
  approved: [],
  definitionsDir: findDefinitionsDir(process.cwd()) ?? '',
  noQuotes: process.env['EXORCIST_MCP_NO_QUOTES'] === '1',
};

const reply = (r: ToolText) => ({ content: [{ type: 'text' as const, text: r.text }], ...(r.isError ? { isError: true } : {}) });

const server = new McpServer({ name: 'exorcist', version: VERSION });

/**
 * Can the client show a form? (Kiro can: it advertises elicitation but no roots.)
 * A client that lists only `url` mode cannot.
 */
const canAsk = (): boolean => {
  const e = server.server.getClientCapabilities()?.elicitation;
  return e !== undefined && (e.form !== undefined || e.url === undefined);
};

/** Ask the person. Only an explicit "accept" with allow=true counts; any error is "no". */
async function askPerson(folder: string): Promise<boolean> {
  try {
    const r = await server.server.elicitInput(
      {
        mode: 'form',
        message: approvalMessage(folder),
        requestedSchema: {
          type: 'object',
          properties: { allow: { type: 'boolean', title: 'Allow for this session', description: 'Yes lets Exorcist 98 read this folder until the server stops. No reads nothing.', default: false } },
          required: ['allow'],
        },
      },
      { timeout: 120_000 },
    );
    return r.action === 'accept' && r.content?.['allow'] === true;
  } catch {
    return false;
  }
}

/**
 * Folders the tools may read besides the start folder (S-018): EXORCIST_ROOTS
 * (separated like PATH) and the roots the client shares through MCP
 * `roots/list`, refreshed when the client says they changed.
 */
let clientRoots: string[] | null = null;
async function refreshRoots(): Promise<void> {
  const fromEnv = (process.env['EXORCIST_ROOTS'] ?? '').split(delimiter);
  const home = homedir();
  let fromClient: string[] = [];
  if (server.server.getClientCapabilities()?.roots) {
    if (clientRoots === null) {
      try {
        clientRoots = (await server.server.listRoots()).roots.map((r) => r.uri);
      } catch {
        clientRoots = [];
      }
    }
    fromClient = clientRoots;
  }
  // Relative paths and "." start in the first client root, else the first EXORCIST_ROOTS
  // folder, else the start folder (Kiro starts a Power's server in the Power's own folder).
  const approved = ctx.approved ?? [];
  ctx.base = usableRoots(fromClient, home)[0] ?? usableRoots(fromEnv, home)[0] ?? approved[0];
  ctx.roots = usableRoots([...fromEnv, ...fromClient, ...approved], home);
}
server.server.setNotificationHandler(RootsListChangedNotificationSchema, async () => { clientRoots = null; });
const withRoots = <A, R>(fn: (c: Ctx, a: A) => Promise<R>) => async (a: A): Promise<R> => {
  await refreshRoots();
  if (canAsk()) ctx.ask = askPerson; else delete ctx.ask;
  return fn(ctx, a);
};

server.registerTool(
  'scan_repo',
  {
    title: 'Scan a folder for attacks on AI agents',
    description:
      'Scan a folder or file inside the project for hidden instructions, poisoned tool descriptions, dangerous hooks and leaked secrets. ' +
      'Returns plain-language findings with file and line. Quoted text is left out unless includeQuotes is true.',
    inputSchema: {
      path: z.string().min(1).describe('Folder or file to scan, relative to the project folder (use "." for the whole project)'),
      maxFindings: z.number().int().min(1).max(100).optional().describe('How many findings to list (default 25)'),
      includeQuotes: z.boolean().optional().describe('Include the matched text, revealed and marked untrusted'),
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  async (a) => reply(await withRoots(scanRepoTool)(a)),
);

server.registerTool(
  'scan_mcp_config',
  {
    title: 'Scan an MCP configuration file',
    description: 'Check an MCP config file (for example .kiro/settings/mcp.json) for risky settings, and say which servers are behind the shield.',
    inputSchema: {
      path: z.string().min(1).describe('Path of the MCP config file, relative to the project folder'),
      includeQuotes: z.boolean().optional(),
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  async (a) => reply(await withRoots(scanMcpConfigTool)(a)),
);

server.registerTool(
  'explain_finding',
  {
    title: 'Explain a rule in plain language',
    description: 'Explain what an Exorcist 98 rule (such as EX-001) detects, what the attacker is doing, and how to fix it.',
    inputSchema: { ruleId: z.string().min(1).describe('A rule id such as EX-001') },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  async (a) => reply(await withRoots(explainFindingTool)(a)),
);

server.registerTool(
  'quarantine',
  {
    title: 'Disable an MCP server and keep a backup',
    description:
      'Disable one MCP server in a config file and keep a restorable backup in the vault. This changes the user\'s configuration: ' +
      'ask the user before calling it, and tell them the restore command afterwards.',
    inputSchema: {
      config: z.string().min(1).describe('Path of the MCP config file, relative to the project folder'),
      server: z.string().min(1).describe('Name of the server to disable'),
      reason: z.string().max(200).optional(),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  },
  async (a) => reply(await withRoots(quarantineTool)(a)),
);

await server.connect(new StdioServerTransport());
