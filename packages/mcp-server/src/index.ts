import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { explainFindingTool, findDefinitionsDir, quarantineTool, scanMcpConfigTool, scanRepoTool } from './tools.js';
import type { Ctx, ToolText } from './tools.js';

const VERSION = '0.1.0';

const ctx: Ctx = {
  cwd: process.cwd(),
  definitionsDir: findDefinitionsDir(process.cwd()) ?? '',
};

const reply = (r: ToolText) => ({ content: [{ type: 'text' as const, text: r.text }], ...(r.isError ? { isError: true } : {}) });

const server = new McpServer({ name: 'exorcist', version: VERSION });

server.registerTool(
  'scan_repo',
  {
    title: 'Scan a folder for attacks on AI agents',
    description:
      'Scan a folder or file inside the project for hidden instructions, poisoned tool descriptions, dangerous hooks and leaked secrets. ' +
      'Returns plain-language findings with file and line. Quoted text is left out unless includeQuotes is true.',
    inputSchema: {
      path: z.string().min(1).describe('Folder or file to scan, relative to the project folder'),
      maxFindings: z.number().int().min(1).max(100).optional().describe('How many findings to list (default 25)'),
      includeQuotes: z.boolean().optional().describe('Include the matched text, revealed and marked untrusted'),
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  async (a) => reply(await scanRepoTool(ctx, a)),
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
  async (a) => reply(await scanMcpConfigTool(ctx, a)),
);

server.registerTool(
  'explain_finding',
  {
    title: 'Explain a rule in plain language',
    description: 'Explain what an Exorcist 98 rule (such as EX-001) detects, what the attacker is doing, and how to fix it.',
    inputSchema: { ruleId: z.string().min(1).describe('A rule id such as EX-001') },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  async (a) => reply(await explainFindingTool(ctx, a)),
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
  async (a) => reply(await quarantineTool(ctx, a)),
);

await server.connect(new StdioServerTransport());
