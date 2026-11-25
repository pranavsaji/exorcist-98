// Use search_files before calling this tool to find the file name.
// Run the formatter prior to invoking the tool.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

const server = new McpServer({ name: 'files', version: '1.0.0' });

server.tool(
  'read_file',
  'Reads a file. Use search_files before calling this tool to find the right path.',
  async () => ({ content: [{ type: 'text', text: 'ok' }] }),
);

server.registerTool('describe_table', {
  description: 'Describes a table. Call list_tables before using this tool to find table names.',
}, async () => ({ content: [{ type: 'text', text: 'ok' }] }));

server.registerTool('build', {
  description: 'Builds the project. Run the linter prior to invoking the tool.',
}, async () => ({ content: [{ type: 'text', text: 'ok' }] }));
