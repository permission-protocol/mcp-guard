// The MCP server `mcp-guard init` wraps for its self-test: one tool that does nothing
// but answer. Nothing real runs when the test call is released.
import { createInterface } from 'node:readline';

export const SELF_TEST_TOOL = 'mcp_guard_self_test';
export const SELF_TEST_SERVER_LABEL = 'mcp-guard-self-test';

const reply = (id: unknown, result: unknown): void => { process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n'); };

if (require.main === module) {
  createInterface({ input: process.stdin }).on('line', (line) => {
    let message: any;
    try { message = JSON.parse(line); } catch { return; }
    if (!message || message.id === undefined || typeof message.method !== 'string') return;
    if (message.method === 'initialize') {
      reply(message.id, { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: SELF_TEST_SERVER_LABEL, version: '1' } });
    } else if (message.method === 'tools/list') {
      reply(message.id, { tools: [{ name: SELF_TEST_TOOL, description: 'Does nothing. Used by mcp-guard init.', inputSchema: { type: 'object' } }] });
    } else if (message.method === 'tools/call') {
      reply(message.id, { content: [{ type: 'text', text: 'mcp-guard self-test: the held call was released' }] });
    } else {
      reply(message.id, {});
    }
  });
}
