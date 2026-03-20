/**
 * Tiny MCP server for testing mcp-guard.
 * Responds to tools/call, tools/list, and initialize.
 * Newline-delimited JSON-RPC over stdio.
 */
import { createInterface } from 'node:readline';

const TOOLS = [
  { name: 'send_email', description: 'Send an email', inputSchema: { type: 'object', properties: { to: { type: 'string' }, body: { type: 'string' } } } },
  { name: 'delete_user_data', description: 'Delete all user data', inputSchema: { type: 'object', properties: { user_id: { type: 'string' } } } },
  { name: 'deploy_production', description: 'Deploy to production', inputSchema: { type: 'object', properties: { version: { type: 'string' } } } },
];

const rl = createInterface({ input: process.stdin });

rl.on('line', (line) => {
  if (!line.trim()) return;

  let msg: any;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }

  if (msg.method === 'initialize') {
    respond(msg.id, {
      protocolVersion: '2024-11-05',
      capabilities: { tools: {} },
      serverInfo: { name: 'example-server', version: '0.1.0' },
    });
  } else if (msg.method === 'tools/list') {
    respond(msg.id, { tools: TOOLS });
  } else if (msg.method === 'tools/call') {
    const toolName = msg.params?.name ?? 'unknown';
    respond(msg.id, {
      content: [{ type: 'text', text: `Executed ${toolName} successfully` }],
    });
  } else if (msg.method === 'notifications/initialized') {
    // No response needed for notifications
  } else {
    respondError(msg.id, -32601, `Method not found: ${msg.method}`);
  }
});

function respond(id: any, result: any) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n');
}

function respondError(id: any, code: number, message: string) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } }) + '\n');
}
