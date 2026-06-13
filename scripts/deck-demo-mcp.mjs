#!/usr/bin/env node
// Combined demo MCP server for the live internal Permission Deck — exposes all six
// action tools (comms + spend + code/infra) behind one guard so a single deck governs
// everything. Zero-dependency stdio JSON-RPC, same stub pattern as actions-mcp/infra-mcp.

import { appendFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUTBOX = join(__dirname, '..', 'deck-outbox.log');
const log = (line) => appendFileSync(OUTBOX, `[${new Date().toISOString()}] ${line}\n`);

const TOOLS = {
  send_email: { desc: 'Send an email', props: { to: 'string', subject: 'string', body: 'string' },
    run: (a) => `Email sent to ${a.to}: ${a.subject}` },
  post_x: { desc: 'Post to X', props: { text: 'string' },
    run: (a) => `Posted to X: ${String(a.text).slice(0, 40)}…` },
  spend: { desc: 'Spend money', props: { payee: 'string', amount_usd: 'number', memo: 'string' },
    run: (a) => `Spent $${a.amount_usd} to ${a.payee}` },
  merge_pr: { desc: 'Merge a pull request', props: { repo: 'string', pr_number: 'number', title: 'string' },
    run: (a) => `PR MERGED ${a.repo}#${a.pr_number}` },
  run_sql_migration: { desc: 'Run a SQL migration', props: { env: 'string', statement: 'string' },
    run: (a) => `SQL MIGRATED env=${a.env}` },
  deploy: { desc: 'Deploy a service', props: { env: 'string', service: 'string' },
    run: (a) => `DEPLOYED ${a.service} to ${a.env}` },
};

const toolList = Object.entries(TOOLS).map(([name, t]) => ({
  name, description: t.desc,
  inputSchema: {
    type: 'object',
    properties: Object.fromEntries([
      ...Object.entries(t.props).map(([k, ty]) => [k, { type: ty }]),
      ['_pp', { type: 'object', description: 'Permission Deck metadata (confidence, etc.)' }],
    ]),
  },
}));

const send = (o) => process.stdout.write(JSON.stringify(o) + '\n');
const ok = (id, result) => send({ jsonrpc: '2.0', id, result });
const err = (id, code, message) => send({ jsonrpc: '2.0', id, error: { code, message } });

createInterface({ input: process.stdin }).on('line', (line) => {
  if (!line.trim()) return;
  let m; try { m = JSON.parse(line); } catch { return; }
  const { id, method, params } = m;
  switch (method) {
    case 'initialize':
      return ok(id, { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'deck-demo-mcp', version: '0.1.0' } });
    case 'notifications/initialized': return;
    case 'ping': return ok(id, {});
    case 'tools/list': return ok(id, { tools: toolList });
    case 'tools/call': {
      const t = TOOLS[params?.name];
      if (!t) return err(id, -32602, `Unknown tool: ${params?.name}`);
      const msg = t.run(params.arguments ?? {});
      log(msg);
      return ok(id, { content: [{ type: 'text', text: msg }], isError: false });
    }
    default:
      if (id !== undefined) return err(id, -32601, `Method not found: ${method}`);
  }
});
