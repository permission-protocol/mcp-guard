#!/usr/bin/env node
// Live internal Permission Deck. Starts the guard (approval API on 7700) wrapping the
// combined 6-tool demo server, serves the console on 7701, seeds a realistic mixed
// queue across all three lanes, and stays up so you can open it and actually use it.
//
//   npm run deck      then open  http://localhost:7701
//
// Approve / Hold / Deny / Undo all work live; approvals issue signed receipts.

import { spawn } from 'node:child_process';
import { createServer, request as httpRequest } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, extname } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const API_PORT = 7700;
const UI_PORT = 7701;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// 1) Guard + approval API, wrapping the combined demo MCP server.
const guard = spawn(
  'node',
  [join(ROOT, 'dist/src/cli.js'), '--config', join(ROOT, 'scripts/deck.config.yaml'),
   '--agent-id', 'charles', '--approval-port', String(API_PORT),
   '--', 'node', join(ROOT, 'scripts/deck-demo-mcp.mjs')],
  { stdio: ['pipe', 'pipe', 'inherit'] },
);
guard.stdout.on('data', () => {}); // drain
const send = (o) => guard.stdin.write(JSON.stringify(o) + '\n');

// 2) Single-origin server: serve the console AND reverse-proxy /api → backend,
//    so one URL (incl. an HTTPS tunnel) drives the whole deck. SSE streams through.
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };
function proxyApi(req, res) {
  const preq = httpRequest(
    { hostname: 'localhost', port: API_PORT, path: req.url, method: req.method,
      headers: { ...req.headers, host: `localhost:${API_PORT}` } },
    (pres) => { res.writeHead(pres.statusCode, pres.headers); pres.pipe(res); },
  );
  preq.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end('deck backend unreachable'); });
  req.pipe(preq);
}
createServer((req, res) => {
  if (req.url.startsWith('/api')) return proxyApi(req, res);
  const rel = (req.url === '/' || req.url.startsWith('/?')) ? '/index.html' : req.url.split('?')[0];
  const file = join(ROOT, 'console', rel);
  if (!file.startsWith(join(ROOT, 'console')) || !existsSync(file)) { res.writeHead(404); return res.end('not found'); }
  res.writeHead(200, { 'Content-Type': MIME[extname(file)] ?? 'text/plain' });
  res.end(readFileSync(file));
}).listen(UI_PORT);

// 3) Seed a realistic mixed queue across all lanes.
async function seed() {
  await sleep(700);
  send({ jsonrpc: '2.0', id: 0, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'deck', version: '1' } } });
  await sleep(300);
  const calls = [
    { name: 'post_x', arguments: { text: 'The "secret patching" incident is the whole argument for external governance in one screenshot.' } },
    { name: 'send_email', arguments: { to: 'patrik@validio.io', subject: 'agent authority layer', body: "Hi Patrik — I'm the founder of Permission Protocol. Most firms running AI agents in production can't answer a simple question: who authorized that action?" } },
    { name: 'spend', arguments: { payee: 'Instantly.ai', amount_usd: 49, memo: 'Cohort-1 verified contacts', _pp: { confidence: 68 } } },
    { name: 'merge_pr', arguments: { repo: 'permission-protocol/mcp-guard', pr_number: 214, title: 'feat: Permission Deck slices 1 & 2' } },
    { name: 'run_sql_migration', arguments: { env: 'production', statement: 'ALTER TABLE receipts ADD COLUMN scope_sha text;' } },
    { name: 'deploy', arguments: { env: 'production', service: 'approval-server', _pp: { requires_input: true } } },
  ];
  calls.forEach((params, i) => send({ jsonrpc: '2.0', id: i + 1, method: 'tools/call', params }));
  await sleep(500);
  process.stderr.write(`\n  ✅ Live Permission Deck is up.\n     Open:  http://localhost:${UI_PORT}\n     (approval API on :${API_PORT}; Ctrl-C to stop)\n\n`);
}
seed();

const stop = () => { try { guard.kill('SIGINT'); } catch {} process.exit(0); };
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
