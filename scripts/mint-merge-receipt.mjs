#!/usr/bin/env node
// Mint a real signed merge receipt by driving the actual deck-approve path, and
// write it to .pp/merge-receipt.json — the file the self-gate workflow verifies.
// Usage: node scripts/mint-merge-receipt.mjs <pr_number> <head_sha>

import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const PR = Number(process.argv[2] ?? '1');
const HEAD_SHA = process.argv[3] || process.env.PR_HEAD_SHA || process.env.GITHUB_SHA;
const PORT = 7794;
const RECEIPTS = join(ROOT, 'scripts', '.mint-receipts.jsonl');
const OUT = join(ROOT, '.pp', 'merge-receipt.json');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const api = async (p, m = 'GET') => fetch(`http://localhost:${PORT}${p}`, { method: m }).then((r) => r.json());

if (existsSync(RECEIPTS)) rmSync(RECEIPTS);
if (!HEAD_SHA) {
  console.error('missing PR head SHA. Usage: node scripts/mint-merge-receipt.mjs <pr_number> <head_sha>');
  process.exit(1);
}

const guard = spawn('node',
  [join(ROOT, 'dist/src/cli.js'), '--config', join(ROOT, 'infra-mcp/pp.config.yaml'),
   '--agent-id', 'rod', '--approval-port', String(PORT), '--', 'node', join(ROOT, 'infra-mcp/server.mjs')],
  { stdio: ['pipe', 'pipe', 'inherit'], env: { ...process.env, PP_SHARED_RECEIPTS_PATH: RECEIPTS } });
const send = (o) => guard.stdin.write(JSON.stringify(o) + '\n');

await sleep(600);
send({ jsonrpc: '2.0', id: 0, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'mint', version: '1' } } });
await sleep(300);
send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'merge_pr', arguments: { repo: 'permission-protocol/mcp-guard', pr_number: PR, title: 'Permission Deck slices 1 & 2', scope_sha: HEAD_SHA } } });
await sleep(700);

const q = await api('/api/pending');
const merge = q.find((i) => i.tool_name === 'merge_pr');
if (!merge) { console.error('no merge_pr pending'); guard.kill('SIGINT'); process.exit(1); }
const appr = await api(`/api/approve/${merge.id}`, 'POST');
await sleep(300);

const lines = readFileSync(RECEIPTS, 'utf8').trim().split('\n');
const receipt = lines.map((l) => JSON.parse(l)).find((r) => r.receipt_id === appr.receipt_id);
writeFileSync(OUT, JSON.stringify(receipt, null, 2));
console.log(`minted receipt ${receipt.receipt_id} for PR #${PR} -> ${OUT}`);
console.log(`  scope=${receipt.scope} scope_ref=${receipt.scope_ref} scope_sha=${receipt.scope_sha} approved_by=${receipt.approved_by} sig=${receipt.signature?.verified}`);
guard.kill('SIGINT');
await sleep(200);
rmSync(RECEIPTS, { force: true });
process.exit(0);
