#!/usr/bin/env node
// Permission Deck Slice 2 — end-to-end acceptance driver.
// PR merge surfaces in the deck → approve → scoped signed receipt → offline gate
// verifies it green → merge proceeds. Prod SQL migration hard-stops. Wrong scope_sha
// is refused by the gate. Exit 0 = all beats pass.

import { spawn, execFileSync } from 'node:child_process';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 7793;
const BASE = `http://localhost:${PORT}`;
const OUTBOX = join(ROOT, 'infra-mcp', 'outbox.log');
const RECEIPTS = join(ROOT, 'scripts', '.demo2-receipts.jsonl');
const PR = { repo: 'pp/mcp-guard', pr_number: 16, scope_sha: 'abc123def456' };
const SCOPE_REF = `refs/pull/${PR.pr_number}/merge`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const outbox = () => (existsSync(OUTBOX) ? readFileSync(OUTBOX, 'utf8') : '');
let passed = 0, failed = 0;
const check = (n, c) => (c ? (console.log(`  ✓ ${n}`), passed++) : (console.log(`  ✗ ${n}`), failed++));
const api = async (p, m = 'GET') => fetch(`${BASE}${p}`, { method: m }).then((r) => r.json());

// Run the CI gate exactly as a GitHub Action would; return its exit code.
function gate(extraArgs) {
  try {
    execFileSync('node', [join(ROOT, 'scripts/verify-receipt.mjs'), '--receipts-path', RECEIPTS, ...extraArgs], { stdio: 'pipe' });
    return 0;
  } catch (e) { return e.status ?? 1; }
}

for (const f of [OUTBOX, RECEIPTS]) if (existsSync(f)) rmSync(f);

const guard = spawn(
  'node',
  [join(ROOT, 'dist/src/cli.js'), '--config', join(ROOT, 'infra-mcp/pp.config.yaml'),
   '--agent-id', 'charles', '--approval-port', String(PORT),
   '--', 'node', join(ROOT, 'infra-mcp/server.mjs')],
  { stdio: ['pipe', 'pipe', 'inherit'], env: { ...process.env, PP_SHARED_RECEIPTS_PATH: RECEIPTS } },
);
const send = (o) => guard.stdin.write(JSON.stringify(o) + '\n');
let buf = '';
const responses = new Map();
guard.stdout.on('data', (d) => {
  buf += d.toString(); let nl;
  while ((nl = buf.indexOf('\n')) >= 0) { const l = buf.slice(0, nl); buf = buf.slice(nl + 1); if (l.trim()) try { const m = JSON.parse(l); if (m.id != null) responses.set(m.id, m); } catch {} }
});

async function run() {
  await sleep(600);
  send({ jsonrpc: '2.0', id: 0, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'demo2', version: '1' } } });
  await sleep(300);
  send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'merge_pr', arguments: { ...PR, title: 'feat: Permission Deck slice 2' } } });
  send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'run_sql_migration', arguments: { env: 'production', statement: 'ALTER TABLE receipts ADD COLUMN scope_sha text;' } } });
  await sleep(700);

  console.log('\nBeat A — PR merge holds in Decide, gate is red (no receipt):');
  let q = await api('/api/pending');
  const merge = q.find((i) => i.tool_name === 'merge_pr');
  check('merge_pr held in Decide / reversible', merge?.lane === 'decide' && merge?.reversibility === 'reversible');
  check('PR not merged while held (no PR MERGED)', !/PR MERGED/.test(outbox()));
  check('gate RED before approval (no receipt → exit 2)', gate(['--receipt-id', 'rcpt_does_not_exist', '--scope', 'github:merge', '--scope-ref', SCOPE_REF, '--scope-sha', PR.scope_sha]) === 2);

  console.log('\nBeat B — prod SQL migration hard-stops:');
  const sql = q.find((i) => i.tool_name === 'run_sql_migration');
  check('sql migration held, irreversible, NO countdown', sql?.lane === 'decide' && sql?.reversibility === 'irreversible' && sql?.countdown_remaining === undefined);
  check('migration did NOT run (no SQL MIGRATED)', !/SQL MIGRATED/.test(outbox()));

  console.log('\nBeat C — approve PR → scoped signed receipt → merge proceeds:');
  const appr = await api(`/api/approve/${merge.id}`, 'POST');
  check('approve returned a receipt_id', !!appr.receipt_id);
  await sleep(400);
  check('PR merged AFTER approval (PR MERGED in outbox)', /PR MERGED/.test(outbox()));

  console.log('\nBeat D — the receipt is the bridge: offline gate verifies it:');
  check('gate GREEN with correct scope_sha (exit 0)', gate(['--receipt-id', appr.receipt_id, '--scope', 'github:merge', '--scope-ref', SCOPE_REF, '--scope-sha', PR.scope_sha]) === 0);
  check('gate REFUSES wrong scope_sha (exit 1)', gate(['--receipt-id', appr.receipt_id, '--scope', 'github:merge', '--scope-ref', SCOPE_REF, '--scope-sha', 'WRONG_SHA_999']) === 1);

  console.log(`\n${failed === 0 ? '✅ ALL BEATS PASS' : '❌ FAILURES'} — ${passed} passed, ${failed} failed`);
}

run().catch((e) => { console.error('driver error:', e); failed++; })
  .finally(async () => { try { guard.kill('SIGINT'); } catch {} await sleep(200); process.exit(failed === 0 ? 0 : 1); });
