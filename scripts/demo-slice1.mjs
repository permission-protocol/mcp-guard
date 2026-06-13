#!/usr/bin/env node
// Permission Deck Slice 1 — end-to-end acceptance driver.
// Spawns the real guard wrapping the Actions-MCP, exercises the three demo beats
// through the live approval API, and asserts execution evidence from outbox.log.
// Exit 0 = all beats pass.

import { spawn } from 'node:child_process';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 7791;
const BASE = `http://localhost:${PORT}`;
const OUTBOX = join(ROOT, 'actions-mcp', 'outbox.log');
const RECEIPTS = join(ROOT, 'pp-receipts.jsonl');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const outbox = () => (existsSync(OUTBOX) ? readFileSync(OUTBOX, 'utf8') : '');
let passed = 0, failed = 0;
function check(name, cond) {
  if (cond) { console.log(`  ✓ ${name}`); passed++; }
  else { console.log(`  ✗ ${name}`); failed++; }
}
const api = async (path, method = 'GET') =>
  fetch(`${BASE}${path}`, { method }).then((r) => r.json());

// Clean prior run artifacts.
for (const f of [OUTBOX, RECEIPTS]) if (existsSync(f)) rmSync(f);

const guard = spawn(
  'node',
  [
    join(ROOT, 'dist/src/cli.js'),
    '--config', join(ROOT, 'scripts/demo-slice1.config.yaml'),
    '--agent-id', 'charles',
    '--approval-port', String(PORT),
    '--', 'node', join(ROOT, 'actions-mcp/server.mjs'),
  ],
  { stdio: ['pipe', 'pipe', 'inherit'] },
);
const send = (obj) => guard.stdin.write(JSON.stringify(obj) + '\n');

const responses = new Map();
let buf = '';
guard.stdout.on('data', (d) => {
  buf += d.toString();
  let nl;
  while ((nl = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
    if (!line.trim()) continue;
    try { const m = JSON.parse(line); if (m.id != null) responses.set(m.id, m); } catch {}
  }
});

async function run() {
  await sleep(600); // let guard + approval server boot
  send({ jsonrpc: '2.0', id: 0, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'demo', version: '1' } } });
  await sleep(300);

  // Fire the three actions.
  send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'post_x', arguments: { text: 'The secret-patching incident is the whole argument for external governance.' } } });
  send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'spend', arguments: { payee: 'Instantly.ai', amount_usd: 49, _pp: { confidence: 68 } } } });
  send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'send_email', arguments: { to: 'patrik@validio.io', subject: 'agent authority', body: 'I am the founder of Permission Protocol...' } } });
  await sleep(700);

  // --- Beat 2: spend acted under cap + surfaced in Verify ---
  console.log('\nBeat 2 — spend under cap acts + surfaces in Verify:');
  let q = await api('/api/pending');
  const spend = q.find((i) => i.tool_name === 'spend');
  check('spend executed (SPENT in outbox)', /SPENT/.test(outbox()));
  check('spend surfaced in Verify lane', spend?.lane === 'verify');
  check('spend marked confidence 68', spend?.confidence === 68);

  // --- Beat 3 (moat): irreversible post hard-stops, no execution until signed ---
  console.log('\nBeat 3 — irreversible post hard-stops (no receipt, no execution):');
  const post = q.find((i) => i.tool_name === 'post_x');
  check('post_x held in Decide lane', post?.lane === 'decide');
  check('post_x is irreversible (no countdown)', post?.reversibility === 'irreversible' && post?.countdown_remaining === undefined);
  check('post_x did NOT execute while held', !/X POSTED/.test(outbox()));

  // --- Beat 1: reversible email auto-releases on countdown ---
  console.log('\nBeat 1 — reversible email auto-clears on countdown:');
  const email = q.find((i) => i.tool_name === 'send_email');
  check('email held in Decide with a live countdown', email?.lane === 'decide' && typeof email?.countdown_remaining === 'number');
  check('email not yet sent (within countdown)', !/EMAIL SENT/.test(outbox()));
  await sleep(2600); // let the 2s countdown fire
  check('email auto-sent after countdown', /EMAIL SENT/.test(outbox()));

  // --- Approve the held post, completing the moat loop ---
  console.log('\nMoat — approve the post: receipt issued, then it executes:');
  const approve = await api(`/api/approve/${post.id}`, 'POST');
  check('approve returned a receipt_id', !!approve.receipt_id);
  await sleep(400);
  check('post_x executed AFTER approval (X POSTED in outbox)', /X POSTED/.test(outbox()));
  const receipts = await api('/api/receipts');
  const signed = receipts.find((r) => r.signature && r.signature.verified === true && r.signature.algorithm === 'ed25519');
  check('an Ed25519-signed, verified receipt exists', !!signed);

  console.log(`\n${failed === 0 ? '✅ ALL BEATS PASS' : '❌ FAILURES'} — ${passed} passed, ${failed} failed`);
}

run()
  .catch((e) => { console.error('driver error:', e); failed++; })
  .finally(async () => { try { guard.kill('SIGINT'); } catch {} await sleep(200); process.exit(failed === 0 ? 0 : 1); });
