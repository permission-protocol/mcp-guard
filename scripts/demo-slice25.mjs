#!/usr/bin/env node
// Permission Deck Slice 2.5 — end-to-end acceptance driver (no agent in the loop).
// A signed GitHub webhook for a labeled PR → Decide card in the deck → approve →
// scoped signed receipt → offline gate verifies it green. Bad signature is rejected;
// an unlabeled PR is ignored. Exit 0 = all beats pass.

import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 7795;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = 'deck-webhook-secret';
const RECEIPTS = join(ROOT, 'scripts', '.demo25-receipts.jsonl');
const PUBKEY = join(ROOT, 'scripts', '.demo25.pub.pem');
const TOKEN = crypto.randomBytes(32).toString('hex'); // approval API access token for this run
const AUTH = { Authorization: `Bearer ${TOKEN}` };
const PR = 16, REPO = 'permission-protocol/mcp-guard', SHA = 'abc123def456';
const SCOPE_REF = `refs/pull/${PR}/merge`;

process.env.PP_WEBHOOK_SECRET = SECRET;
process.env.PP_SHARED_RECEIPTS_PATH = RECEIPTS;
if (existsSync(RECEIPTS)) rmSync(RECEIPTS);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let passed = 0, failed = 0;
const check = (n, c) => (c ? (console.log(`  ✓ ${n}`), passed++) : (console.log(`  ✗ ${n}`), failed++));
const sign = (body) => 'sha256=' + crypto.createHmac('sha256', SECRET).update(body).digest('hex');

async function post(path, body, sig) {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(sig ? { 'X-Hub-Signature-256': sig } : {}) },
    body,
  });
  return { status: res.status, json: await res.json().catch(() => ({})) };
}
const api = (p, m = 'GET') => fetch(`${BASE}${p}`, { method: m, headers: AUTH }).then((r) => r.json());

function gate(args) {
  try { execFileSync('node', [join(ROOT, 'scripts/verify-receipt.mjs'), '--receipts-path', RECEIPTS, '--pubkey', PUBKEY, ...args], { stdio: 'pipe' }); return 0; }
  catch (e) { return e.status ?? 1; }
}

const prPayload = (over = {}) => JSON.stringify({
  action: 'labeled',
  repository: { full_name: REPO },
  pull_request: {
    number: PR, title: 'feat: permission deck slices', head: { sha: SHA },
    html_url: `https://github.com/${REPO}/pull/${PR}`,
    labels: [{ name: 'needs-authority' }],
  },
  ...over,
});

async function run() {
  const { startApprovalServer } = await import('../dist/src/approval-server.js');
  const { exportPublicKey } = await import('../dist/src/signer.js');
  exportPublicKey(PUBKEY); // pin the key, exactly as a CI gate would
  const server = startApprovalServer({ port: PORT, token: TOKEN });
  await server.ready;

  console.log('\nBeat A — bad signature is rejected (fail closed):');
  const bad = await post('/api/github/webhook', prPayload(), 'sha256=deadbeef');
  check('rejected with 401', bad.status === 401);

  console.log('\nBeat B — unlabeled PR is ignored:');
  const noLabel = prPayload();
  const unl = JSON.stringify({ ...JSON.parse(noLabel), pull_request: { ...JSON.parse(noLabel).pull_request, labels: [{ name: 'chore' }] } });
  const ig = await post('/api/github/webhook', unl, sign(unl));
  check('ignored (200, not queued)', ig.status === 200 && ig.json.ignored === true);

  console.log('\nBeat C — signed labeled PR queues as a Decide card:');
  const body = prPayload();
  const wh = await post('/api/github/webhook', body, sign(body));
  check('accepted (202 queued)', wh.status === 202 && wh.json.queued === true);
  const q = await api('/api/pending');
  const item = q.find((i) => i.tool_name === 'merge_pr' && i.id === wh.json.id);
  check('appears in Decide lane', item && item.lane === 'decide');

  console.log('\nBeat D — approve in the deck → scoped signed receipt:');
  const appr = await api(`/api/approve/${wh.json.id}`, 'POST');
  check('approve returned a receipt_id', !!appr.receipt_id);

  console.log('\nBeat E — the offline gate verifies it (the bridge):');
  check('gate GREEN with correct scope and head SHA (exit 0)', gate(['--receipt-id', appr.receipt_id, '--scope', 'github:merge', '--scope-ref', SCOPE_REF, '--scope-sha', SHA]) === 0);
  check('gate REFUSES wrong PR ref (exit 1)', gate(['--receipt-id', appr.receipt_id, '--scope', 'github:merge', '--scope-ref', 'refs/pull/999/merge']) === 1);

  console.log('\nBeat F — a denied PR can never be approved afterwards:');
  const body2 = prPayload({ pull_request: { ...JSON.parse(prPayload()).pull_request, number: PR + 1 } });
  const wh2 = await post('/api/github/webhook', body2, sign(body2));
  const denied = await fetch(`${BASE}/api/deny/${wh2.json.id}`, { method: 'POST', headers: AUTH });
  const late = await fetch(`${BASE}/api/approve/${wh2.json.id}`, { method: 'POST', headers: AUTH });
  check('deny accepted (200)', denied.status === 200);
  check('approve after deny refused (409)', late.status === 409);

  await server.close();
  console.log(`\n${failed === 0 ? '✅ ALL BEATS PASS' : '❌ FAILURES'} — ${passed} passed, ${failed} failed`);
}

run().catch((e) => { console.error('driver error:', e); failed++; })
  .finally(async () => { await sleep(150); if (existsSync(RECEIPTS)) rmSync(RECEIPTS); process.exit(failed === 0 ? 0 : 1); });
