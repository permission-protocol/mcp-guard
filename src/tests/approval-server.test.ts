import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { request } from 'node:http';
import { networkInterfaces } from 'node:os';
import { readFileSync, existsSync, writeFileSync } from 'node:fs';
import { startApprovalServer, type ApprovalServerHandle } from '../approval-server.js';
import { addPending, surfaceActed, getAction, _resetQueue, setAutoReleaseHandler, type PendingEnrichment } from '../pending.js';
import type { IssuedReceipt } from '../issuer.js';
import { derivePreview, buildEnrichment } from '../proxy.js';
import type { Decision } from '../engine.js';
import { keySetPath } from '../keystore.js';
import { isolateKeys, testIssuer } from './helpers.js';

const TOKEN = 'test-token-0123456789abcdef0123456789abcdef';
const SECRET = 'approval-test-webhook-secret';
let handle: ApprovalServerHandle;
let BASE = '';
let PORT = 0;
const released: Array<{ id: string; issued: IssuedReceipt }> = [];

const auth = { Authorization: `Bearer ${TOKEN}` };
const get = (path: string, headers: Record<string, string> = auth) => fetch(`${BASE}${path}`, { headers });
const post = (path: string, headers: Record<string, string> = auth) => fetch(`${BASE}${path}`, { method: 'POST', headers });

function enrichment(over: Partial<PendingEnrichment> = {}): PendingEnrichment {
  return { lane: 'decide', reversibility: 'reversible', countdown_seconds: 5, summary: 'Send email to a@b.com', args_preview: 'hello body', ...over };
}

function add(over: Partial<PendingEnrichment> = {}, resolve: (l: string) => void = () => {}) {
  return addPending({
    toolName: 'send_email',
    toolArgs: { to: 'a@b.com', body: 'hello body', bcc: 'hidden@x.com' },
    agentId: 'agent-1',
    ruleId: 'rule-email',
    forwardLine: '{"jsonrpc":"2.0","id":1,"method":"tools/call"}',
    jsonrpcId: 1,
    resolve,
    enrichment: enrichment(over),
  });
}

function rawRequest(path: string, headers: Record<string, string>): Promise<{ status: number; headers: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port: PORT, path, method: 'GET', headers }, (res) => {
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers }));
    });
    req.on('error', reject);
    req.end();
  });
}

describe('Approval server', () => {
  before(async () => {
    isolateKeys();
    process.env.PP_WEBHOOK_SECRET = SECRET;
    handle = startApprovalServer({
      port: 0,
      token: TOKEN,
      operator: 'rod',
      issuer: testIssuer(),
      hooks: { release: (action, issued) => { released.push({ id: action.id, issued }); } },
    });
    PORT = await handle.ready;
    BASE = `http://127.0.0.1:${PORT}`;
    setAutoReleaseHandler(null);
  });
  after(() => handle.close());
  beforeEach(() => {
    _resetQueue();
    released.length = 0;
  });

  it('listens on 127.0.0.1 only', async () => {
    const external = Object.values(networkInterfaces()).flat()
      .find((i) => i && i.family === 'IPv4' && !i.internal);
    assert.equal((await get('/api/pending')).status, 200);
    if (!external) return; // no non-loopback interface in this environment
    const r = await fetch(`http://${external.address}:${PORT}/api/pending`, { headers: auth }).then(() => 'reachable', () => 'refused');
    assert.equal(r, 'refused');
  });

  it('refuses a token shorter than 32 characters', () => {
    assert.throws(() => startApprovalServer({ port: 0, token: 'short', issuer: testIssuer() }), /at least 32/);
  });

  it('rejects a foreign Host header with 421 (DNS rebinding)', async () => {
    const r = await rawRequest('/api/pending', { Host: 'evil.example', ...auth });
    assert.equal(r.status, 421);
    const ok = await rawRequest('/api/pending', { Host: `localhost:${PORT}`, ...auth });
    assert.equal(ok.status, 200);
  });

  it('every API route requires the token', async () => {
    const a = add();
    for (const [method, path] of [
      ['GET', '/api/pending'], ['GET', '/api/stream'], ['GET', '/api/receipts'],
      ['POST', `/api/approve/${a.id}`], ['POST', `/api/deny/${a.id}`], ['POST', `/api/hold/${a.id}`],
    ]) {
      for (const headers of [{}, { Authorization: 'Bearer wrong-token-wrong-token-wrong-token' }, { Authorization: TOKEN }] as Record<string, string>[]) {
        const r = await fetch(`${BASE}${path}`, { method, headers });
        assert.equal(r.status, 401, `${method} ${path} ${JSON.stringify(headers)}`);
        await r.body?.cancel();
      }
    }
    assert.equal(getAction(a.id)?.status, 'pending', 'nothing happened without the token');
  });

  it('GET / is static and carries no token', async () => {
    const r = await fetch(`${BASE}/`);
    const html = await r.text();
    assert.equal(r.status, 200);
    assert.ok(!html.includes(TOKEN));
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
  });

  it('sends no CORS headers on any route, including OPTIONS', async () => {
    const a = add();
    const responses = [
      await fetch(`${BASE}/`),
      await fetch(`${BASE}/api/pending`, { headers: { ...auth, Origin: 'https://evil.example' } }),
      await fetch(`${BASE}/api/receipts`, { headers: { ...auth, Origin: 'https://evil.example' } }),
      await fetch(`${BASE}/api/approve/${a.id}`, { method: 'OPTIONS', headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'POST' } }),
      await fetch(`${BASE}/api/hold/${a.id}`, { method: 'POST', headers: auth }),
    ];
    for (const r of responses) {
      for (const [k] of r.headers) assert.ok(!k.toLowerCase().startsWith('access-control-'), `${r.url} sent ${k}`);
      await r.body?.cancel();
    }
  });

  it('audit PoC: another origin can neither read nor approve without the token', async () => {
    const a = add();
    const read = await fetch(`${BASE}/api/pending`, { headers: { Origin: 'https://evil.example' } });
    assert.equal(read.status, 401);
    const approve = await fetch(`${BASE}/api/approve/${a.id}`, { method: 'POST', headers: { Origin: 'https://evil.example' } });
    assert.equal(approve.status, 401);
    assert.equal(released.length, 0);
  });

  it('GET /api/pending exposes the contract fields, including every argument', async () => {
    add({ confidence: 72 });
    const items = (await (await get('/api/pending')).json()) as any[];
    assert.equal(items.length, 1);
    for (const k of ['id', 'tool_name', 'lane', 'reversibility', 'summary', 'args_preview', 'args_full', 'agent_id', 'rule_id', 'status', 'created_at', 'acted']) {
      assert.ok(k in items[0], `missing field ${k}`);
    }
    assert.ok(items[0].args_full.includes('hidden@x.com'), 'approver sees arguments the preview omits');
    assert.equal(items[0].confidence, 72);
  });

  it('approve releases once, signed by the operator as local:<operator>', async () => {
    const a = add();
    const r1 = await post(`/api/approve/${a.id}`);
    assert.equal(r1.status, 200);
    const body = (await r1.json()) as any;
    assert.equal(body.status, 'approved');
    assert.match(body.receipt_id, /^rcpt_mg_/);
    const rec = released[0].issued.record;
    assert.equal(rec.status, 'APPROVED');
    assert.equal(rec.deciderId, 'local:rod');
    assert.equal(rec.resolutionType, 'allow_once');
    assert.equal(rec.reasonCodes, '["RULE_MATCHED:rule-email","OPERATOR_APPROVED"]');
    assert.equal(rec.idemKey, `mcp-guard:${a.id}`);
    assert.ok(released[0].issued.artifact, 'signed');

    const r2 = await post(`/api/approve/${a.id}`);
    assert.equal(r2.status, 409);
    assert.equal(released.length, 1);
  });

  it('B2: approving with no usable key leaves the call held and names the code', async () => {
    const a = add();
    const saved = readFileSync(keySetPath(), 'utf-8');
    writeFileSync(keySetPath(), JSON.stringify({ keys: [] }));
    try {
      const r = await post(`/api/approve/${a.id}`);
      assert.equal(r.status, 409);
      assert.equal(((await r.json()) as any).error, 'SIGNING_KEY_MISSING');
      assert.equal(getAction(a.id)?.status, 'pending', 'still held');
      assert.equal(released.length, 0);
    } finally {
      writeFileSync(keySetPath(), saved);
    }
    assert.equal((await post(`/api/approve/${a.id}`)).status, 200, 'approvable once the key is back');
  });

  it('deny answers the waiting client, signs a DENIED receipt and is final', async () => {
    let answered = '';
    const a = add({}, (l) => { answered = l; });
    const res = (await (await post(`/api/deny/${a.id}`)).json()) as any;
    assert.equal(res.status, 'denied');
    assert.match(answered, /"code":-32003/);
    const receipts = (await (await get('/api/receipts')).json()) as any[];
    const rec = receipts.find((x) => x.record.id === res.receipt_id);
    assert.equal(rec.record.status, 'DENIED');
    assert.equal(rec.record.resolutionType, 'deny');
    assert.equal(rec.record.reasonCodes, '["RULE_MATCHED:rule-email","OPERATOR_DENIED"]');
    assert.ok(rec.artifact);
    const again = await post(`/api/approve/${a.id}`);
    assert.equal(again.status, 409);
    assert.equal(released.length, 0);
  });

  it('hold cancels the countdown and keeps it pending', async () => {
    const a = add();
    const res = await post(`/api/hold/${a.id}`);
    assert.deepEqual(await res.json(), { id: a.id, status: 'pending' });
    const pend = (await (await get('/api/pending')).json()) as any[];
    assert.equal(pend[0].countdown_remaining, undefined);
    assert.equal(pend[0].countdown_seconds, undefined, 'a held card shows no countdown');
  });

  it('acted items are acknowledged, not re-forwarded, and cannot be denied', async () => {
    const a = surfaceActed({ toolName: 'spend', agentId: 'agent', ruleId: 'spend', enrichment: enrichment({ lane: 'verify' }), receiptId: 'rcpt_x' });
    assert.equal((await post(`/api/deny/${a.id}`)).status, 409);
    const ack = (await (await post(`/api/approve/${a.id}`)).json()) as any;
    assert.equal(ack.status, 'acknowledged');
    assert.equal(released.length, 0);
  });

  it('post-release undo is gone', async () => {
    const a = add();
    assert.equal((await post(`/api/undo/${a.id}`)).status, 404);
  });

  it('GET /api/stream streams the queue with header auth', async () => {
    add();
    const controller = new AbortController();
    const res = await fetch(`${BASE}/api/stream`, { headers: auth, signal: controller.signal });
    assert.equal(res.headers.get('content-type'), 'text/event-stream');
    const reader = res.body!.getReader();
    const { value } = await reader.read();
    const frame = Buffer.from(value!).toString();
    assert.ok(frame.includes('event: queue'));
    assert.ok(frame.includes('"tool_name":"send_email"'));
    controller.abort();
    await reader.cancel().catch(() => {});
  });

  describe('GitHub webhook', () => {
    const sign = (body: string) => 'sha256=' + crypto.createHmac('sha256', SECRET).update(body).digest('hex');
    const body = JSON.stringify({
      action: 'labeled',
      repository: { full_name: 'o/r' },
      pull_request: { number: 7, title: 't', head: { sha: 'abc' }, labels: [{ name: 'needs-authority' }] },
    });
    const hook = (b: string, extra: Record<string, string> = {}) =>
      fetch(`${BASE}/api/github/webhook`, { method: 'POST', body: b, headers: { 'X-Hub-Signature-256': sign(b), ...extra } });

    it('rejects a bad signature', async () => {
      const r = await fetch(`${BASE}/api/github/webhook`, { method: 'POST', body, headers: { 'X-Hub-Signature-256': 'sha256=00' } });
      assert.equal(r.status, 401);
    });

    const records = () => {
      const path = process.env.PP_SHARED_RECEIPTS_PATH!;
      return (existsSync(path) ? readFileSync(path, 'utf-8') : '').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    };

    it('audit PoC: deny then approve gives 409; only the signed denial exists', async () => {
      const q = (await (await hook(body)).json()) as any;
      const denied = (await (await post(`/api/deny/${q.id}`)).json()) as any;
      const a1 = await post(`/api/approve/${q.id}`);
      const a2 = await post(`/api/approve/${q.id}`);
      assert.equal(a1.status, 409);
      assert.equal(a2.status, 409);
      const forPr = records().filter((l) => l.record?.idemKey === `mcp-guard:${q.id}`);
      assert.equal(forPr.length, 1);
      assert.equal(forPr[0].record.id, denied.receipt_id);
      assert.equal(forPr[0].record.status, 'DENIED');
    });

    it('approve issues one receipt bound to the PR head commit, decided by the operator', async () => {
      const q = (await (await hook(body)).json()) as any;
      const r = (await (await post(`/api/approve/${q.id}`)).json()) as any;
      assert.match(r.receipt_id, /^rcpt_mg_/);
      const receipts = (await (await get('/api/receipts')).json()) as any[];
      const rec = receipts.find((x) => x.record.id === r.receipt_id).record;
      const req = JSON.parse(rec.requestJson);
      assert.deepEqual(req.scope, { capability: 'github:merge', commitSha: 'abc', ref: 'refs/pull/7/merge' });
      assert.deepEqual(req.action, { operation: 'github/merge', resource: 'github-webhook', tool: 'merge_pr' });
      assert.equal(rec.deciderId, 'local:rod');
      assert.equal((await post(`/api/approve/${q.id}`)).status, 409);
    });

    it('ignores a replayed delivery id', async () => {
      const first = await hook(body, { 'X-GitHub-Delivery': 'd-1' });
      assert.equal(first.status, 202);
      const again = (await (await hook(body, { 'X-GitHub-Delivery': 'd-1' })).json()) as any;
      assert.equal(again.ignored, true);
    });
  });

  it('derivePreview renders human artifacts per tool', () => {
    assert.equal(derivePreview('send_email', { to: 'x@y.com', body: 'hi there' }).args_preview, 'hi there');
    assert.equal(derivePreview('spend', { amount_usd: 49, payee: 'Instantly' }).args_preview, '$49 → Instantly');
    assert.equal(derivePreview('spend', { amount: 900, amount_usd: 1, payee: 'X' }, 'amount').args_preview, '$900 → X');
    assert.equal(derivePreview('post_x', { text: 'gm' }).args_preview, 'gm');
  });

  it('buildEnrichment falls reversibility safe to irreversible when unset', () => {
    const d: Decision = { decision: 'held_for_approval', rule_id: 'r', reason: 'x' };
    const e = buildEnrichment(d, 'post_x', { text: 'hi' });
    assert.equal(e.reversibility, 'irreversible');
    assert.equal(e.lane, 'decide');
  });
});
