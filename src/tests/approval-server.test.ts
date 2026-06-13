import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { startApprovalServer, setOnApprove, type ApprovalServerHandle } from '../approval-server.js';
import { addPending, getAction, resolveAction, _resetQueue, setAutoReleaseHandler, type PendingEnrichment } from '../pending.js';
import { derivePreview, buildEnrichment } from '../proxy.js';
import type { Decision } from '../engine.js';

const PORT = 7799;
const BASE = `http://localhost:${PORT}`;
let handle: ApprovalServerHandle;

function enrichment(over: Partial<PendingEnrichment> = {}): PendingEnrichment {
  return {
    lane: 'decide',
    reversibility: 'reversible',
    countdown_seconds: 5,
    summary: 'Send email to a@b.com',
    args_preview: 'hello body',
    ...over,
  };
}

function add(over: Partial<PendingEnrichment> = {}) {
  return addPending(
    'send_email',
    { to: 'a@b.com', body: 'hello body' },
    'agent-1',
    'rule-email',
    '{"jsonrpc":"2.0","id":1,"method":"tools/call"}',
    1,
    () => {},
    enrichment(over),
  );
}

describe('Approval server endpoints (API contract)', () => {
  before(() => {
    handle = startApprovalServer(PORT);
    setAutoReleaseHandler(() => {});
  });
  after(() => handle.close());
  beforeEach(() => {
    _resetQueue();
    setOnApprove(() => {});
  });

  it('GET /api/pending exposes the contract fields including countdown_remaining', async () => {
    add({ confidence: 72 });
    const res = await fetch(`${BASE}/api/pending`);
    assert.equal(res.status, 200);
    const items = (await res.json()) as any[];
    assert.equal(items.length, 1);
    const it0 = items[0];
    for (const k of ['id', 'tool_name', 'lane', 'reversibility', 'summary', 'args_preview', 'agent_id', 'rule_id', 'status', 'created_at']) {
      assert.ok(k in it0, `missing field ${k}`);
    }
    assert.equal(it0.tool_name, 'send_email');
    assert.equal(it0.lane, 'decide');
    assert.equal(it0.reversibility, 'reversible');
    assert.equal(it0.countdown_seconds, 5);
    assert.ok(it0.countdown_remaining <= 5 && it0.countdown_remaining >= 4);
    assert.equal(it0.confidence, 72);
    assert.equal(it0.status, 'pending');
  });

  it('POST /api/hold/:id cancels the countdown and keeps it pending', async () => {
    const a = add();
    const res = await fetch(`${BASE}/api/hold/${a.id}`, { method: 'POST' });
    assert.equal(res.status, 200);
    const body = (await res.json()) as any;
    assert.deepEqual(body, { id: a.id, status: 'pending' });

    const pend = (await (await fetch(`${BASE}/api/pending`)).json()) as any[];
    assert.equal(pend[0].countdown_remaining, undefined, 'no countdown after hold');
  });

  it('POST /api/approve/:id returns receipt_id and invokes the proxy callback', async () => {
    const a = add();
    let approved: string | null = null;
    // Simulate the proxy stamping receipt_id during onApprove (releaseAction).
    setOnApprove((id) => {
      approved = id;
      const act = getAction(id);
      if (act) act.receipt_id = 'rcpt_dg_test';
    });
    const res = await fetch(`${BASE}/api/approve/${a.id}`, { method: 'POST' });
    assert.equal(res.status, 200);
    const body = (await res.json()) as any;
    assert.equal(body.status, 'approved');
    assert.equal(approved, a.id);
    assert.equal(body.receipt_id, 'rcpt_dg_test');
  });

  it('POST /api/undo/:id works within window, 409 outside', async () => {
    const a = add({ countdown_seconds: undefined });
    resolveAction(a.id, 'approved', 5); // 5s undo window
    const ok = await fetch(`${BASE}/api/undo/${a.id}`, { method: 'POST' });
    assert.equal(ok.status, 200);
    assert.equal((await ok.json() as any).status, 'undone');

    const b = add({ countdown_seconds: undefined });
    resolveAction(b.id, 'auto_released', 0); // already expired window
    const late = await fetch(`${BASE}/api/undo/${b.id}`, { method: 'POST' });
    assert.equal(late.status, 409);
  });

  it('GET /api/stream emits an initial queue SSE frame', async () => {
    add();
    const controller = new AbortController();
    const res = await fetch(`${BASE}/api/stream`, { signal: controller.signal });
    assert.equal(res.headers.get('content-type'), 'text/event-stream');
    const reader = res.body!.getReader();
    const { value } = await reader.read();
    const frame = Buffer.from(value!).toString();
    assert.ok(frame.includes('event: queue'));
    assert.ok(frame.includes('"tool_name":"send_email"'));
    controller.abort();
    await reader.cancel().catch(() => {});
  });

  it('derivePreview renders human artifacts per tool', () => {
    assert.equal(derivePreview('send_email', { to: 'x@y.com', body: 'hi there' }).args_preview, 'hi there');
    assert.equal(derivePreview('spend', { amount_usd: 49, payee: 'Instantly' }).args_preview, '$49 → Instantly');
    assert.equal(derivePreview('post_x', { text: 'gm' }).args_preview, 'gm');
  });

  it('buildEnrichment falls reversibility safe to irreversible when unset', () => {
    const d: Decision = { decision: 'held_for_approval', rule_id: 'r', reason: 'x' };
    const e = buildEnrichment(d, 'post_x', { text: 'hi' });
    assert.equal(e.reversibility, 'irreversible');
    assert.equal(e.lane, 'decide');
  });
});
