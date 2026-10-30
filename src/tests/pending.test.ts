import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  addPending,
  addExternalDecision,
  surfaceActed,
  getAction,
  getPending,
  transition,
  countdownRemaining,
  queueSize,
  setAutoReleaseHandler,
  setExpireHandler,
  MAX_RESOLVED,
  _resetQueue,
  type PendingEnrichment,
} from '../pending.js';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function enrichment(over: Partial<PendingEnrichment> = {}): PendingEnrichment {
  return { lane: 'decide', reversibility: 'reversible', countdown_seconds: 1, summary: 's', args_preview: 'p', ...over };
}

function add(over: Partial<PendingEnrichment> = {}, ttlSeconds?: number) {
  return addPending({
    toolName: 'send_email',
    toolArgs: { body: 'hi' },
    agentId: 'agent-1',
    ruleId: 'rule-1',
    forwardLine: '{"jsonrpc":"2.0","id":1,"method":"tools/call"}',
    jsonrpcId: 1,
    resolve: () => {},
    enrichment: enrichment(over),
    ttlSeconds,
  });
}

describe('Decision state machine', () => {
  beforeEach(() => {
    _resetQueue();
    setAutoReleaseHandler(null);
    setExpireHandler(null);
  });

  it('threads enrichment fields onto the pending item', () => {
    const a = add({ confidence: 70 });
    assert.equal(a.status, 'pending');
    assert.equal(a.kind, 'held');
    assert.equal(a.confidence, 70);
    assert.equal(getPending().length, 1);
  });

  it('a countdown calls the handler while the item is still pending (it signs before the item is final)', async () => {
    let seen: string | null = null;
    setAutoReleaseHandler((a) => { seen = a.status; });
    const a = add({ countdown_seconds: 0.05 });
    await sleep(120);
    assert.equal(seen, 'pending');
    assert.equal(getAction(a.id)?.status, 'pending');
  });

  it('without a handler, a countdown moves the item to auto_released', async () => {
    const a = add({ countdown_seconds: 0.05 });
    await sleep(120);
    assert.equal(getAction(a.id)?.status, 'auto_released');
  });

  it('hold cancels the countdown; the item stays pending', async () => {
    let fired = false;
    setAutoReleaseHandler(() => { fired = true; });
    const a = add({ countdown_seconds: 0.05 });
    assert.ok(transition(a.id, 'hold').ok);
    await sleep(120);
    assert.equal(fired, false);
    assert.equal(getAction(a.id)?.status, 'pending');
    assert.equal(countdownRemaining(a), undefined);
  });

  it('irreversible items never auto-release', async () => {
    let fired = false;
    setAutoReleaseHandler(() => { fired = true; });
    const a = add({ reversibility: 'irreversible', countdown_seconds: 0.05 });
    await sleep(120);
    assert.equal(fired, false);
    assert.equal(a.releaseAt, undefined);
  });

  it('final states never change: deny then approve is refused', () => {
    const a = add();
    assert.ok(transition(a.id, 'deny').ok);
    for (const ev of ['approve', 'auto_release', 'expire', 'hold', 'deny'] as const) {
      const r = transition(a.id, ev);
      assert.equal(r.ok, false, ev);
      assert.equal(!r.ok && r.error, 'final', ev);
    }
    assert.equal(getAction(a.id)?.status, 'denied');
  });

  it('approving twice succeeds once', () => {
    const a = add();
    assert.ok(transition(a.id, 'approve').ok);
    assert.equal(transition(a.id, 'approve').ok, false);
  });

  it('a manual approve racing the countdown releases exactly once', async () => {
    let autoReleases = 0;
    setAutoReleaseHandler((x) => { if (transition(x.id, 'auto_release').ok) autoReleases++; });
    const a = add({ countdown_seconds: 0.05 });
    await sleep(45);
    const manual = transition(a.id, 'approve');
    await sleep(60);
    assert.equal((manual.ok ? 1 : 0) + autoReleases, 1);
  });

  it('expires after the TTL and tells the handler', async () => {
    let expired: string | null = null;
    setExpireHandler((x) => { expired = x.status; });
    const a = add({ reversibility: 'irreversible' }, 0.05);
    assert.ok(a.expires_at);
    await sleep(120);
    assert.equal(expired, 'expired');
    assert.equal(transition(a.id, 'approve').ok, false);
  });

  it('acted items can only be acknowledged', () => {
    const a = surfaceActed({ toolName: 'spend', agentId: 'a', ruleId: 'r', enrichment: enrichment({ lane: 'verify' }) });
    const deny = transition(a.id, 'deny');
    assert.equal(!deny.ok && deny.error, 'not_allowed');
    assert.equal(transition(a.id, 'approve').ok, false);
    assert.ok(transition(a.id, 'acknowledge').ok);
    assert.equal(getAction(a.id)?.status, 'acknowledged');
  });

  it('external items approve or deny once and never expire', () => {
    const a = addExternalDecision({ toolName: 'merge_pr', agentId: 'gh', ruleId: 'r', enrichment: enrichment({ countdown_seconds: undefined }) });
    assert.equal(a.expires_at, undefined);
    assert.equal(transition(a.id, 'hold').ok, false);
    assert.ok(transition(a.id, 'deny').ok);
    assert.equal(transition(a.id, 'approve').ok, false);
  });

  it(`keeps at most ${MAX_RESOLVED} resolved items`, () => {
    for (let i = 0; i < 500; i++) transition(add({ countdown_seconds: undefined }).id, 'deny');
    const live = add({ countdown_seconds: undefined });
    assert.ok(queueSize() <= MAX_RESOLVED + 1);
    assert.equal(getAction(live.id)?.status, 'pending');
  });

  it('countdown_remaining counts down and is server-computed', () => {
    const a = add({ countdown_seconds: 10 });
    const r = countdownRemaining(a);
    assert.ok(r !== undefined && r <= 10 && r >= 9);
  });

  it('status is assigned only inside transition()', () => {
    const src = readFileSync(join(__dirname, '..', '..', '..', 'src', 'pending.ts'), 'utf-8');
    const assignments = src.split('\n').filter((l) => /\.status\s*=[^=]/.test(l));
    assert.deepEqual(assignments.map((l) => l.trim()), ['action.status = FINAL_STATUS[event];']);
  });
});
