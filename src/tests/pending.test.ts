import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  addPending,
  getAction,
  getPending,
  resolveAction,
  holdAction,
  undoAction,
  countdownRemaining,
  setAutoReleaseHandler,
  _resetQueue,
  type PendingEnrichment,
} from '../pending.js';

const noopResolve = (_line: string): void => {};

function enrichment(over: Partial<PendingEnrichment> = {}): PendingEnrichment {
  return {
    lane: 'decide',
    reversibility: 'reversible',
    countdown_seconds: 1,
    summary: 'test summary',
    args_preview: 'test preview',
    ...over,
  };
}

function add(over: Partial<PendingEnrichment> = {}) {
  return addPending(
    'send_email',
    { body: 'hi' },
    'agent-1',
    'rule-1',
    '{"jsonrpc":"2.0","id":1,"method":"tools/call"}',
    1,
    noopResolve,
    enrichment(over),
  );
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('Pending countdown / undo (Permission Deck Slice 1)', () => {
  beforeEach(() => {
    _resetQueue();
    setAutoReleaseHandler(() => {});
  });

  it('threads enrichment fields onto the pending item', () => {
    const a = add({ confidence: 88 });
    assert.equal(a.lane, 'decide');
    assert.equal(a.reversibility, 'reversible');
    assert.equal(a.countdown_seconds, 1);
    assert.equal(a.confidence, 88);
    assert.equal(a.summary, 'test summary');
    assert.equal(a.args_preview, 'test preview');
    assert.equal(a.status, 'pending');
    assert.ok(a.created_at);
  });

  it('countdown auto-release fires when nothing intervenes', async () => {
    let fired: string | null = null;
    setAutoReleaseHandler((id) => {
      fired = id;
      resolveAction(id, 'auto_released');
    });
    const a = add({ countdown_seconds: 1 });
    assert.equal(getPending().length, 1);
    await sleep(1100);
    assert.equal(fired, a.id);
    assert.equal(getAction(a.id)!.status, 'auto_released');
    assert.equal(getPending().length, 0);
  });

  it('hold cancels the countdown timer (no auto-release fires)', async () => {
    let fired = false;
    setAutoReleaseHandler(() => {
      fired = true;
    });
    const a = add({ countdown_seconds: 1 });
    const held = holdAction(a.id);
    assert.ok(held);
    assert.equal(countdownRemaining(held!), undefined, 'countdown removed after hold');
    await sleep(1200);
    assert.equal(fired, false, 'timer must not fire after hold');
    assert.equal(getAction(a.id)!.status, 'pending', 'item stays pending');
  });

  it('irreversible items never auto-release (no countdown timer)', async () => {
    let fired = false;
    setAutoReleaseHandler(() => {
      fired = true;
    });
    const a = add({ reversibility: 'irreversible', countdown_seconds: undefined });
    assert.equal(countdownRemaining(a), undefined);
    await sleep(300);
    assert.equal(fired, false);
    assert.equal(getAction(a.id)!.status, 'pending');
  });

  it('undo within the window succeeds; outside the window is rejected', async () => {
    const a = add({ reversibility: 'reversible', countdown_seconds: undefined });
    // Release it with a short 1s undo window.
    resolveAction(a.id, 'approved', 1);
    const undone = undoAction(a.id);
    assert.ok(undone, 'undo within window should succeed');
    assert.equal(getAction(a.id)!.status, 'undone');

    // A second item, let its undo window lapse.
    const b = add({ reversibility: 'reversible', countdown_seconds: undefined });
    resolveAction(b.id, 'auto_released', 1);
    await sleep(1100);
    const late = undoAction(b.id);
    assert.equal(late, undefined, 'undo outside the window must be rejected');
    assert.equal(getAction(b.id)!.status, 'auto_released');
  });

  it('hold/deny before expiry wins the race against auto-release', () => {
    let fired = false;
    setAutoReleaseHandler(() => {
      fired = true;
    });
    const a = add({ countdown_seconds: 1 });
    const denied = resolveAction(a.id, 'denied');
    assert.ok(denied);
    assert.equal(denied!.status, 'denied');
    assert.equal(fired, false);
  });

  it('countdown_remaining counts down and is server-computed', () => {
    const a = add({ countdown_seconds: 5 });
    const remaining = countdownRemaining(a);
    assert.ok(remaining !== undefined && remaining <= 5 && remaining >= 4);
  });
});
