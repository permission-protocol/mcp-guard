import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  surfaceActed,
  acknowledgeAction,
  undoAction,
  getPending,
  getAction,
  _resetQueue,
  type PendingEnrichment,
} from '../pending.js';

const verifyEnrichment: PendingEnrichment = {
  lane: 'verify',
  reversibility: 'reversible',
  confidence: 68,
  summary: 'Spend $49 → Instantly',
  args_preview: '$49 → Instantly',
};

describe('Verify-lane surfacing (acted-under-rule)', () => {
  beforeEach(() => _resetQueue());

  it('surfaces an acted item as pending in the Verify lane', () => {
    const a = surfaceActed('spend', { amount_usd: 49 }, 'agent', 'spend', verifyEnrichment, 'rcpt_1');
    assert.equal(a.acted, true);
    assert.equal(a.status, 'pending');
    assert.equal(a.lane, 'verify');
    assert.equal(a.receipt_id, 'rcpt_1');
    assert.equal(getPending().length, 1); // shows in the queue
  });

  it('acknowledge marks approved WITHOUT a resolver (no re-forward)', () => {
    let resolverCalled = false;
    const a = surfaceActed('spend', { amount_usd: 49 }, 'agent', 'spend', verifyEnrichment);
    // The surfaced item's resolver is a no-op; prove acknowledging never invokes forward semantics.
    a.resolve = () => { resolverCalled = true; };
    const ack = acknowledgeAction(a.id);
    assert.equal(ack?.status, 'approved');
    assert.equal(resolverCalled, false);
    assert.equal(getPending().length, 0);
  });

  it('acknowledge only applies to acted items', () => {
    // A non-acted id cannot be acknowledged.
    assert.equal(acknowledgeAction('nonexistent'), undefined);
  });

  it('undo rolls back an acted item within the window', () => {
    const a = surfaceActed('spend', { amount_usd: 49 }, 'agent', 'spend', verifyEnrichment);
    const undone = undoAction(a.id);
    assert.equal(undone?.status, 'undone');
    assert.equal(getAction(a.id)?.status, 'undone');
  });

  it('irreversible acted item is not undoable', () => {
    const a = surfaceActed(
      'post_x',
      { text: 'hi' },
      'agent',
      'post-x',
      { ...verifyEnrichment, reversibility: 'irreversible' },
    );
    assert.equal(undoAction(a.id), undefined);
  });
});
