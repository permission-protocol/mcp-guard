import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { surfaceActed, transition, getPending, _resetQueue, type PendingEnrichment } from '../pending.js';

const verifyEnrichment: PendingEnrichment = {
  lane: 'verify',
  reversibility: 'reversible',
  confidence: 68,
  summary: 'Spend $49 → Instantly',
  args_preview: '$49 → Instantly',
};

describe('Verify-lane surfacing (acted under a standing rule)', () => {
  beforeEach(() => _resetQueue());

  it('surfaces an acted item as pending in the Verify lane', () => {
    const a = surfaceActed({ toolName: 'spend', toolArgs: { amount_usd: 49 }, agentId: 'agent', ruleId: 'spend', enrichment: verifyEnrichment, receiptId: 'rcpt_1' });
    assert.equal(a.kind, 'acted');
    assert.equal(a.status, 'pending');
    assert.equal(a.receipt_id, 'rcpt_1');
    assert.equal(getPending().length, 1);
  });

  it('acknowledge never invokes the resolver (no re-forward)', () => {
    let resolverCalled = false;
    const a = surfaceActed({ toolName: 'spend', agentId: 'agent', ruleId: 'spend', enrichment: verifyEnrichment });
    a.resolve = () => { resolverCalled = true; };
    assert.ok(transition(a.id, 'acknowledge').ok);
    assert.equal(resolverCalled, false);
    assert.equal(getPending().length, 0);
  });

  it('an action that already ran cannot be denied after the fact', () => {
    const a = surfaceActed({ toolName: 'spend', agentId: 'agent', ruleId: 'spend', enrichment: verifyEnrichment });
    const r = transition(a.id, 'deny');
    assert.equal(r.ok, false);
  });
});
