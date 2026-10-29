import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { evaluate } from '../engine.js';
import { extractMeta } from '../classify.js';
import { testConfig } from './helpers.js';

// Permission Deck Slice 1 — the three-beat demo, expressed as the classifier contract.
const config = testConfig({
  rules: [
    { id: 'post-x', tool: 'post_x', action: 'require_approval', reversibility: 'irreversible' },
    { id: 'send-email', tool: 'send_email', action: 'require_approval', reversibility: 'reversible', countdown_seconds: 300 },
    { id: 'spend', tool: 'spend', action: 'require_approval', reversibility: 'reversible', cap_usd: 50, amount_arg: 'amount_usd', verify_threshold: 70 },
    { id: 'reauth', tool: 'instantly_reauth', action: 'require_approval' },
    { id: 'block-delete', tool: 'delete_user_data', action: 'block' },
    { id: 'read', tool: 'read_docs', action: 'allow', verify_threshold: 70 },
  ],
});

describe('Permission Deck classifier', () => {
  it('irreversible post -> Decide, hard stop (no countdown)', () => {
    const d = evaluate('post_x', { text: 'hello world' }, config);
    assert.equal(d.decision, 'held_for_approval');
    assert.equal(d.lane, 'decide');
    assert.equal(d.reversibility, 'irreversible');
    assert.equal(d.countdown_seconds, undefined);
  });

  it('reversible email -> Decide with countdown auto-release', () => {
    const d = evaluate('send_email', { to: 'x@y.com' }, config);
    assert.equal(d.decision, 'held_for_approval');
    assert.equal(d.countdown_seconds, 300);
  });

  it('spend under cap (from amount_arg) -> acts now, surfaces in Verify', () => {
    const d = evaluate('spend', { amount_usd: 49, _pp: { confidence: 68 } }, config);
    assert.equal(d.decision, 'allowed');
    assert.equal(d.lane, 'verify');
    assert.equal(d.confidence, 68);
  });

  it('spend at/over cap -> Decide hard stop', () => {
    const d = evaluate('spend', { amount_usd: 500 }, config);
    assert.equal(d.decision, 'held_for_approval');
    assert.equal(d.reversibility, 'irreversible');
  });

  it('audit PoC: _pp.amount_usd cannot understate the real amount', () => {
    const d = evaluate('spend', { amount_usd: 25000, payee: 'attacker', _pp: { amount_usd: 1 } }, config);
    assert.equal(d.decision, 'held_for_approval');
  });

  it('reads the amount only from amount_arg, never from other fields', () => {
    const d = evaluate('spend', { amount: 1, _pp: { amount_usd: 1 } }, config);
    assert.equal(d.decision, 'held_for_approval', 'amount_usd missing -> hard stop');
  });

  it('missing, non-number, NaN, Infinity or negative amounts are a hard stop', () => {
    for (const amount_usd of [undefined, '10', NaN, Infinity, -5, null, { v: 1 }]) {
      const d = evaluate('spend', { amount_usd } as Record<string, unknown>, config);
      assert.equal(d.decision, 'held_for_approval', String(amount_usd));
      assert.equal(d.lane, 'decide');
      assert.equal(d.reversibility, 'irreversible');
    }
  });

  it('no _pp value turns a held or blocked call into an allowed one', () => {
    const pps = [
      undefined,
      { confidence: 0 }, { confidence: 100 }, { confidence: -1 },
      { requires_input: true }, { requires_input: false },
      { amount_usd: 0 }, { amount_usd: 1, confidence: 100, requires_input: false },
      'string', [1, 2], null,
    ];
    for (const _pp of pps) {
      for (const [tool, args] of [
        ['post_x', {}], ['send_email', {}], ['instantly_reauth', {}], ['spend', { amount_usd: 500 }], ['spend', {}],
      ] as const) {
        const d = evaluate(tool, { ...args, _pp }, config);
        assert.equal(d.decision, 'held_for_approval', `${tool} ${JSON.stringify(_pp)}`);
      }
      assert.equal(evaluate('delete_user_data', { _pp }, config).decision, 'blocked');
    }
  });

  it('needs human-only input -> Unblock', () => {
    const d = evaluate('instantly_reauth', { _pp: { requires_input: true } }, config);
    assert.equal(d.decision, 'held_for_approval');
    assert.equal(d.lane, 'unblock');
  });

  it('explicit block passes through with no lane', () => {
    const d = evaluate('delete_user_data', {}, config);
    assert.equal(d.decision, 'blocked');
    assert.equal(d.lane, undefined);
  });

  it('unmatched tool under default allow has no lane', () => {
    const d = evaluate('anything', {}, config);
    assert.equal(d.decision, 'allowed');
    assert.equal(d.lane, undefined);
  });

  it('fail-safe: protected action with unknown reversibility is irreversible', () => {
    const d = evaluate('instantly_reauth', {}, config);
    assert.equal(d.reversibility, 'irreversible');
  });

  it('low-confidence allowed action routes to Verify when threshold set', () => {
    const d = evaluate('read_docs', { _pp: { confidence: 40 } }, config);
    assert.equal(d.decision, 'allowed');
    assert.equal(d.lane, 'verify');
  });

  it('extractMeta clamps confidence and ignores non-object _pp', () => {
    assert.equal(extractMeta({ _pp: { confidence: 150 } }).confidence, 100);
    assert.equal(extractMeta({ _pp: { confidence: -10 } }).confidence, 0);
    assert.deepEqual(extractMeta({ _pp: 'x' }), {});
    assert.equal((extractMeta({ _pp: { amount_usd: 5 } }) as Record<string, unknown>).amount_usd, undefined);
  });
});
