import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { evaluate } from '../engine.js';
import { classify, extractMeta } from '../classify.js';
import type { Config } from '../config.js';

// Permission Deck Slice 1 — the three-beat demo, expressed as the classifier contract.
const config: Config = {
  default_action: 'allow',
  mode: 'enforce',
  rules: [
    { id: 'post-x', tool: 'post_x', action: 'require_approval', reversibility: 'irreversible' },
    { id: 'send-email', tool: 'send_email', action: 'require_approval', reversibility: 'reversible', countdown_seconds: 300 },
    { id: 'spend', tool: 'spend', action: 'require_approval', reversibility: 'reversible', cap_usd: 50, verify_threshold: 70 },
    { id: 'reauth', tool: 'instantly_reauth', action: 'require_approval' },
    { id: 'block-delete', tool: 'delete_user_data', action: 'block' },
  ],
};

describe('Permission Deck classifier', () => {
  it('irreversible post -> Decide, hard stop (no countdown)', () => {
    const d = evaluate('post_x', { text: 'hello world' }, config);
    assert.equal(d.decision, 'held_for_approval');
    assert.equal(d.lane, 'decide');
    assert.equal(d.reversibility, 'irreversible');
    assert.equal(d.countdown_seconds, undefined); // hard stop never auto-clears
  });

  it('reversible email -> Decide with countdown auto-release', () => {
    const d = evaluate('send_email', { to: 'x@y.com' }, config);
    assert.equal(d.decision, 'held_for_approval');
    assert.equal(d.lane, 'decide');
    assert.equal(d.reversibility, 'reversible');
    assert.equal(d.countdown_seconds, 300);
  });

  it('spend under cap -> acts now, surfaces in Verify', () => {
    const d = evaluate('spend', { _pp: { amount_usd: 49, confidence: 68 } }, config);
    assert.equal(d.decision, 'allowed');
    assert.equal(d.lane, 'verify');
    assert.equal(d.confidence, 68);
  });

  it('spend at/over cap -> Decide hard stop', () => {
    const d = evaluate('spend', { _pp: { amount_usd: 500 } }, config);
    assert.equal(d.decision, 'held_for_approval');
    assert.equal(d.lane, 'decide');
    assert.equal(d.reversibility, 'irreversible');
    assert.equal(d.countdown_seconds, undefined);
  });

  it('needs human-only input -> Unblock', () => {
    const d = evaluate('instantly_reauth', { _pp: { requires_input: true } }, config);
    assert.equal(d.decision, 'held_for_approval');
    assert.equal(d.lane, 'unblock');
  });

  it('reads amount from bare args as well as _pp', () => {
    const d = evaluate('spend', { amount_usd: 10 }, config);
    assert.equal(d.decision, 'allowed');
    assert.equal(d.lane, 'verify');
  });

  it('explicit block passes through with no lane', () => {
    const d = evaluate('delete_user_data', undefined, config);
    assert.equal(d.decision, 'blocked');
    assert.equal(d.lane, undefined);
  });

  it('unmatched tool under default allow has no lane', () => {
    const d = evaluate('read_file', undefined, config);
    assert.equal(d.decision, 'allowed');
    assert.equal(d.lane, undefined);
  });

  it('fail-safe: protected action with unknown reversibility is treated as irreversible', () => {
    const d = classify(
      { decision: 'held_for_approval', rule_id: 'r', reason: 'matched' },
      { id: 'r', tool: 't', action: 'require_approval' },
      {},
    );
    assert.equal(d.reversibility, 'irreversible');
    assert.equal(d.countdown_seconds, undefined);
  });

  it('low-confidence allowed action routes to Verify when threshold set', () => {
    const allowConfig: Config = {
      default_action: 'allow',
      mode: 'enforce',
      rules: [{ id: 'auto-reply', tool: 'auto_reply', action: 'allow', verify_threshold: 70 }],
    };
    const d = evaluate('auto_reply', { _pp: { confidence: 40 } }, allowConfig);
    assert.equal(d.decision, 'allowed');
    assert.equal(d.lane, 'verify');
    assert.equal(d.confidence, 40);
  });

  it('extractMeta clamps confidence to 0-100', () => {
    assert.equal(extractMeta({ _pp: { confidence: 250 } }).confidence, 100);
    assert.equal(extractMeta({ _pp: { confidence: -5 } }).confidence, 0);
  });
});
