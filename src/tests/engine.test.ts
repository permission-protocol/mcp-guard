import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { evaluate } from '../engine.js';
import { testConfig } from './helpers.js';

describe('Decision Engine', () => {
  const config = testConfig({
    rules: [
      { id: 'block-delete', tool: 'delete_user_data', action: 'block' },
      { id: 'hold-deploy', tool: 'deploy_production', action: 'require_approval' },
      { id: 'allow-email', tool: 'send_email', action: 'allow' },
      { id: 'block-reads', method: 'resources/read', action: 'block' },
    ],
  });

  it('matches a block rule', () => {
    const d = evaluate('delete_user_data', undefined, config);
    assert.equal(d.decision, 'blocked');
    assert.equal(d.rule_id, 'block-delete');
  });

  it('matches a require_approval rule', () => {
    const d = evaluate('deploy_production', {}, config);
    assert.equal(d.decision, 'held_for_approval');
    assert.equal(d.rule_id, 'hold-deploy');
  });

  it('matches an allow rule', () => {
    const d = evaluate('send_email', {}, config);
    assert.equal(d.decision, 'allowed');
    assert.equal(d.rule_id, 'allow-email');
  });

  it('falls back to default_action: allow', () => {
    const d = evaluate('unknown_tool', {}, config);
    assert.equal(d.decision, 'allowed');
    assert.equal(d.rule_id, null);
  });

  it('falls back to default_action: block', () => {
    const d = evaluate('unknown_tool', {}, testConfig({ default_action: 'block' }));
    assert.equal(d.decision, 'blocked');
  });

  it('governs non-tool methods by method rules', () => {
    assert.equal(evaluate(null, undefined, config, 'resources/read').decision, 'blocked');
    assert.equal(evaluate(null, undefined, testConfig({ default_action: 'block' }), 'prompts/get').decision, 'blocked');
    assert.equal(evaluate(null, undefined, config, 'prompts/get').decision, 'allowed');
  });

  it('a tool rule never matches another method', () => {
    const d = evaluate('delete_user_data', undefined, config, 'prompts/get');
    assert.equal(d.rule_id, null);
  });
});
