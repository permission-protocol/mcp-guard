import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { evaluate } from '../engine.js';
import type { Config } from '../config.js';

describe('Decision Engine', () => {
  const config: Config = {
    default_action: 'allow',
    rules: [
      { id: 'block-delete', tool: 'delete_user_data', action: 'block' },
      { id: 'hold-deploy', tool: 'deploy_production', action: 'require_approval' },
      { id: 'allow-email', tool: 'send_email', action: 'allow' },
    ],
  };

  it('matches a block rule', () => {
    const d = evaluate('delete_user_data', config);
    assert.equal(d.decision, 'blocked');
    assert.equal(d.rule_id, 'block-delete');
  });

  it('matches a require_approval rule', () => {
    const d = evaluate('deploy_production', config);
    assert.equal(d.decision, 'held_for_approval');
    assert.equal(d.rule_id, 'hold-deploy');
  });

  it('matches an allow rule', () => {
    const d = evaluate('send_email', config);
    assert.equal(d.decision, 'allowed');
    assert.equal(d.rule_id, 'allow-email');
  });

  it('falls back to default_action: allow', () => {
    const d = evaluate('unknown_tool', config);
    assert.equal(d.decision, 'allowed');
    assert.equal(d.rule_id, null);
  });

  it('falls back to default_action: block', () => {
    const blockConfig: Config = { default_action: 'block', rules: [] };
    const d = evaluate('any_tool', blockConfig);
    assert.equal(d.decision, 'blocked');
    assert.equal(d.rule_id, null);
  });
});
