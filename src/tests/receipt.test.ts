import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createReceipt } from '../receipt.js';
import type { Decision } from '../engine.js';

describe('Receipt Emitter', () => {
  it('generates a valid receipt with all fields', () => {
    const decision: Decision = {
      decision: 'blocked',
      rule_id: 'block-delete',
      reason: 'Matched rule "block-delete"',
    };

    const receipt = createReceipt('agent-1', 'delete_user_data', decision, { name: 'delete_user_data', arguments: {} });

    assert.ok(receipt.receipt_id, 'has receipt_id');
    assert.match(receipt.receipt_id, /^rcpt_dg_[a-z0-9]+_[a-f0-9]{12}$/, 'receipt_id uses deploy-gate prefix');
    assert.ok(receipt.timestamp, 'has timestamp');
    assert.doesNotThrow(() => new Date(receipt.timestamp), 'timestamp is valid ISO');
    assert.equal(receipt.agent_id, 'agent-1');
    assert.equal(receipt.tool_name, 'delete_user_data');
    assert.equal(receipt.decision, 'blocked');
    assert.equal(receipt.status, 'DENIED');
    assert.equal(receipt.action, 'delete_user_data');
    assert.equal(receipt.actor, 'agent-1');
    assert.equal(receipt.policy, 'block-delete');
    assert.equal(receipt.risk_tier, 'critical');
    assert.match(receipt.summary, /AI summary:/);
    assert.equal(receipt.signature.verified, false);
    assert.equal(receipt.issuer, 'permissionprotocol.com');
    assert.equal(receipt.receipt_version, 1);
    assert.equal(receipt.url, `https://app.permissionprotocol.com/r/${receipt.receipt_id}`);
    assert.equal(receipt.viewer_url, receipt.url);
    assert.equal(receipt.enrichmentSnapshot.summary, receipt.summary);
    assert.ok(receipt.enrichmentSnapshot.riskSignals.length > 0);
    assert.ok(receipt.enrichmentSnapshot.verificationSteps.length >= 3);
    assert.equal(receipt.diff.files[0]?.filename, 'arguments.json');
    assert.match(receipt.diff.files[0]?.patch ?? '', /diff --git a\/arguments\.json b\/arguments\.json/);
    assert.equal(receipt.policy_details.matched_rule_id, 'block-delete');
    assert.equal(receipt.policy_details.outcome, 'blocked');
    assert.doesNotThrow(() => JSON.parse(receipt.request_json), 'request_json is valid JSON');
    assert.equal(receipt.reason, 'Matched rule "block-delete"');
    assert.equal(receipt.rule_id, 'block-delete');
    assert.equal(typeof receipt.request_payload_hash, 'string');
    assert.equal(receipt.request_payload_hash.length, 64, 'SHA-256 hex is 64 chars');
    assert.equal(receipt.target_server, 'unknown');
    assert.equal(receipt.mode, 'enforce');
  });

  it('hashes different payloads differently', () => {
    const decision: Decision = { decision: 'allowed', rule_id: null, reason: 'test' };
    const r1 = createReceipt('a', 'tool', decision, { foo: 1 });
    const r2 = createReceipt('a', 'tool', decision, { foo: 2 });
    assert.notEqual(r1.request_payload_hash, r2.request_payload_hash);
  });

  it('generates unique receipt IDs', () => {
    const decision: Decision = { decision: 'allowed', rule_id: null, reason: 'test' };
    const r1 = createReceipt('a', 'tool', decision, {});
    const r2 = createReceipt('a', 'tool', decision, {});
    assert.notEqual(r1.receipt_id, r2.receipt_id);
  });

  it('captures observe-mode warnings for held decisions', () => {
    const decision: Decision = { decision: 'held_for_approval', rule_id: 'hold-prod', reason: 'Matched rule "hold-prod"' };
    const receipt = createReceipt('agent-2', 'deploy_production', decision, { environment: 'production' }, 'server', 'observe');

    assert.equal(receipt.status, 'AWAITING_APPROVAL');
    assert.equal(receipt.mode, 'observe');
    assert.equal(receipt.policy_details.enforcement_mode, 'observe');
    assert.ok(receipt.enrichmentSnapshot.confidenceWarnings.some((warning) => warning.includes('Observe mode')));
    assert.equal(receipt.diff.riskLevel, 'high');
  });
});
