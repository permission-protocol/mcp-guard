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
    assert.match(receipt.receipt_id, /^[0-9a-f-]{36}$/, 'receipt_id is UUID');
    assert.ok(receipt.timestamp, 'has timestamp');
    assert.doesNotThrow(() => new Date(receipt.timestamp), 'timestamp is valid ISO');
    assert.equal(receipt.agent_id, 'agent-1');
    assert.equal(receipt.tool_name, 'delete_user_data');
    assert.equal(receipt.decision, 'blocked');
    assert.equal(receipt.reason, 'Matched rule "block-delete"');
    assert.equal(receipt.rule_id, 'block-delete');
    assert.equal(typeof receipt.request_payload_hash, 'string');
    assert.equal(receipt.request_payload_hash.length, 64, 'SHA-256 hex is 64 chars');
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
});
