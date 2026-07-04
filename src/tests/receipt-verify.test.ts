import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createReceipt, signReceipt, type ScopeBinding } from '../receipt.js';
import { verifyReceiptOffline } from '../receipt-verify.js';
import { getPublicKeyPem, publishPublicKey } from '../signer.js';
import { readFileSync } from 'node:fs';
import { deriveScope } from '../proxy.js';
import type { Decision } from '../engine.js';

const held: Decision = {
  decision: 'held_for_approval',
  rule_id: 'merge-pr',
  reason: 'reversible — Decide before merge',
  lane: 'decide',
  reversibility: 'reversible',
};

const MERGE_SCOPE: ScopeBinding = {
  scope: 'github:merge',
  scope_ref: 'refs/pull/16/merge',
  scope_sha: 'abc123def456',
};

function signedMergeReceipt(scope: ScopeBinding = MERGE_SCOPE) {
  const receipt = createReceipt(
    'agent-1',
    'merge_pr',
    held,
    { pr_number: 16, scope_sha: scope.scope_sha },
    'infra-mcp',
    'enforce',
    scope,
  );
  return signReceipt(receipt, 'permission-deck-operator');
}

function cloneReceipt<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

describe('Slice 2 — scope-bound receipts & offline verifier', () => {
  it('scope is carried on the receipt and folded into the signed payload', () => {
    const receipt = signedMergeReceipt();
    assert.equal(receipt.scope, 'github:merge');
    assert.equal(receipt.scope_ref, 'refs/pull/16/merge');
    assert.equal(receipt.scope_sha, 'abc123def456');
    assert.ok(receipt.signature.value, 'has a signature');
  });

  it('a correctly-scoped signed receipt verifies offline against the published key', () => {
    const receipt = signedMergeReceipt();
    const pem = getPublicKeyPem();
    const result = verifyReceiptOffline(receipt, pem, {
      scope: 'github:merge',
      scope_ref: 'refs/pull/16/merge',
      scope_sha: 'abc123def456',
    });
    assert.equal(result.valid, true, result.reasons.join('; '));
    assert.deepEqual(result.reasons, []);
  });

  it('verifies against the PUBLISHED .pub.pem file path (what CI reads)', () => {
    const receipt = signedMergeReceipt();
    const pubPath = publishPublicKey();
    const pem = readFileSync(pubPath, 'utf-8');
    const result = verifyReceiptOffline(receipt, pem, { scope: 'github:merge' });
    assert.equal(result.valid, true, result.reasons.join('; '));
  });

  it('REFUSES a receipt presented for the wrong scope_sha', () => {
    const receipt = signedMergeReceipt();
    const pem = getPublicKeyPem();
    const result = verifyReceiptOffline(receipt, pem, {
      scope: 'github:merge',
      scope_ref: 'refs/pull/16/merge',
      scope_sha: 'WRONG_SHA_0000', // gate expects a different merge SHA
    });
    assert.equal(result.valid, false);
    assert.ok(
      result.reasons.some((r) => r.includes('PP_SCOPE_MISMATCH') && r.includes('scope_sha')),
      `expected scope_sha mismatch, got: ${result.reasons.join('; ')}`,
    );
  });

  it('REFUSES a receipt whose scope_sha was tampered after signing (signature breaks)', () => {
    const receipt = signedMergeReceipt();
    const pem = getPublicKeyPem();
    // Attacker swaps the bound SHA but keeps the old signature.
    receipt.scope_sha = 'tampered_sha';
    const result = verifyReceiptOffline(receipt, pem);
    assert.equal(result.valid, false);
    assert.ok(
      result.reasons.some((r) => r.includes('PP_INVALID_SIGNATURE')),
      `expected signature failure, got: ${result.reasons.join('; ')}`,
    );
  });

  it('REFUSES an expired receipt', () => {
    const receipt = createReceipt(
      'agent-1',
      'merge_pr',
      held,
      { pr_number: 16, scope_sha: MERGE_SCOPE.scope_sha },
      'infra-mcp',
      'enforce',
      MERGE_SCOPE,
    );
    receipt.expires_at = new Date(Date.now() - 60_000).toISOString();
    signReceipt(receipt, 'permission-deck-operator');
    const pem = getPublicKeyPem();
    const result = verifyReceiptOffline(receipt, pem);
    assert.equal(result.valid, false);
    assert.ok(
      result.reasons.some((r) => r.includes('PP_EXPIRED')),
      `expected expiry failure, got: ${result.reasons.join('; ')}`,
    );
  });

  it('REFUSES a receipt whose expiry was removed after signing', () => {
    const receipt = createReceipt(
      'agent-1',
      'merge_pr',
      held,
      { pr_number: 16, scope_sha: MERGE_SCOPE.scope_sha },
      'infra-mcp',
      'enforce',
      MERGE_SCOPE,
    );
    receipt.expires_at = new Date(Date.now() - 60_000).toISOString();
    signReceipt(receipt, 'permission-deck-operator');

    const tampered = cloneReceipt(receipt);
    tampered.expires_at = null;

    const pem = getPublicKeyPem();
    const result = verifyReceiptOffline(tampered, pem);
    assert.equal(result.valid, false);
    assert.ok(
      result.reasons.some((r) => r.includes('PP_INVALID_SIGNATURE')),
      `expected signature failure, got: ${result.reasons.join('; ')}`,
    );
  });

  it('REFUSES a receipt whose action metadata was tampered after signing', () => {
    const receipt = signedMergeReceipt();
    const tampered = cloneReceipt(receipt);
    tampered.action = 'deploy_production';
    tampered.resource = 'prod';
    tampered.diff.files[0].patch = 'tampered patch';
    tampered.policy_details.decision_reason = 'tampered reason';

    const pem = getPublicKeyPem();
    const result = verifyReceiptOffline(tampered, pem, MERGE_SCOPE);
    assert.equal(result.valid, false);
    assert.ok(
      result.reasons.some((r) => r.includes('PP_INVALID_SIGNATURE')),
      `expected signature failure, got: ${result.reasons.join('; ')}`,
    );
  });

  it('REFUSES a receipt that is not AUTHORIZED (no human approval)', () => {
    // Unsigned, still AWAITING_APPROVAL — never approved in the console.
    const receipt = createReceipt('agent-1', 'merge_pr', held, { pr_number: 16 }, 'infra-mcp', 'enforce', MERGE_SCOPE);
    const pem = getPublicKeyPem();
    const result = verifyReceiptOffline(receipt, pem, { scope: 'github:merge' });
    assert.equal(result.valid, false);
    assert.ok(result.reasons.some((r) => r.includes('PP_NOT_AUTHORIZED')));
    assert.ok(result.reasons.some((r) => r.includes('PP_UNSIGNED_RECEIPT')));
  });

  it('back-compat: a Slice-1 (no-scope) receipt still signs & verifies', () => {
    const allowed: Decision = { decision: 'allowed', rule_id: null, reason: 'comms ok' };
    const receipt = createReceipt('agent-1', 'send_email', allowed, { body: 'hi' }, 'actions-mcp', 'enforce');
    assert.equal(receipt.scope, null);
    assert.equal(receipt.scope_ref, null);
    assert.equal(receipt.scope_sha, null);
    signReceipt(receipt);
    const pem = getPublicKeyPem();
    // No expectations passed — pure signature/status check, as Slice 1 receipts have no scope.
    const result = verifyReceiptOffline(receipt, pem);
    assert.equal(result.valid, true, result.reasons.join('; '));
  });

  it('deriveScope maps the infra tools to the scope vocabulary; comms tools get none', () => {
    assert.deepEqual(deriveScope('merge_pr', { pr_number: 7, scope_sha: 'deadbeef' }), {
      scope: 'github:merge',
      scope_ref: 'refs/pull/7/merge',
      scope_sha: 'deadbeef',
    });
    assert.equal(deriveScope('run_sql_migration', { env: 'production' })?.scope, 'sql:migrate:production');
    assert.equal(deriveScope('deploy', { env: 'staging' })?.scope, 'deploy:staging');
    assert.equal(deriveScope('send_email', { body: 'x' }), undefined);
  });
});
