import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { verify as edVerify } from 'node:crypto';
import { createReceipt, signReceipt } from '../receipt.js';
import { getPublicKeyPem, DEV_KEY_ID, SIGN_ALGORITHM } from '../signer.js';
import type { Decision } from '../engine.js';

const heldDecision: Decision = {
  decision: 'held_for_approval',
  rule_id: 'hold-post',
  reason: 'irreversible — hard stop until approved',
  lane: 'decide',
  reversibility: 'irreversible',
};

describe('Receipt signing (Permission Deck Slice 1)', () => {
  it('issues an Ed25519-signed receipt on approve with the dev key_id', () => {
    const receipt = createReceipt('agent-1', 'post_x', heldDecision, { text: 'hello world' }, 'actions-mcp', 'enforce');
    // Before signing: unsigned.
    assert.equal(receipt.signature.value, null);
    assert.equal(receipt.signature.verified, false);

    signReceipt(receipt, 'permission-deck-operator');

    assert.equal(receipt.signature.algorithm, SIGN_ALGORITHM);
    assert.equal(receipt.signature.key_id, DEV_KEY_ID);
    assert.ok(receipt.signature.value, 'signature value present');
    assert.equal(receipt.signature.verified, true);
    assert.equal(receipt.status, 'AUTHORIZED');
    assert.equal(receipt.approved_by, 'permission-deck-operator');
  });

  it('the signature cryptographically verifies against the dev public key', () => {
    const receipt = createReceipt('agent-1', 'send_email', heldDecision, { body: 'draft' }, 'actions-mcp', 'enforce');
    signReceipt(receipt);

    const signingBytes = `${receipt.receipt_id}.${receipt.request_payload_hash}`;
    const ok = edVerify(
      null,
      Buffer.from(signingBytes),
      getPublicKeyPem(),
      Buffer.from(receipt.signature.value!, 'hex'),
    );
    assert.equal(ok, true, 'Ed25519 signature must verify against the dev public key');
  });

  it('a tampered signing input fails verification (binding holds)', () => {
    const receipt = createReceipt('agent-1', 'spend', heldDecision, { amount_usd: 49 }, 'actions-mcp', 'enforce');
    signReceipt(receipt);

    const tampered = `${receipt.receipt_id}.deadbeef`;
    const ok = edVerify(
      null,
      Buffer.from(tampered),
      getPublicKeyPem(),
      Buffer.from(receipt.signature.value!, 'hex'),
    );
    assert.equal(ok, false, 'tampered payload must not verify');
  });
});
