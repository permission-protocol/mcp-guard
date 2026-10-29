import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalizeJcsV2, JCS_V2_FIELDS } from '../signing/canonical.js';
import { checkArtifact } from '../signing/artifact.js';
import { fingerprintOf } from '../signing/keys.js';
import { verifyArtifactReceipt } from '../receipt-verify.js';

const DIR = join(__dirname, '..', '..', '..', 'src', 'tests', 'fixtures', 'receipt-spec');
const keys = JSON.parse(readFileSync(join(DIR, 'keys.json'), 'utf-8'));
const VECTORS = ['approve-policy-execute-lane.json', 'approve-human-execute-lane-create-pr.json', 'approve-human-execute-lane-refund.json'];
const testKeyFp = fingerprintOf(Buffer.from(keys.keys[0].public_key_b64, 'base64'));

describe('receipt-spec jcs_v2 vectors (org standard compatibility)', () => {
  it('the frozen field list is the app SIGNED_FIELDS_V2: 24 fields ending in the decider binding', () => {
    assert.equal(JCS_V2_FIELDS.length, 24);
    assert.deepEqual(JCS_V2_FIELDS.slice(-6), ['deciderId', 'deciderDisplay', 'deciderAuthMethod', 'resolutionType', 'attributionConfidence', 'scope']);
    assert.ok(Object.isFrozen(JCS_V2_FIELDS));
  });

  for (const name of VECTORS) {
    const v = JSON.parse(readFileSync(join(DIR, name), 'utf-8'));
    describe(name, () => {
      it('canonicalizing the receipt record reproduces the signed bytes exactly', () => {
        assert.equal(canonicalizeJcsV2(v.receipt), Buffer.from(v.artifact.payload_bytes_b64, 'base64').toString('utf8'));
      });

      it('passes the spec checks against the test key set, pinned by fingerprint', () => {
        const { payload } = checkArtifact(v.artifact, keys, new Map([['pp-test-2026-q2', testKeyFp]]));
        assert.equal(payload.id, v.artifact.receipt_id);
      });

      it('passes the gate before its signed expiry and fails after it', () => {
        const before = new Date(Date.parse(v.receipt.expiresAt) - 60_000);
        assert.deepEqual(verifyArtifactReceipt({ artifact: v.artifact }, keys, { now: before }).reasons, []);
        const after = verifyArtifactReceipt({ artifact: v.artifact }, keys, { now: new Date(Date.parse(v.receipt.expiresAt) + 1) });
        assert.ok(after.reasons.some((r) => r.startsWith('PP_EXPIRED')));
      });
    });
  }
});
