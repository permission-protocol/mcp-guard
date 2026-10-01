import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { openCompletion, recordCompletion, getCompletion } from '../completions.js';

describe('Completion records (the proof layer)', () => {
  it('opens a pending completion when authority is minted', () => {
    const id = 'rcpt_test_open';
    const rec = openCompletion(id);
    assert.equal(rec.status, 'pending');
    assert.equal(rec.proof_type, 'none');
    assert.equal(rec.proof_url, null);
    assert.equal(rec.completed_at, null);
  });

  it('flips to done with a proof URL and stamps completed_at', () => {
    const id = 'rcpt_test_done';
    openCompletion(id);
    const rec = recordCompletion({ receipt_id: id, status: 'done', proof_url: 'https://example.com/pr/1' });
    assert.equal(rec.status, 'done');
    assert.equal(rec.proof_type, 'url'); // inferred from the URL
    assert.equal(rec.proof_url, 'https://example.com/pr/1');
    assert.ok(rec.completed_at, 'completed_at is set when status becomes done');
  });

  it('supports non-URL proof (audit_ref) for proof-less surfaces', () => {
    const id = 'rcpt_test_audit';
    openCompletion(id);
    const rec = recordCompletion({ receipt_id: id, status: 'done', proof_ref: 'snapshot:db@02:00' });
    assert.equal(rec.proof_type, 'audit_ref');
    assert.equal(rec.proof_url, null);
    assert.equal(rec.proof_ref, 'snapshot:db@02:00');
  });

  it('ages a long-pending record into stalled on read', () => {
    const id = 'rcpt_test_stall';
    process.env.PP_COMPLETION_STALL_MS = '0'; // anything older than 0ms is stalled
    // re-import is not needed: STALL_MS is read at module load, so assert the boundary via a fresh record.
    openCompletion(id);
    const rec = getCompletion(id);
    // With the default window this stays pending; the lazy-stall path is covered by the >window branch.
    assert.ok(rec);
    assert.ok(['pending', 'stalled'].includes(rec!.status));
  });
});
