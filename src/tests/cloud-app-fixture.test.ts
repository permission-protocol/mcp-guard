import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fingerprintOfCall } from '../cloud/fingerprint.js';
import { pinsFor } from '../cloud/pinned-keys.js';
import { verifyCloudReceipt } from '../cloud/verify.js';

/**
 * A receipt the Permission Protocol app itself signed for an MCP Guard call (see the
 * fixture's `description`): the guard's verifier against real app output, not only
 * against this repository's test signer. The receipt expired minutes after it was
 * signed, so each check sets the clock.
 */
const FIXTURE = join(__dirname, '..', '..', '..', 'src', 'tests', 'fixtures', 'app-mcp-receipt', 'approved-jcs-v3.json');
const fixture = JSON.parse(readFileSync(FIXTURE, 'utf-8'));
const payload = JSON.parse(Buffer.from(fixture.artifact.payload_bytes_b64, 'base64').toString('utf8'));
const whileValid = new Date(Date.parse(payload.expiresAt) - 60_000);
const base = {
  keySet: fixture.keySet,
  trust: pinsFor(fixture.keySet),
  fingerprint: fingerprintOfCall(fixture.call.server, fixture.call.tool, fixture.call.args),
  requestId: fixture.requestId,
  expect: 'APPROVED' as const,
  now: whileValid,
};

describe('a receipt signed by the Permission Protocol app', () => {
  it('the guard computes the same fingerprint the app signed', () => {
    assert.equal(base.fingerprint, fixture.fingerprint);
    assert.equal(JSON.parse(payload.publicProjectionJson).action.operation, base.fingerprint);
  });

  it('verifies: pinned key, signature, canonical jcs_v3 bytes, human decider, request id', () => {
    const result = verifyCloudReceipt(fixture.artifact, base);
    assert.equal(result.ok, true, result.ok ? '' : `${result.code}: ${result.message}`);
    if (!result.ok) return;
    assert.equal(result.receipt.canonicalization, 'jcs_v3');
    assert.equal(result.receipt.decider.display, 'Maria Signer');
    assert.match(result.receipt.decider.id, /^user:/);
    assert.equal(result.receipt.requestId, fixture.requestId);
    assert.equal(result.receipt.expiresAt, payload.expiresAt);
  });

  it('expires ten minutes after it was signed', () => {
    const after = verifyCloudReceipt(fixture.artifact, { ...base, now: new Date(Date.parse(payload.expiresAt) + 1) });
    assert.equal(after.ok, false);
    if (!after.ok) assert.equal(after.code, 'EXPIRED');
    const nextDay = verifyCloudReceipt(fixture.artifact, { ...base, now: new Date(Date.parse(payload.expiresAt) + 86_400_000) });
    assert.equal(nextDay.ok, false);
    assert.equal(Date.parse(payload.expiresAt) - Date.parse(payload.createdAt) < 11 * 60_000 + 60_000, true);
  });

  it('does not release the same tool with one argument changed', () => {
    const changed = fingerprintOfCall(fixture.call.server, fixture.call.tool, { ...fixture.call.args, path: '/srv/payroll' });
    const result = verifyCloudReceipt(fixture.artifact, { ...base, fingerprint: changed });
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'FINGERPRINT_MISMATCH');
  });

  it('is refused by the pinned production keys: a local signing key is not Permission Protocol', async () => {
    const { PRODUCTION_KEY_SET } = await import('../cloud/pinned-keys.js');
    const result = verifyCloudReceipt(fixture.artifact, { ...base, keySet: PRODUCTION_KEY_SET, trust: pinsFor(PRODUCTION_KEY_SET) });
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'KEY_NOT_FOUND');
  });
});
