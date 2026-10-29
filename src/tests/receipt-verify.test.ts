import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { issueReceipt, type ReceiptInput, type Receipt } from '../receipt.js';
import { verifyReceipt } from '../receipt-verify.js';
import { currentKeyId, getPublicKeyPem, keyIdForPublicKey } from '../signer.js';
import { ReplayCache, type PinnedKeys } from '../verify-core.js';
import { isolateKeys } from './helpers.js';

let keys: PinnedKeys;

function scoped(over: Partial<ReceiptInput> = {}): Receipt {
  return issueReceipt({
    method: 'tools/call',
    tool: 'deploy',
    args: { env: 'staging', sha: 'GOODSHA' },
    decision: { decision: 'allowed', rule_id: 'deploy', reason: 'approved' },
    approval: { kind: 'human', id: 'rod', via: 'local-token' },
    actor: 'agent',
    mode: 'enforce',
    policy_sha256: 'p',
    ttl_seconds: 900,
    target_server: 'srv',
    scope: { scope: 'deploy:staging', scope_ref: 'refs/heads/main', scope_sha: 'GOODSHA' },
    ...over,
  });
}

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

describe('Offline receipt verification (v2)', () => {
  beforeEach(() => {
    isolateKeys();
    keys = { [currentKeyId()]: getPublicKeyPem() };
  });

  it('accepts a valid scoped human-approved receipt with matching expectations', () => {
    const r = verifyReceipt(scoped(), keys, { expected: { scope: 'deploy:staging', scope_ref: 'refs/heads/main', scope_sha: 'GOODSHA' } });
    assert.deepEqual(r, { valid: true, reasons: [] });
  });

  it('changing any envelope field breaks the signature', () => {
    const base = scoped();
    const tampers: Record<string, (e: any) => void> = {
      receipt_id: (e) => { e.receipt_id = 'rcpt_mg_other'; },
      method: (e) => { e.method = 'prompts/get'; },
      tool: (e) => { e.tool = 'merge_pr'; },
      args_sha256: (e) => { e.args_sha256 = '0'.repeat(64); },
      scope: (e) => { e.scope.scope = 'deploy:production'; },
      scope_ref: (e) => { e.scope.ref = 'refs/heads/other'; },
      scope_sha: (e) => { e.scope.sha = 'BADSHA'; },
      decision: (e) => { e.decision = 'blocked'; },
      approval_kind: (e) => { e.approval.kind = 'policy'; },
      approval_id: (e) => { e.approval.id = 'ceo@example.com'; },
      approval_via: (e) => { e.approval.via = 'sso'; },
      actor: (e) => { e.actor = 'other-agent'; },
      rule_id: (e) => { e.rule_id = 'other'; },
      policy_sha256: (e) => { e.policy_sha256 = 'other'; },
      mode: (e) => { e.mode = 'observe'; },
      issued_at: (e) => { e.issued_at = new Date(Date.now() - 1000).toISOString(); },
      expires_at: (e) => { e.expires_at = '2099-01-01T00:00:00.000Z'; },
      nonce: (e) => { e.nonce = 'fresh'; },
    };
    for (const [field, mutate] of Object.entries(tampers)) {
      const t = clone(base);
      mutate(t.envelope);
      const r = verifyReceipt(t, keys, { allowPolicyApproval: true });
      assert.equal(r.valid, false, field);
      assert.ok(r.reasons.some((x) => x.startsWith('PP_INVALID_SIGNATURE')), `${field}: ${r.reasons}`);
    }
  });

  it('editing the unsigned display block does not change the verdict', () => {
    const t = clone(scoped());
    t.display.summary = 'anything';
    t.display.risk_tier = 'low';
    assert.equal(verifyReceipt(t, keys).valid, true);
  });

  it('audit PoC: a staging approval cannot be re-split into deploy:production', () => {
    const crafted = scoped({
      args: { env: 'staging', sha: 'x.scope=deploy:production.scope_ref=refs/heads/main.scope_sha=GOODSHA' },
      scope: { scope: 'deploy:staging', scope_sha: 'x.scope=deploy:production.scope_ref=refs/heads/main.scope_sha=GOODSHA' },
    });
    const forged = clone(crafted);
    forged.envelope.scope = { scope: 'deploy:production', ref: 'refs/heads/main', sha: 'GOODSHA' };
    (forged.envelope as any).args_sha256 = `${crafted.envelope.args_sha256}.scope=deploy:staging`;
    const r = verifyReceipt(forged, keys, { expected: { scope: 'deploy:production', scope_ref: 'refs/heads/main', scope_sha: 'GOODSHA' } });
    assert.equal(r.valid, false);
  });

  it('rejects an expired receipt and a missing or invalid expiry', () => {
    const r = scoped({ ttl_seconds: 1 });
    assert.equal(verifyReceipt(r, keys, { now: new Date(Date.now() + 5000) }).reasons.some((x) => x.startsWith('PP_EXPIRED')), true);
    const missing = clone(r); delete (missing.envelope as any).expires_at;
    assert.ok(verifyReceipt(missing, keys).reasons[0].startsWith('PP_MALFORMED_RECEIPT'));
    const bad = clone(r); bad.envelope.expires_at = 'not-a-date';
    assert.ok(verifyReceipt(bad, keys).reasons.some((x) => x.startsWith('PP_EXPIRED')));
  });

  it('a scoped receipt released by countdown is refused unless policy approval is allowed', () => {
    const r = scoped({ approval: { kind: 'policy', id: 'deploy', via: 'countdown' } });
    const res = verifyReceipt(r, keys);
    assert.equal(res.valid, false);
    assert.ok(res.reasons.some((x) => x.startsWith('PP_APPROVAL_NOT_HUMAN')));
    assert.equal(verifyReceipt(r, keys, { allowPolicyApproval: true }).valid, true);
  });

  it('an unscoped policy-approved receipt verifies', () => {
    const r = scoped({ tool: 'send_email', scope: undefined, approval: { kind: 'policy', id: 'r', via: 'rule' } });
    assert.equal(verifyReceipt(r, keys).valid, true);
  });

  it('rejects receipts that do not authorize', () => {
    for (const decision of ['blocked', 'held_for_approval'] as const) {
      const r = scoped({ decision: { decision, rule_id: 'x', reason: 'x' }, approval: null });
      assert.ok(verifyReceipt(r, keys).reasons.some((x) => x.startsWith('PP_NOT_AUTHORIZED')), decision);
    }
  });

  it('accepts only pinned keys', () => {
    const other = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const r = verifyReceipt(scoped(), { [keyIdForPublicKey(other)]: other });
    assert.equal(r.valid, false);
    assert.ok(r.reasons.some((x) => x.includes('untrusted key_id')));
    // Pinning the right key id with the wrong key material still fails.
    const swapped = verifyReceipt(scoped(), { [currentKeyId()]: other });
    assert.equal(swapped.valid, false);
  });

  it('rejects any receipt version other than 2', () => {
    const v1 = { receipt_id: 'rcpt_dg_x', status: 'AUTHORIZED', signature: { algorithm: 'ed25519', value: 'aa' } } as unknown as Receipt;
    assert.ok(verifyReceipt(v1, keys).reasons[0].startsWith('PP_UNSUPPORTED_VERSION'));
    const v3 = clone(scoped()); (v3.envelope as any).v = 3;
    assert.ok(verifyReceipt(v3, keys).reasons[0].startsWith('PP_UNSUPPORTED_VERSION'));
  });

  it('scope expectations must match exactly', () => {
    const r = verifyReceipt(scoped(), keys, { expected: { scope_sha: 'OTHER' } });
    assert.ok(r.reasons.some((x) => x.startsWith('PP_SCOPE_MISMATCH')));
    const unscoped = scoped({ tool: 'send_email', scope: undefined });
    assert.equal(verifyReceipt(unscoped, keys, { expected: { scope: 'deploy:staging' } }).valid, false);
  });

  it('a replay cache honors a receipt once', () => {
    const r = scoped();
    const cache = new ReplayCache();
    assert.equal(verifyReceipt(r, keys, { replayCache: cache }).valid, true);
    const again = verifyReceipt(r, keys, { replayCache: cache });
    assert.equal(again.valid, false);
    assert.ok(again.reasons.some((x) => x.startsWith('PP_REPLAYED')));
  });

  it('a full replay cache refuses new receipts instead of forgetting used ones', () => {
    const cache = new ReplayCache(1);
    assert.equal(verifyReceipt(scoped(), keys, { replayCache: cache }).valid, true);
    const second = verifyReceipt(scoped(), keys, { replayCache: cache });
    assert.equal(second.valid, false);
    assert.ok(second.reasons.some((x) => x.startsWith('PP_REPLAY_CACHE_FULL')));
  });
});
