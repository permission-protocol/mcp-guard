import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { signingBytes } from '../receipt.js';
import { JCS_V2_FIELDS } from '../signing/canonical.js';
import { hashablePayloadInputHash, policyVersionOf, POLICY_DECIDER_ID, type DecisionInput } from '../issuer.js';
import { emitReceipt } from '../receipt-log.js';
import { loadSigningKey, keySetPath, SigningError } from '../keystore.js';
import { verifyArtifactReceipt } from '../receipt-verify.js';
import { isolateKeys, testIssuer } from './helpers.js';

const SENTINEL = 'sk_live_SENTINEL_9f8e7d';

function input(over: Partial<DecisionInput> = {}): DecisionInput {
  return {
    method: 'tools/call',
    tool: 'send_email',
    input: { to: 'a@b.com', body: `password is ${SENTINEL}` },
    status: 'APPROVED',
    ruleId: 'email',
    reasonCodes: ['RULE_MATCHED:email'],
    decider: { kind: 'policy' },
    argKeys: ['body', 'to'],
    ...over,
  };
}

const request = (issued: { record: Record<string, unknown> }) => JSON.parse(String(issued.record.requestJson));
const verify = (issued: { artifact?: unknown }) => {
  const key = loadSigningKey();
  return verifyArtifactReceipt({ artifact: issued.artifact }, key.keySet, { trust: new Map([[key.keyId, key.fingerprint]]), allowPolicyApproval: true });
};

describe('Issuer: jcs_v2 receipts', () => {
  beforeEach(() => { isolateKeys(); });

  it('records only the frozen jcs_v2 fields and signs a verifiable artifact', () => {
    const issued = testIssuer().issue(input());
    for (const k of Object.keys(issued.record)) assert.ok(JCS_V2_FIELDS.includes(k), `unexpected field ${k}`);
    assert.equal(issued.record.canonicalization, 'jcs_v2');
    assert.equal(issued.record.receiptVersion, 2);
    assert.equal(issued.record.signatureKeyId, loadSigningKey().keyId);
    assert.equal(issued.record.scope, 'production');
    assert.match(issued.record.id, /^rcpt_mg_[0-9a-z]+_[0-9a-f]{12}$/);
    assert.ok(!('verified' in issued.artifact!), 'a receipt never vouches for itself');
    assert.deepEqual(verify(issued).reasons, []);
  });

  it('B4: no raw argument anywhere; the arguments are bound by pp.hashable_payload.v1', () => {
    const issued = testIssuer().issue(input());
    const path = process.env.PP_SHARED_RECEIPTS_PATH!;
    const writes: string[] = [];
    const orig = process.stderr.write.bind(process.stderr);
    (process.stderr as any).write = (chunk: any) => { writes.push(String(chunk)); return true; };
    try { emitReceipt(issued, path); } finally { (process.stderr as any).write = orig; }
    const signedBytes = Buffer.from(issued.artifact!.payload_bytes_b64, 'base64').toString('utf8');
    for (const text of [JSON.stringify(issued), readFileSync(path, 'utf-8'), writes.join(''), signedBytes]) {
      assert.ok(!text.includes(SENTINEL));
      assert.ok(!text.includes('a@b.com'));
    }
    const want = hashablePayloadInputHash('send_email', 'tools/call', { to: 'a@b.com', body: `password is ${SENTINEL}` });
    assert.equal(issued.record.inputHash, want);
    assert.equal(request(issued).hashes.inputHash, want);
    // Key order does not change the hash.
    assert.equal(hashablePayloadInputHash('t', 'o', { a: 1, b: { c: 2, d: 3 } }), hashablePayloadInputHash('t', 'o', { b: { d: 3, c: 2 }, a: 1 }));
  });

  it('pp.hashable_payload.v1 golden value', () => {
    // sha256 of {"input":{"amount":5,"to":"x"},"metadata":null,"operation":"tools/call","tool":"spend"}
    assert.equal(
      hashablePayloadInputHash('spend', 'tools/call', { to: 'x', amount: 5 }),
      'sha256:' + require('node:crypto').createHash('sha256').update('{"input":{"amount":5,"to":"x"},"metadata":null,"operation":"tools/call","tool":"spend"}').digest('hex'),
    );
  });

  it('names the server by its configured label and binds the scope inside the signed request', () => {
    const issued = testIssuer({ server_label: 'github-mcp' }).issue(input({
      tool: 'merge_pr', input: { pr_number: 16, sha: 'abc' }, reversibility: 'irreversible',
      scope: { scope: 'github:merge', scope_ref: 'refs/pull/16/merge', scope_sha: 'abc' },
    }));
    const req = request(issued);
    assert.deepEqual(req.action, { operation: 'tools/call', resource: 'github-mcp', tool: 'merge_pr' });
    assert.deepEqual(req.scope, { capability: 'github:merge', commitSha: 'abc', ref: 'refs/pull/16/merge' });
    assert.equal(req.context.reversibility, 'IRREVERSIBLE');
    assert.equal(req.policy.decision.outcome, 'approved');
    assert.equal(req.policy.decision.ruleVersion, policyVersionOf('a'.repeat(64)));
  });

  it('B5: decider binding per path', () => {
    const policy = testIssuer().issue(input());
    assert.equal(policy.record.deciderId, POLICY_DECIDER_ID);
    assert.equal(policy.record.deciderAuthMethod, 'policy');
    assert.equal(policy.record.attributionConfidence, 'credentialed');
    assert.equal(policy.record.resolutionType, undefined);

    const approve = testIssuer().issue(input({ decider: { kind: 'operator', operator: 'rod' }, reasonCodes: ['RULE_MATCHED:email', 'OPERATOR_APPROVED'] }));
    assert.equal(approve.record.deciderId, 'local:rod');
    assert.equal(approve.record.deciderDisplay, 'rod');
    assert.equal(approve.record.deciderAuthMethod, 'local_console');
    assert.equal(approve.record.attributionConfidence, 'heuristic');
    assert.equal(approve.record.resolutionType, 'allow_once');

    const deny = testIssuer().issue(input({ status: 'DENIED', decider: { kind: 'operator', operator: 'rod' } }));
    assert.equal(deny.record.resolutionType, 'deny');
    assert.equal(deny.record.status, 'DENIED');

    assert.throws(() => testIssuer().issue(input({ decider: { kind: 'operator', operator: null } })),
      (e: any) => e instanceof SigningError && e.code === 'UNATTRIBUTED_PRODUCTION_DECIDER');
    const unattributedDeny = testIssuer().issue(input({ status: 'DENIED', decider: { kind: 'operator', operator: '' } }));
    assert.equal(unattributedDeny.record.attributionConfidence, 'unattributed');
    assert.equal(unattributedDeny.record.deciderId, undefined);
  });

  it('B6: expiry 1 h unscoped, 15 min scoped, per-rule override; reason codes and policy version are signed', () => {
    const now = new Date('2026-01-01T00:00:00Z');
    assert.equal(testIssuer().issue(input({ now })).record.expiresAt, '2026-01-01T01:00:00.000Z');
    assert.equal(testIssuer().issue(input({ now, scope: { scope: 'deploy:production' } })).record.expiresAt, '2026-01-01T00:15:00.000Z');
    const perRule = testIssuer({ rules: [{ id: 'email', tool: 'send_email', action: 'allow', receipt_ttl_seconds: 60 }] }).issue(input({ now }));
    assert.equal(perRule.record.expiresAt, '2026-01-01T00:01:00.000Z');
    const r = testIssuer().issue(input({ reasonCodes: ['RULE_MATCHED:email', 'COUNTDOWN_AUTO_RELEASE'] }));
    assert.equal(r.record.reasonCodes, '["RULE_MATCHED:email","COUNTDOWN_AUTO_RELEASE"]');
    assert.equal(r.record.policyVersion, `mcp-guard-config:sha256:${'a'.repeat(64)}`);
  });

  it('signing: off writes an unsigned record; observe mode marks a signing failure', () => {
    const off = testIssuer({ signing: 'off' }).issue(input());
    assert.equal(off.artifact, undefined);
    assert.equal(off.unsigned, true);
    assert.equal(off.record.signatureKeyId, undefined);

    writeFileSync(keySetPath(), JSON.stringify({ keys: [] }));
    assert.throws(() => testIssuer().issue(input()), (e: any) => e.code === 'SIGNING_KEY_MISSING');
    const observed = testIssuer({ mode: 'observe' }).issue(input());
    assert.equal(observed.artifact, undefined);
    assert.equal(observed.signingFailed, 'SIGNING_KEY_MISSING');
  });

  it('a demo key signs scope demo', () => {
    isolateKeys({ demo: true });
    assert.equal(testIssuer().issue(input()).record.scope, 'demo');
  });
});

describe('Legacy 0.2 envelope bytes (kept for verification only)', () => {
  it('golden vector: signing bytes for a fixed envelope', () => {
    const env = {
      v: 2 as const, receipt_id: 'rcpt_mg_x', method: 'tools/call', tool: 'deploy', args_sha256: 'h',
      scope: { scope: 'deploy:production', ref: null, sha: 'abc' }, decision: 'allowed' as const,
      approval: { kind: 'human' as const, id: 'rod', via: 'local-token' }, actor: 'a', rule_id: 'r',
      policy_sha256: 'p', mode: 'enforce' as const, issued_at: '2026-01-01T00:00:00.000Z',
      expires_at: '2026-01-01T00:15:00.000Z', nonce: 'n', key_id: 'pp-dev-0000000000000000',
    };
    assert.equal(
      signingBytes(env),
      'pp-mcp-guard-receipt-v2\n{"actor":"a","approval":{"id":"rod","kind":"human","via":"local-token"},"args_sha256":"h","decision":"allowed","expires_at":"2026-01-01T00:15:00.000Z","issued_at":"2026-01-01T00:00:00.000Z","key_id":"pp-dev-0000000000000000","method":"tools/call","mode":"enforce","nonce":"n","policy_sha256":"p","receipt_id":"rcpt_mg_x","rule_id":"r","scope":{"ref":null,"scope":"deploy:production","sha":"abc"},"tool":"deploy","v":2}',
    );
  });
});
