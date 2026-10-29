import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { issueReceipt, emitReceipt, signingBytes, hashArgs, SIGNING_DOMAIN, type ReceiptInput } from '../receipt.js';
import { currentKeyId } from '../signer.js';
import { isolateKeys } from './helpers.js';

const SENTINEL = 'sk_live_SENTINEL_9f8e7d';

function input(over: Partial<ReceiptInput> = {}): ReceiptInput {
  return {
    method: 'tools/call',
    tool: 'send_email',
    args: { to: 'a@b.com', body: `password is ${SENTINEL}` },
    decision: { decision: 'allowed', rule_id: 'r', reason: 'Matched rule "r"' },
    approval: { kind: 'human', id: 'rod', via: 'local-token' },
    actor: 'agent-1',
    mode: 'enforce',
    policy_sha256: 'abc',
    ttl_seconds: 900,
    target_server: 'node server.js',
    ...over,
  };
}

describe('Receipt v2', () => {
  beforeEach(() => { isolateKeys(); });

  it('has exactly the documented envelope fields', () => {
    const r = issueReceipt(input({ scope: { scope: 'deploy:staging', scope_sha: 'abc' } }));
    assert.deepEqual(Object.keys(r.envelope).sort(), [
      'actor', 'approval', 'args_sha256', 'decision', 'expires_at', 'issued_at', 'key_id', 'method', 'mode',
      'nonce', 'policy_sha256', 'receipt_id', 'rule_id', 'scope', 'tool', 'v',
    ]);
    assert.equal(r.envelope.v, 2);
    assert.equal(r.envelope.key_id, currentKeyId());
    assert.equal(r.signature.key_id, currentKeyId());
    assert.deepEqual(r.envelope.scope, { scope: 'deploy:staging', ref: null, sha: 'abc' });
    assert.ok(!('verified' in r.signature), 'no self-reported verified flag');
  });

  it('signs the domain-separated canonical envelope', () => {
    const r = issueReceipt(input());
    const bytes = signingBytes(r.envelope);
    assert.ok(bytes.startsWith(SIGNING_DOMAIN));
    // canonical: key order does not matter
    const shuffled = Object.fromEntries(Object.entries(r.envelope).reverse()) as typeof r.envelope;
    assert.equal(signingBytes(shuffled), bytes);
  });

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

  it('expires after ttl_seconds', () => {
    const now = new Date('2026-01-01T00:00:00Z');
    const r = issueReceipt(input({ now, ttl_seconds: 60 }));
    assert.equal(r.envelope.expires_at, '2026-01-01T00:01:00.000Z');
  });

  it('hashes canonical arguments', () => {
    assert.equal(hashArgs({ a: 1, b: 2 }), hashArgs({ b: 2, a: 1 }));
    assert.equal(issueReceipt(input()).envelope.args_sha256, hashArgs(input().args));
  });

  it('never carries raw argument values (stderr, file)', () => {
    const r = issueReceipt(input());
    const path = process.env.PP_SHARED_RECEIPTS_PATH!;
    const writes: string[] = [];
    const orig = process.stderr.write.bind(process.stderr);
    (process.stderr as any).write = (chunk: any) => { writes.push(String(chunk)); return true; };
    try { emitReceipt(r, path); } finally { (process.stderr as any).write = orig; }
    const file = readFileSync(path, 'utf-8');
    assert.ok(!JSON.stringify(r).includes(SENTINEL));
    assert.ok(!file.includes(SENTINEL));
    assert.ok(!writes.join('').includes(SENTINEL));
    assert.deepEqual(r.display.arg_keys, ['body', 'to']);
  });
});
