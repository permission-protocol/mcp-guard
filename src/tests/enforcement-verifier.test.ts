import { describe, it, after } from 'node:test';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import stableStringify from 'fast-json-stable-stringify';
import { buildAuthorizationSigningBytes, verifyAuthorization } from '../enforcement/verifier.js';
import { loadPolicy, PolicyError, _resetPolicyCache, type ToolPolicy } from '../enforcement/policy.js';
import { interceptToolCall } from '../enforcement/index.js';
import type { CanonicalPayload, SignedToken } from '../enforcement/types.js';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
const now = Math.floor(Date.now() / 1000);

const policy: ToolPolicy = {
  protected: true,
  allowed_signers: ['alice'],
  allowed_roles: ['admin'],
  required_approvals: 1,
  max_ttl_seconds: 300,
};

function makePayload(id: string): CanonicalPayload {
  return {
    request_id: `req-${id}`,
    action: 'deploy:production',
    args: { repo: 'permission-protocol/demo', ref: `sha-${id}` },
    issued_at: now,
    expires_at: now + 120,
    nonce: `nonce-${id}`,
  };
}

function hashPayload(payload: CanonicalPayload): string {
  return `sha256:${createHash('sha256').update(stableStringify(payload)).digest('hex')}`;
}

function makeToken(payload: CanonicalPayload, overrides: Partial<SignedToken> = {}): SignedToken {
  const token: SignedToken = {
    request_id: payload.request_id,
    decision: 'approved',
    payload_hash: hashPayload(payload),
    signers: ['alice'],
    roles: ['admin'],
    signed_at: now,
    expires_at: now + 120,
    key_id: 'pp-prod-1',
    signature: '',
    ...overrides,
  };
  token.signature = sign(null, Buffer.from(buildAuthorizationSigningBytes(token)), privateKey).toString('hex');
  return token;
}

describe('authorization token verification', () => {
  it('accepts an approved token whose signature covers the full authorization envelope', async () => {
    const payload = makePayload('valid-envelope');
    const token = makeToken(payload);

    await assert.doesNotReject(
      () => verifyAuthorization(payload, token, publicKeyPem, policy),
    );
  });

  it('rejects legacy signatures that cover only the payload hash', async () => {
    const payload = makePayload('legacy-signature');
    const token = makeToken(payload);
    token.signature = sign(
      null,
      Buffer.from(token.payload_hash.replace('sha256:', '')),
      privateKey,
    ).toString('hex');

    await assert.rejects(
      () => verifyAuthorization(payload, token, publicKeyPem, policy),
      /Cryptographic signature verification failed/,
    );
  });

  it('rejects authorization metadata changed after signing', async () => {
    const payload = makePayload('metadata-tamper');
    const deniedToken = makeToken(payload, {
      decision: 'denied',
      signers: ['mallory'],
      roles: ['viewer'],
    });
    const tampered: SignedToken = {
      ...deniedToken,
      decision: 'approved',
      signers: ['alice'],
      roles: ['admin'],
    };

    await assert.rejects(
      () => verifyAuthorization(payload, tampered, publicKeyPem, policy),
      /Cryptographic signature verification failed/,
    );
  });

  it('rejects a token replayed against a different request id', async () => {
    const payload = makePayload('original-request');
    const token = makeToken(payload);
    const differentPayload = {
      ...payload,
      request_id: 'req-different-request',
      nonce: 'nonce-different-request',
    };

    await assert.rejects(
      () => verifyAuthorization(differentPayload, token, publicKeyPem, policy),
      /Request ID mismatch/,
    );
  });
});

describe('authorization policy enforcement', () => {
  it('counts a repeated signer name once toward required_approvals', async () => {
    const payload = makePayload('duplicate-signers');
    const token = makeToken(payload, { signers: ['alice', 'alice'] });
    await assert.rejects(
      () => verifyAuthorization(payload, token, publicKeyPem, { ...policy, required_approvals: 2 }),
      /Requires 2 valid approvals, found 1/,
    );
  });

  it('accepts two distinct allowed signers for a two-approval policy', async () => {
    const payload = makePayload('two-signers');
    const token = makeToken(payload, { signers: ['alice', 'bob'] });
    await assert.doesNotReject(
      () => verifyAuthorization(payload, token, publicKeyPem, { ...policy, allowed_signers: ['alice', 'bob'], required_approvals: 2 }),
    );
  });

  it('rejects a token signed under a different key id', async () => {
    const payload = makePayload('other-key-id');
    const token = makeToken(payload, { key_id: 'pp-other' });
    await assert.rejects(() => verifyAuthorization(payload, token, publicKeyPem, policy), /Untrusted key_id/);
  });
});

describe('policy loading fails closed', () => {
  const saved = process.env.PP_CONFIG_PATH;
  after(() => {
    if (saved === undefined) delete process.env.PP_CONFIG_PATH; else process.env.PP_CONFIG_PATH = saved;
    _resetPolicyCache();
  });

  it('a missing policy file is a typed error, not "nothing protected"', async () => {
    _resetPolicyCache();
    process.env.PP_CONFIG_PATH = join(tmpdir(), 'definitely-missing-pp.config.yaml');
    assert.throws(() => loadPolicy(), (e: any) => e instanceof PolicyError && e.code === 'PP_POLICY_MISSING');
    const r = await interceptToolCall({ method: 'tools/call', params: { name: 'deploy', arguments: {} } }, publicKeyPem);
    assert.equal(r.allowed, false);
  });

  it('an unparsable policy is a typed error', () => {
    _resetPolicyCache();
    const dir = mkdtempSync(join(tmpdir(), 'pp-policy-'));
    const path = join(dir, 'pp.config.yaml');
    writeFileSync(path, 'tools: [unclosed');
    assert.throws(() => loadPolicy(path), (e: any) => e instanceof PolicyError && e.code === 'PP_POLICY_INVALID');
  });
});
