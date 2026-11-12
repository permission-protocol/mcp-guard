import { describe, it, after } from 'node:test';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import stableStringify from 'fast-json-stable-stringify';
import { AuthorizationError, buildAuthorizationSigningBytes, verifyAuthorization } from '../enforcement/verifier.js';
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
  it('required_approvals: 1 still accepts one allowed signer holding an allowed role', async () => {
    const payload = makePayload('one-approval');
    await assert.doesNotReject(
      () => verifyAuthorization(payload, makeToken(payload), publicKeyPem, { ...policy, required_approvals: 1 }),
    );
  });

  it('refuses a 3-of-3 policy: three names under one signature and one key are not three approvals', async () => {
    const payload = makePayload('three-of-three');
    const token = makeToken(payload, { signers: ['alice', 'bob', 'carol'] });
    await assert.rejects(
      () => verifyAuthorization(payload, token, publicKeyPem, { ...policy, allowed_roles: undefined, allowed_signers: ['alice', 'bob', 'carol'], required_approvals: 3 }),
      (e: any) => e instanceof PolicyError && e.code === 'PP_POLICY_UNSUPPORTED',
    );
  });

  it('refuses any required_approvals above 1, and a repeated name never counts twice', async () => {
    for (const [id, signers] of [['two-distinct', ['alice', 'bob']], ['duplicate-signers', ['alice', 'alice']]] as const) {
      const payload = makePayload(id);
      const token = makeToken(payload, { signers: [...signers] });
      await assert.rejects(
        () => verifyAuthorization(payload, token, publicKeyPem, { ...policy, allowed_roles: undefined, allowed_signers: ['alice', 'bob'], required_approvals: 2 }),
        (e: any) => e instanceof PolicyError && e.code === 'PP_POLICY_UNSUPPORTED',
      );
    }
  });

  it('refuses invalid required_approvals and allowed lists given as strings', async () => {
    const payload = makePayload('invalid-policy');
    const token = makeToken(payload);
    for (const bad of [{ required_approvals: 0 }, { required_approvals: 1.5 }, { required_approvals: '1' }, { allowed_roles: 'admin' }, { allowed_signers: 'alice' }]) {
      await assert.rejects(
        () => verifyAuthorization(payload, token, publicKeyPem, { ...policy, ...(bad as any) }),
        (e: any) => e instanceof PolicyError && e.code === 'PP_POLICY_INVALID',
      );
    }
  });

  it('refuses a signer who does not hold an allowed role', async () => {
    const payload = makePayload('signer-without-role');
    const token = makeToken(payload, { signers: ['mallory'], roles: ['viewer'] });
    await assert.rejects(
      () => verifyAuthorization(payload, token, publicKeyPem, { ...policy, allowed_signers: ['mallory'] }),
      /Requires 1 valid approval, found 0/,
    );
  });

  it("refuses to credit one signer's role to another: a multi-signer token under a role policy", async () => {
    // alice holds admin; mallory is an allowed signer without it. The token's roles are one list.
    for (const [id, roles] of [['global-role', ['admin']], ['aligned-roles', ['admin', 'viewer']]] as const) {
      const payload = makePayload(id);
      const token = makeToken(payload, { signers: ['alice', 'mallory'], roles: [...roles] });
      await assert.rejects(
        () => verifyAuthorization(payload, token, publicKeyPem, { ...policy, allowed_signers: ['mallory'] }),
        (e: any) => e instanceof AuthorizationError && e.code === 'PP_ROLE_NOT_BOUND',
      );
    }
  });

  it('without a role policy, one allowed signer among several is one approval', async () => {
    const payload = makePayload('signers-no-roles');
    const token = makeToken(payload, { signers: ['alice', 'bob'], roles: [] });
    await assert.doesNotReject(
      () => verifyAuthorization(payload, token, publicKeyPem, { protected: true, allowed_signers: ['bob'], max_ttl_seconds: 300 }),
    );
  });

  it('rejects a future signed_at timestamp that attempts to bypass max_ttl_seconds', async () => {
    const payload = { ...makePayload('future-signed-at'), expires_at: now + 86400 * 365 };
    const token = makeToken(payload, { signed_at: now + 86400 * 365, expires_at: now + 86400 * 365 });
    await assert.rejects(
      () => verifyAuthorization(payload, token, publicKeyPem, policy),
      /Invalid token timestamps/,
    );
  });

  it('rejects a token signed under a different key id', async () => {
    const payload = makePayload('other-key-id');
    const token = makeToken(payload, { key_id: 'pp-other' });
    await assert.rejects(() => verifyAuthorization(payload, token, publicKeyPem, policy), /Untrusted key_id/);
  });
});

describe('interceptToolCall enforces the same policy limits', () => {
  const saved = process.env.PP_CONFIG_PATH;
  after(() => {
    if (saved === undefined) delete process.env.PP_CONFIG_PATH; else process.env.PP_CONFIG_PATH = saved;
    _resetPolicyCache();
  });
  const usePolicy = (yaml: string) => {
    _resetPolicyCache();
    const dir = mkdtempSync(join(tmpdir(), 'pp-intercept-'));
    process.env.PP_CONFIG_PATH = join(dir, 'pp.config.yaml');
    writeFileSync(process.env.PP_CONFIG_PATH, yaml);
  };
  const call = (id: string, signers = ['alice']) => {
    const payload = { ...makePayload(id), action: 'deploy' };
    const token = makeToken(payload, { signers });
    return { method: 'tools/call', params: { name: 'deploy', arguments: { ...payload.args, _authorization: { payload, token } } } };
  };

  it('a 3-approval policy is refused at load, and interceptToolCall does not allow the call', async () => {
    usePolicy('tools:\n  deploy:\n    protected: true\n    allowed_signers: [alice, bob, carol]\n    required_approvals: 3\n');
    assert.throws(() => loadPolicy(), (e: any) => e instanceof PolicyError && e.code === 'PP_POLICY_UNSUPPORTED');
    const r = await interceptToolCall(call('intercept-3', ['alice', 'bob', 'carol']), publicKeyPem);
    assert.equal(r.allowed, false);
    assert.match(r.reason ?? '', /required_approvals 3 is not supported/);
  });

  it('a 1-approval policy still allows a valid authorization', async () => {
    usePolicy('tools:\n  deploy:\n    protected: true\n    allowed_signers: [alice]\n    allowed_roles: [admin]\n    required_approvals: 1\n');
    const r = await interceptToolCall(call('intercept-1'), publicKeyPem);
    assert.equal(r.allowed, true, r.reason);
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
