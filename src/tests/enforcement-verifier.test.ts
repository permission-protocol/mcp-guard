import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import stableStringify from 'fast-json-stable-stringify';
import { buildAuthorizationSigningBytes, verifyAuthorization } from '../enforcement/verifier.js';
import type { ToolPolicy } from '../enforcement/policy.js';
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
