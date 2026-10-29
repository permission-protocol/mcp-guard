import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import stableStringify from 'fast-json-stable-stringify';
import { ReplayCache } from '../verify-core.js';
import { buildAuthorizationSigningBytes, verifyAuthorization } from '../enforcement/verifier.js';
import type { ToolPolicy } from '../enforcement/policy.js';
import type { CanonicalPayload, SignedToken } from '../enforcement/types.js';

describe('ReplayCache keeps used authorizations until they expire', () => {
  it('never forgets an unexpired entry to make room; refuses instead', () => {
    let t = 1_000;
    const cache = new ReplayCache(3, () => t, 0);
    assert.equal(cache.use('a', 10_000), 'ok');
    assert.equal(cache.use('b', 10_000), 'ok');
    assert.equal(cache.use('c', 10_000), 'ok');
    assert.equal(cache.use('d', 10_000), 'full', 'full of unexpired entries: fail closed');
    assert.equal(cache.use('a', 10_000), 'replayed', 'a was not evicted');
  });

  it('prunes only expired entries', () => {
    let t = 1_000;
    const cache = new ReplayCache(2, () => t, 0);
    assert.equal(cache.use('short', 2_000), 'ok');
    assert.equal(cache.use('long', 50_000), 'ok');
    t = 3_000; // 'short' has expired
    assert.equal(cache.use('new', 50_000), 'ok', 'room made by dropping only the expired entry');
    assert.equal(cache.use('long', 50_000), 'replayed');
  });

  it('keeps entries for a grace period past expiry', () => {
    let t = 1_000;
    const cache = new ReplayCache(10, () => t, 60_000);
    assert.equal(cache.use('k', 2_000), 'ok');
    t = 2_500; // past expiry, inside the grace period
    assert.equal(cache.use('k', 2_000), 'replayed');
  });
});

describe('reviewer repro: replay after 10,000 other authorizations', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const now = Math.floor(Date.now() / 1000);
  const policy: ToolPolicy = { protected: true, allowed_signers: ['alice'], required_approvals: 1 };

  function authorization(id: string): { payload: CanonicalPayload; token: SignedToken } {
    const payload: CanonicalPayload = {
      request_id: `req-replay-${id}`, action: 'deploy:production', args: { ref: id },
      issued_at: now, expires_at: now + 600, nonce: `nonce-replay-${id}`,
    };
    const token: SignedToken = {
      request_id: payload.request_id, decision: 'approved',
      payload_hash: `sha256:${createHash('sha256').update(stableStringify(payload)).digest('hex')}`,
      signers: ['alice'], roles: ['admin'], signed_at: now, expires_at: now + 600, key_id: 'pp-prod-1', signature: '',
    };
    token.signature = sign(null, Buffer.from(buildAuthorizationSigningBytes(token)), privateKey).toString('hex');
    return { payload, token };
  }

  it('an unexpired authorization is still refused after 10,000 others', async () => {
    const first = authorization('first');
    await verifyAuthorization(first.payload, first.token, publicKeyPem, policy);
    for (let i = 0; i < 10_000; i++) {
      const a = authorization(String(i));
      await verifyAuthorization(a.payload, a.token, publicKeyPem, policy);
    }
    await assert.rejects(
      () => verifyAuthorization(first.payload, first.token, publicKeyPem, policy),
      /Replay detected/,
    );
  });
});
