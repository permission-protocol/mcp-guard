import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalJsonText } from '../signing/canonical.js';
import { mcpgKeyId } from '../signing/keys.js';
import { ReplayCache } from '../verify-core.js';
import { argsHashOf, callFingerprint, fingerprintOfCall } from '../cloud/fingerprint.js';
import { PRODUCTION_KEY_SET, isDemoKeyId, pinsFor } from '../cloud/pinned-keys.js';
import { verifyCloudReceipt, type CloudReceiptArtifact, type CloudVerifyOptions } from '../cloud/verify.js';
import { mintCloudReceipt, receiptPayload, signBytes, testPpIssuer, type MintOptions } from './cloud-helpers.js';

const issuer = testPpIssuer();
const ARGS = { path: '/srv/data/report.csv', recursive: false };
const FINGERPRINT = fingerprintOfCall('filesystem', 'delete_file', ARGS);
const REQUEST_ID = `mcpreq_${'a'.repeat(32)}`;

const options = (over: Partial<CloudVerifyOptions> = {}): CloudVerifyOptions => ({
  keySet: issuer.keySet,
  trust: issuer.trust,
  fingerprint: FINGERPRINT,
  requestId: REQUEST_ID,
  expect: 'APPROVED',
  ...over,
});
const mint = (over: Partial<MintOptions> = {}): CloudReceiptArtifact =>
  mintCloudReceipt(issuer, { fingerprint: FINGERPRINT, requestId: REQUEST_ID, ...over });
const refused = (artifact: unknown, code: string, over: Partial<CloudVerifyOptions> = {}): void => {
  const result = verifyCloudReceipt(artifact, options(over));
  assert.equal(result.ok, false, `expected ${code}, but the receipt was accepted`);
  if (!result.ok) assert.equal(result.code, code, result.message);
};

describe('action fingerprint', () => {
  // The same vector is pinned in the app (tests/mcp-approval-unit.test.ts): both sides must agree.
  const VECTOR_ARGS = { path: '/srv/data/report.csv', recursive: false, tags: ['b', 'a'], nested: { z: 1, a: null } };

  it('matches the vector Permission Protocol computes', () => {
    assert.equal(canonicalJsonText(VECTOR_ARGS), '{"nested":{"a":null,"z":1},"path":"/srv/data/report.csv","recursive":false,"tags":["b","a"]}');
    assert.equal(argsHashOf(VECTOR_ARGS), 'sha256:ec1d957a3458226e331f43bb2075070e068b20d392b74dab0fd9a7eb41e2e6cc');
    assert.equal(
      callFingerprint({ server: 'filesystem', tool: 'delete_file', argsHash: argsHashOf(VECTOR_ARGS) }),
      'sha256:a625d4965bc1b1bb77e30e7002060d03cf04db4161e8f2e5ba62dcc005e2f93f',
    );
  });

  it('is the same for any key order and different for any changed argument, tool or server', () => {
    assert.equal(fingerprintOfCall('filesystem', 'delete_file', { recursive: false, path: '/srv/data/report.csv' }), FINGERPRINT);
    assert.notEqual(fingerprintOfCall('filesystem', 'delete_file', { ...ARGS, recursive: true }), FINGERPRINT);
    assert.notEqual(fingerprintOfCall('filesystem', 'delete_file', { ...ARGS, extra: 1 }), FINGERPRINT);
    assert.notEqual(fingerprintOfCall('filesystem', 'read_file', ARGS), FINGERPRINT);
    assert.notEqual(fingerprintOfCall('other-server', 'delete_file', ARGS), FINGERPRINT);
    assert.equal(argsHashOf(undefined), argsHashOf({}));
  });
});

describe('a receipt that releases the call', () => {
  it('verifies in the format production signs (jcs_v3), and reports who signed', () => {
    const result = verifyCloudReceipt(mint({ receiptId: 'rcpt_ok' }), options());
    assert.equal(result.ok, true, result.ok ? '' : result.message);
    if (!result.ok) return;
    assert.equal(result.receipt.receiptId, 'rcpt_ok');
    assert.equal(result.receipt.status, 'APPROVED');
    assert.equal(result.receipt.fingerprint, FINGERPRINT);
    assert.equal(result.receipt.requestId, REQUEST_ID);
    assert.deepEqual(result.receipt.decider, { id: 'user:u_maria', display: 'Maria Signer', authMethod: 'session_stepup_webauthn' });
  });

  it('verifies jcs_v2 (fingerprint in the signed request) and jcs_v4', () => {
    for (const canonicalization of ['jcs_v2', 'jcs_v4']) {
      const result = verifyCloudReceipt(mint({ canonicalization }), options());
      assert.equal(result.ok, true, `${canonicalization}: ${result.ok ? '' : result.message}`);
    }
  });

  it('accepts each session authentication method a person can sign with', () => {
    for (const deciderAuthMethod of ['session', 'session_stepup_webauthn', 'session_reauth']) {
      assert.equal(verifyCloudReceipt(mint({ deciderAuthMethod }), options()).ok, true);
    }
  });
});

describe('tampered receipts', () => {
  it('edited bytes with the old hash: hash mismatch', () => {
    const artifact = mint();
    const payload = JSON.parse(Buffer.from(artifact.payload_bytes_b64, 'base64').toString('utf8'));
    payload.deciderDisplay = 'Someone Else';
    refused({ ...artifact, payload_bytes_b64: Buffer.from(canonicalJsonText(payload)).toString('base64') }, 'SIGNED_PAYLOAD_HASH_MISMATCH');
  });

  it('edited bytes with a recomputed hash: signature invalid', () => {
    const artifact = mint();
    const payload = JSON.parse(Buffer.from(artifact.payload_bytes_b64, 'base64').toString('utf8'));
    payload.expiresAt = new Date(Date.now() + 86_400_000).toISOString();
    const bytes = Buffer.from(canonicalJsonText(payload));
    refused({ ...artifact, payload_bytes_b64: bytes.toString('base64'), signed_payload_hash: createHash('sha256').update(bytes).digest('hex') }, 'SIGNATURE_INVALID');
  });

  it('a DENIED receipt relabelled approved in the envelope is still DENIED in the bytes', () => {
    refused({ ...mint({ status: 'DENIED' }), status: 'APPROVED' }, 'NOT_APPROVED');
  });

  it('a flipped signature bit', () => {
    const artifact = mint();
    const signature = Buffer.from(artifact.signature_b64, 'base64');
    signature[0] ^= 1;
    refused({ ...artifact, signature_b64: signature.toString('base64') }, 'SIGNATURE_INVALID');
  });

  it('a valid signature by a key that is not pinned', () => {
    const stranger = testPpIssuer('pp-test-cloud-k1'); // same key id, different key
    refused(mintCloudReceipt(stranger, { fingerprint: FINGERPRINT, requestId: REQUEST_ID }), 'SIGNATURE_INVALID');
    const unknown = testPpIssuer('pp-some-other-key');
    refused(mintCloudReceipt(unknown, { fingerprint: FINGERPRINT, requestId: REQUEST_ID }), 'KEY_NOT_FOUND');
    // A key the API vouches for but the pins do not: refused even when it is in the key set.
    refused(mintCloudReceipt(unknown, { fingerprint: FINGERPRINT, requestId: REQUEST_ID }), 'KEY_NOT_TRUSTED', { keySet: unknown.keySet, trust: issuer.trust });
  });

  it('a revoked key', () => {
    const revoked = { ...issuer.keySet, keys: issuer.keySet.keys.map((k) => ({ ...k, status: 'revoked' })) };
    refused(mint(), 'KEY_REVOKED', { keySet: revoked });
  });

  it('non-canonical signed bytes, an envelope naming another receipt, an unknown format', () => {
    const payload = receiptPayload(issuer, { fingerprint: FINGERPRINT, requestId: REQUEST_ID, receiptId: 'rcpt_nc' });
    refused(signBytes(issuer, JSON.stringify(payload, null, 1), 'rcpt_nc', 'APPROVED', 'jcs_v3'), 'NON_CANONICAL_PAYLOAD');
    refused({ ...mint({ receiptId: 'rcpt_a' }), receipt_id: 'rcpt_b' }, 'IDENTITY_MISMATCH');
    refused(mint({ canonicalization: 'jcs_v9' }), 'CANONICALIZATION_UNSUPPORTED');
    refused(mint({ canonicalization: 'jcs_v1' }), 'CANONICALIZATION_UNSUPPORTED');
  });

  it('malformed artifacts', () => {
    for (const bad of [null, undefined, 'receipt', 42, [], {}, { ...mint(), alg: 'rs256' }, { ...mint(), signature_b64: '' }, { ...mint(), payload_bytes_b64: 'bm90IGpzb24=' }]) {
      const result = verifyCloudReceipt(bad, options());
      assert.equal(result.ok, false);
    }
  });
});

describe('a real signature for something else', () => {
  it('arguments changed after approval: the fingerprint no longer matches', () => {
    const signedForOriginal = mint();
    const changed = fingerprintOfCall('filesystem', 'delete_file', { ...ARGS, path: '/srv/data/everything' });
    refused(signedForOriginal, 'FINGERPRINT_MISMATCH', { fingerprint: changed });
    refused(signedForOriginal, 'FINGERPRINT_MISMATCH', { fingerprint: fingerprintOfCall('filesystem', 'delete_file', { ...ARGS, recursive: true }) });
    refused(signedForOriginal, 'FINGERPRINT_MISMATCH', { fingerprint: fingerprintOfCall('filesystem', 'delete_all', ARGS) });
    refused(signedForOriginal, 'FINGERPRINT_MISMATCH', { fingerprint: fingerprintOfCall('prod-db', 'delete_file', ARGS) });
  });

  it('a receipt for another request, another lane, or a rejection', () => {
    refused(mint(), 'REQUEST_MISMATCH', { requestId: `mcpreq_${'b'.repeat(32)}` });
    refused(mint({ laneTool: 'twin' }), 'WRONG_LANE');
    refused(mint({ laneTool: 'inline_gate' }), 'WRONG_LANE');
    refused(mint({ status: 'DENIED' }), 'NOT_APPROVED');
    refused(mint({ fields: { status: 'EXPIRED' } }), 'NOT_APPROVED');
  });

  it('an expired receipt, and one with no expiry', () => {
    refused(mint({ expiresAt: new Date(Date.now() - 1_000).toISOString() }), 'EXPIRED');
    refused(mint({ expiresAt: null }), 'EXPIRED');
    refused(mint({ expiresAt: 'tomorrow' }), 'EXPIRED');
    // Valid now, expired by the time it is checked.
    const soon = mint({ expiresAt: new Date(Date.now() + 60_000).toISOString() });
    assert.equal(verifyCloudReceipt(soon, options()).ok, true);
    refused(soon, 'EXPIRED', { now: new Date(Date.now() + 61_000) });
  });

  it('a replayed receipt', () => {
    const replayCache = new ReplayCache();
    const artifact = mint();
    assert.equal(verifyCloudReceipt(artifact, options({ replayCache })).ok, true);
    refused(artifact, 'REPLAYED', { replayCache });
    refused(artifact, 'REPLAYED', { replayCache });
  });

  it('a decision no person made', () => {
    refused(mint({ deciderId: 'system/pp-engine', deciderAuthMethod: null }), 'DECIDER_NOT_HUMAN');
    refused(mint({ deciderId: 'api_key:key_1', deciderAuthMethod: 'api_key' }), 'DECIDER_NOT_HUMAN');
    refused(mint({ deciderId: 'user:u_maria', deciderAuthMethod: 'api_key' }), 'DECIDER_NOT_HUMAN');
    refused(mint({ deciderId: 'user:u_maria', deciderAuthMethod: null }), 'DECIDER_NOT_HUMAN');
    refused(mint({ deciderId: 'user:' }), 'DECIDER_NOT_HUMAN');
    refused(mint({ deciderId: null }), 'DECIDER_NOT_HUMAN');
    refused(mint({ deciderId: 'demo:visitor', deciderAuthMethod: 'anonymous_demo' }), 'DECIDER_NOT_HUMAN');
  });

  it('a demo receipt or a demo key', () => {
    refused(mint({ scope: 'demo' }), 'DEMO_RECEIPT');
    const demo = testPpIssuer('pp-demo-k1');
    refused(mintCloudReceipt(demo, { fingerprint: FINGERPRINT, requestId: REQUEST_ID }), 'DEMO_KEY', { keySet: demo.keySet, trust: demo.trust });
    assert.equal(isDemoKeyId('pp-demo-k1'), true);
  });

  it("an mcp-guard demo key (mcpg-demo-) in a supplied key set, even claiming production scope", () => {
    const base = testPpIssuer();
    const keyId = mcpgKeyId(Buffer.from(base.publicKeyB64, 'base64'), true);
    const keySet = { issuer: 'https://pp.test', keys: [{ key_id: keyId, alg: 'ed25519', public_key_b64: base.publicKeyB64 }] };
    const demo = { ...base, keyId, keySet, trust: pinsFor(keySet) };
    refused(mintCloudReceipt(demo, { fingerprint: FINGERPRINT, requestId: REQUEST_ID }), 'DEMO_KEY', { keySet, trust: demo.trust });
    assert.equal(isDemoKeyId(keyId), true);
  });
});

describe('a denial', () => {
  it('verifies as a signed DENIED, human or system, and never as an approval', () => {
    const byPerson = verifyCloudReceipt(mint({ status: 'DENIED' }), options({ expect: 'DENIED' }));
    assert.equal(byPerson.ok, true);
    const bySystem = verifyCloudReceipt(mint({ status: 'DENIED', deciderId: 'system/pp-engine', deciderDisplay: null, deciderAuthMethod: null, expiresAt: null }), options({ expect: 'DENIED' }));
    assert.equal(bySystem.ok, true);
    refused(mint(), 'NOT_APPROVED', { expect: 'DENIED' });
  });
});

describe('pinned production keys', () => {
  it('are two Ed25519 keys, pinned by fingerprint, that no test key can stand in for', () => {
    assert.deepEqual(PRODUCTION_KEY_SET.keys.map((k) => k.key_id), ['pp_key_default', 'pp_key_348f56d61d0deab4']);
    for (const key of PRODUCTION_KEY_SET.keys) {
      assert.equal(key.alg, 'ed25519');
      assert.equal(Buffer.from(key.public_key_b64, 'base64').length, 32);
    }
    const pins = pinsFor(PRODUCTION_KEY_SET);
    assert.equal(pins.size, 2);
    // Signed by a test key that claims a production key id: the pinned bytes decide.
    const impostor = testPpIssuer('pp_key_default');
    const result = verifyCloudReceipt(
      mintCloudReceipt(impostor, { fingerprint: FINGERPRINT, requestId: REQUEST_ID }),
      options({ keySet: PRODUCTION_KEY_SET, trust: pins }),
    );
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'SIGNATURE_INVALID');
    // And the API cannot hand the guard a key set of its own.
    refused(mintCloudReceipt(impostor, { fingerprint: FINGERPRINT, requestId: REQUEST_ID }), 'KEY_NOT_TRUSTED', { keySet: impostor.keySet, trust: pins });
  });
});
