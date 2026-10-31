import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { buildArtifact, checkArtifact, type ReceiptArtifact } from '../signing/artifact.js';
import { canonicalizeJcsV2, canonicalJsonText } from '../signing/canonical.js';
import { fingerprintOf, mcpgKeyId, rawPublicKey, parseTrust, type KeySet } from '../signing/keys.js';
import { verifyArtifactReceipt } from '../receipt-verify.js';
import { ReplayCache } from '../verify-core.js';

function keypair(demo = false) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const raw = rawPublicKey(publicKey);
  const keyId = mcpgKeyId(raw, demo);
  return { privateKey, raw, keyId, fp: fingerprintOf(raw), entry: { key_id: keyId, alg: 'ed25519', public_key_b64: raw.toString('base64'), status: 'active', created_at: '2026-10-29T00:00:00.000Z', revoked_at: null } };
}

const k = keypair();
const keySet: KeySet = { issuer: 'local:mcp-guard', keys: [k.entry] };
const pins = new Map([[k.keyId, k.fp]]);
const SHA = '308d9db71a3c1b446dfcd8abb2ba25639d67c745';

function record(over: Record<string, unknown> = {}, scope: Record<string, unknown> | null = { capability: 'deploy:production', commitSha: SHA }) {
  const now = Date.now();
  return {
    id: 'rcpt_mg_test_0001',
    idemKey: 'mcp-guard:pending-1',
    agentId: 'agent-1',
    runId: 'run-1',
    requestJson: canonicalJsonText({ action: { operation: 'tools/call', resource: 'srv', tool: 'deploy' }, ...(scope ? { scope } : {}) }),
    inputHash: 'sha256:' + 'ab'.repeat(32),
    status: 'APPROVED',
    riskTier: 'high',
    policyVersion: 'mcp-guard-config:sha256:' + 'cd'.repeat(32),
    reasonCodes: '["OPERATOR_APPROVED"]',
    summary: 'Deploy approved',
    receiptVersion: 2,
    canonicalization: 'jcs_v2',
    signatureAlg: 'ed25519',
    signatureKeyId: k.keyId,
    expiresAt: new Date(now + 15 * 60_000).toISOString(),
    createdAt: new Date(now).toISOString(),
    deciderId: 'local:rod',
    deciderDisplay: 'rod',
    deciderAuthMethod: 'local_console',
    resolutionType: 'allow_once',
    attributionConfidence: 'heuristic',
    scope: 'production',
    ...over,
  };
}

/** Sign arbitrary bytes as an artifact, for crafting malformed-but-signed cases. */
function signBytes(text: string, base: ReceiptArtifact, key = k.privateKey): ReceiptArtifact {
  const bytes = Buffer.from(text, 'utf8');
  const digest = createHash('sha256').update(bytes).digest();
  return { ...base, payload_bytes_b64: bytes.toString('base64'), signed_payload_hash: digest.toString('hex'), signature_b64: sign(null, digest, key).toString('base64') };
}

const codeOf = (fn: () => unknown) => { try { fn(); return 'OK'; } catch (e: any) { return e.code; } };

describe('jcs_v2 artifact checks (spec order, one test per failure code)', () => {
  const good = buildArtifact(record(), k.privateKey);

  it('a freshly built artifact verifies, pinned and unpinned', () => {
    assert.equal(codeOf(() => checkArtifact(good, keySet, pins)), 'OK');
    assert.equal(codeOf(() => checkArtifact(good, keySet, null)), 'OK');
  });

  it('SIGNED_PAYLOAD_HASH_MISMATCH: bytes changed, hash and signature kept', () => {
    const t = { ...good, payload_bytes_b64: Buffer.from(canonicalizeJcsV2(record({ status: 'DENIED' }))).toString('base64') };
    assert.equal(codeOf(() => checkArtifact(t, keySet, pins)), 'SIGNED_PAYLOAD_HASH_MISMATCH');
  });

  it('SIGNATURE_INVALID: bytes and hash changed, signature kept', () => {
    const forged = signBytes(canonicalizeJcsV2(record({ deciderId: 'local:ceo' })), good);
    const t = { ...forged, signature_b64: good.signature_b64 };
    assert.equal(codeOf(() => checkArtifact(t, keySet, pins)), 'SIGNATURE_INVALID');
  });

  it('CANONICALIZATION_UNSUPPORTED: a validly signed payload naming another canonicalization', () => {
    const t = signBytes(canonicalJsonText({ ...record(), canonicalization: 'jcs_v9' }), good);
    assert.equal(codeOf(() => checkArtifact(t, keySet, pins)), 'CANONICALIZATION_UNSUPPORTED');
  });

  it('NON_CANONICAL_PAYLOAD: signed bytes with an unlisted field or other formatting', () => {
    const extra = signBytes(canonicalJsonText({ ...record(), approvedByCeo: true }), good);
    assert.equal(codeOf(() => checkArtifact(extra, keySet, pins)), 'NON_CANONICAL_PAYLOAD');
    const spaced = signBytes(JSON.stringify(JSON.parse(canonicalizeJcsV2(record())), null, 1), good);
    assert.equal(codeOf(() => checkArtifact(spaced, keySet, pins)), 'NON_CANONICAL_PAYLOAD');
  });

  it('IDENTITY_MISMATCH: artifact id or key id differs from the signed ones', () => {
    assert.equal(codeOf(() => checkArtifact({ ...good, receipt_id: 'rcpt_other' }, keySet, pins)), 'IDENTITY_MISMATCH');
    const k2 = keypair();
    const twoKeys = { keys: [k.entry, k2.entry] };
    const signedByK2NamingK1 = signBytes(canonicalizeJcsV2(record()), { ...good, key_id: k2.keyId }, k2.privateKey);
    assert.equal(codeOf(() => checkArtifact(signedByK2NamingK1, twoKeys, null)), 'IDENTITY_MISMATCH');
  });

  it('KEY_NOT_FOUND / KEY_NOT_TRUSTED / KEY_REVOKED / KEY_SET_INVALID', () => {
    const attacker = keypair();
    const forged = buildArtifact(record({ signatureKeyId: attacker.keyId }), attacker.privateKey);
    assert.equal(codeOf(() => checkArtifact(forged, keySet, pins)), 'KEY_NOT_FOUND');
    assert.equal(codeOf(() => checkArtifact(forged, { keys: [k.entry, attacker.entry] }, pins)), 'KEY_NOT_TRUSTED', 'attacker key in the set but not pinned');
    assert.equal(codeOf(() => checkArtifact(good, keySet, new Map([[k.keyId, attacker.fp]]))), 'KEY_NOT_TRUSTED', 'pin mismatch');
    assert.equal(codeOf(() => checkArtifact(good, { keys: [{ ...k.entry, status: 'revoked', revoked_at: '2026-10-29T01:00:00.000Z' }] }, null)), 'KEY_REVOKED');
    assert.equal(codeOf(() => checkArtifact(good, { keys: [k.entry, k.entry] }, null)), 'KEY_SET_INVALID', 'listed twice');
    assert.equal(codeOf(() => checkArtifact(good, { keys: [{ ...k.entry, public_key_b64: attacker.raw.toString('base64') }] }, null)), 'KEY_SET_INVALID', 'mcpg id is not the key fingerprint');
    assert.equal(codeOf(() => checkArtifact(good, {}, null)), 'KEY_SET_INVALID');
  });

  it('parses --trust pins and rejects malformed ones', () => {
    assert.equal(parseTrust([`${k.keyId}=${k.fp}`]).get(k.keyId), k.fp);
    assert.throws(() => parseTrust([`${k.keyId}=md5:abc`]));
  });
});

describe('gate checks on jcs_v2 artifacts (the G7 cases)', () => {
  const v = (rec: Record<string, unknown>, opts = {}) =>
    verifyArtifactReceipt({ artifact: buildArtifact(rec, k.privateKey) }, keySet, { trust: pins, expected: { scope: 'deploy:production', scope_sha: SHA }, ...opts });

  it('a human-approved receipt for this scope and commit passes', () => {
    assert.deepEqual(v(record()).reasons, []);
  });

  it('a demo key is refused even when the signed scope claims production', () => {
    const demo = keypair(true);
    const demoSet: KeySet = { keys: [demo.entry] };
    const demoPins = new Map([[demo.keyId, demo.fp]]);
    const artifact = buildArtifact(record({ signatureKeyId: demo.keyId }), demo.privateKey);
    const result = verifyArtifactReceipt({ artifact }, demoSet, {
      trust: demoPins,
      expected: { scope: 'deploy:production', scope_sha: SHA }
    });
    assert.ok(result.reasons.some((x) => x.startsWith('PP_DEMO_RECEIPT')));
  });

  it('a receipt for another commit is refused', () => {
    const r = v(record({ requestJson: canonicalJsonText({ action: { tool: 'deploy' }, scope: { capability: 'deploy:production', commitSha: 'f'.repeat(40) } }) }));
    assert.ok(r.reasons.some((x) => x.startsWith('PP_SCOPE_MISMATCH')));
  });

  it('a countdown or policy release is refused for a scoped action unless policy approval is allowed', () => {
    const policy = record({ deciderId: 'system/mcp-guard-policy', deciderAuthMethod: 'policy', attributionConfidence: 'credentialed', resolutionType: null, reasonCodes: '["COUNTDOWN_AUTO_RELEASE"]' });
    assert.ok(v(policy).reasons.some((x) => x.startsWith('PP_APPROVAL_NOT_HUMAN')));
    assert.deepEqual(v(policy, { allowPolicyApproval: true }).reasons, []);
    const unattributed = record({ attributionConfidence: 'unattributed' });
    assert.ok(v(unattributed).reasons.some((x) => x.startsWith('PP_APPROVAL_NOT_HUMAN')));
  });

  it('a receipt forged with an attacker key is refused even when it claims a human', () => {
    const attacker = keypair();
    const forged = buildArtifact(record({ signatureKeyId: attacker.keyId, deciderId: 'local:ceo' }), attacker.privateKey);
    const r = verifyArtifactReceipt({ artifact: forged }, { keys: [k.entry, attacker.entry] }, { trust: pins, expected: { scope: 'deploy:production', scope_sha: SHA } });
    assert.ok(r.reasons.some((x) => x.startsWith('KEY_NOT_TRUSTED')));
  });

  it('denied, expired and expiry-less receipts are refused; unscoped receipts fail a scoped gate', () => {
    assert.ok(v(record({ status: 'DENIED' })).reasons.some((x) => x.startsWith('PP_NOT_AUTHORIZED')));
    assert.ok(v(record({ expiresAt: new Date(Date.now() - 1000).toISOString() })).reasons.some((x) => x.startsWith('PP_EXPIRED')));
    assert.ok(v(record({ expiresAt: null })).reasons.some((x) => x.startsWith('PP_EXPIRED')));
    assert.ok(v(record({}, null)).reasons.some((x) => x.startsWith('PP_SCOPE_MISMATCH')));
  });

  it('the gate reads the signed payload, not the artifact convenience fields', () => {
    const denied = buildArtifact(record({ status: 'DENIED' }), k.privateKey);
    const r = verifyArtifactReceipt({ artifact: { ...denied, status: 'APPROVED', expires_at: '2099-01-01T00:00:00.000Z' } }, keySet, { trust: pins });
    assert.ok(r.reasons.some((x) => x.startsWith('PP_NOT_AUTHORIZED')));
  });

  it('a replay cache honors an artifact once', () => {
    const cache = new ReplayCache();
    const a = { artifact: buildArtifact(record(), k.privateKey) };
    assert.equal(verifyArtifactReceipt(a, keySet, { trust: pins, replayCache: cache }).valid, true);
    assert.ok(verifyArtifactReceipt(a, keySet, { trust: pins, replayCache: cache }).reasons.some((x) => x.startsWith('PP_REPLAYED')));
  });
});
