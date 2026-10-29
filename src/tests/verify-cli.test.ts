import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { issueReceipt, signingBytes, type Receipt } from '../receipt.js';
import { exportPublicKey, keyIdForPublicKey } from '../signer.js';
import { buildArtifact } from '../signing/artifact.js';
import { canonicalJsonText } from '../signing/canonical.js';
import { fingerprintOf, mcpgKeyId, rawPublicKey } from '../signing/keys.js';
import { runVerify } from '../verify-cli.js';
import { isolateKeys } from './helpers.js';

const SHA_LEGACY = 'a1b2c3d4';
let legacyPinned = '';
const deployReceiptLegacy = () => issueReceipt({
  method: 'tools/call', tool: 'deploy', args: { env: 'production', sha: SHA_LEGACY },
  decision: { decision: 'allowed', rule_id: 'deploy', reason: 'approved' },
  approval: { kind: 'human', id: 'rod', via: 'local-token' }, actor: 'agent', mode: 'enforce', policy_sha256: 'p', ttl_seconds: 900, target_server: 's',
  scope: { scope: 'deploy:production', scope_sha: SHA_LEGACY },
});
const pinnedLegacy = () => legacyPinned;

/** The deploy-gate template's verify step, run against each trust-boundary case. */
describe('mcp-guard verify (receipt gate CLI)', () => {
  let dir: string;
  let pinned: string;
  const SHA = 'a1b2c3d4';

  const deployReceipt = (approval: Receipt['envelope']['approval'], sha = SHA) => issueReceipt({
    method: 'tools/call', tool: 'deploy', args: { env: 'production', sha },
    decision: { decision: 'allowed', rule_id: 'deploy', reason: 'approved' },
    approval, actor: 'agent', mode: 'enforce', policy_sha256: 'p', ttl_seconds: 900, target_server: 's',
    scope: { scope: 'deploy:production', scope_sha: sha },
  });
  const write = (name: string, r: unknown) => { const p = join(dir, name); writeFileSync(p, JSON.stringify(r)); return p; };
  const gate = (file: string, pubkey = pinned) => runVerify(['--receipt-file', file, '--pubkey', pubkey, '--scope', 'deploy:production', '--scope-sha', SHA]);
  const quiet = <T>(fn: () => T): T => {
    const log = console.log, err = console.error;
    console.log = () => {}; console.error = () => {};
    try { return fn(); } finally { console.log = log; console.error = err; }
  };

  before(() => {
    dir = isolateKeys();
    pinned = exportPublicKey(join(mkdtempSync(join(tmpdir(), 'pin-')), 'mcp-guard.pub.pem'));
    legacyPinned = pinned;
  });

  it('green: a human-approved receipt for this scope and commit', () => {
    assert.equal(quiet(() => gate(write('ok.json', deployReceipt({ kind: 'human', id: 'rod', via: 'local-token' })))), 0);
  });

  it('red: a receipt for a different commit', () => {
    assert.equal(quiet(() => gate(write('sha.json', deployReceipt({ kind: 'human', id: 'rod', via: 'local-token' }, 'ffff')))), 1);
  });

  it('red: a receipt released by countdown, not a human', () => {
    assert.equal(quiet(() => gate(write('cd.json', deployReceipt({ kind: 'policy', id: 'deploy', via: 'countdown' })))), 1);
  });

  it('red: a receipt forged with an attacker key, even when the attacker supplies that key', () => {
    const attacker = generateKeyPairSync('ed25519');
    const pem = attacker.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const forged = deployReceipt({ kind: 'human', id: 'ceo', via: 'local-token' });
    forged.envelope.key_id = keyIdForPublicKey(pem);
    forged.signature = { alg: 'ed25519', key_id: forged.envelope.key_id, value: sign(null, Buffer.from(signingBytes(forged.envelope)), attacker.privateKey).toString('hex') };
    const file = write('forged.json', forged);
    assert.equal(quiet(() => gate(file)), 1, 'refused against the pinned key');
    const attackerPem = join(dir, 'attacker.pub.pem');
    writeFileSync(attackerPem, pem);
    // The template never takes the key from the PR; this shows why it must not.
    assert.equal(quiet(() => gate(file, attackerPem)), 0);
  });

  it('refuses to run without a scope expectation or with an empty one', () => {
    const file = write('ok2.json', deployReceipt({ kind: 'human', id: 'rod', via: 'local-token' }));
    assert.equal(quiet(() => runVerify(['--receipt-file', file, '--pubkey', pinned])), 2);
    assert.equal(quiet(() => runVerify(['--receipt-file', file, '--pubkey', pinned, '--scope', 'deploy:production', '--scope-sha', ''])), 2);
  });

  it('missing input exits 2, and --pubkey is required', () => {
    assert.equal(quiet(() => runVerify(['--receipt-file', join(dir, 'nope.json'), '--pubkey', pinned])), 2);
    assert.equal(quiet(() => runVerify(['--receipt-file', write('x.json', {})])), 2);
  });
});

describe('mcp-guard verify on org-standard (jcs_v2) artifacts', () => {
  let dir2: string;
  const SHA2 = 'b1c2d3e4';
  before(() => { dir2 = mkdtempSync(join(tmpdir(), 'verify-jcs-')); });
  const quiet2 = <T>(fn: () => T): T => {
    const log = console.log, err = console.error;
    console.log = () => {}; console.error = () => {};
    try { return fn(); } finally { console.log = log; console.error = err; }
  };

  it('verifies with --keys and --trust, refuses a wrong pin, and needs --keys', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const raw = rawPublicKey(publicKey);
    const keyId = mcpgKeyId(raw);
    const keysPath = join(dir2, 'keys.json');
    writeFileSync(keysPath, JSON.stringify({ keys: [{ key_id: keyId, alg: 'ed25519', public_key_b64: raw.toString('base64'), status: 'active', revoked_at: null }] }));
    const now = Date.now();
    const artifact = buildArtifact({
      id: 'rcpt_mg_cli_1', agentId: 'a', runId: 'r', status: 'APPROVED', receiptVersion: 2, canonicalization: 'jcs_v2',
      signatureAlg: 'ed25519', signatureKeyId: keyId, createdAt: new Date(now).toISOString(), expiresAt: new Date(now + 900_000).toISOString(),
      requestJson: canonicalJsonText({ scope: { capability: 'deploy:production', commitSha: SHA2 } }),
      deciderId: 'local:rod', deciderAuthMethod: 'local_console', attributionConfidence: 'heuristic', resolutionType: 'allow_once', scope: 'production',
    }, privateKey);
    const file = join(dir2, 'r.json');
    writeFileSync(file, JSON.stringify({ artifact }));
    const base = ['--receipt-file', file, '--scope', 'deploy:production', '--scope-sha', SHA2];
    assert.equal(quiet2(() => runVerify([...base, '--keys', keysPath, '--trust', `${keyId}=${fingerprintOf(raw)}`])), 0);
    assert.equal(quiet2(() => runVerify([...base, '--keys', keysPath, '--trust', `${keyId}=sha256:${'0'.repeat(64)}`])), 1);
    assert.equal(quiet2(() => runVerify(base)), 2);
  });

  it('still verifies a legacy 0.2 receipt with --pubkey and labels it legacy', () => {
    const lines: string[] = [];
    const log = console.log;
    console.log = (m: string) => { lines.push(m); };
    try {
      const file = join(dir2, 'legacy.json');
      writeFileSync(file, JSON.stringify(deployReceiptLegacy()));
      assert.equal(runVerify(['--receipt-file', file, '--pubkey', pinnedLegacy(), '--scope', 'deploy:production', '--scope-sha', SHA_LEGACY]), 0);
    } finally { console.log = log; }
    assert.ok(lines.join('\n').includes('legacy mcp-guard 0.2 receipt'));
  });
});
