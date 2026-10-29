import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { copyFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildArtifact } from '../signing/artifact.js';
import { mcpgKeyId, rawPublicKey } from '../signing/keys.js';
import { keySetPath, loadSigningKey, createKey, revokeKey } from '../keystore.js';
import { runVerify } from '../verify-cli.js';
import type { Decider } from '../issuer.js';
import { isolateKeys, testIssuer } from './helpers.js';

const FIXTURE = join(__dirname, '..', '..', '..', 'src', 'tests', 'fixtures', 'legacy-0.2');
const SHA = 'a1b2c3d4';

const quiet = <T>(fn: () => T): { code: T; out: string } => {
  const lines: string[] = [];
  const log = console.log, err = console.error;
  console.log = (m: string) => { lines.push(String(m)); }; console.error = (m: string) => { lines.push(String(m)); };
  try { return { code: fn(), out: lines.join('\n') }; } finally { console.log = log; console.error = err; }
};

/** The deploy-gate template's verify step, run against each trust-boundary case. */
describe('mcp-guard verify (receipt gate CLI)', () => {
  let dir: string;
  let trust: string;
  const deploy = (decider: Decider, sha = SHA, input: Record<string, unknown> = { env: 'production', sha }) => testIssuer().issue({
    method: 'tools/call', tool: 'deploy', input, status: 'APPROVED', ruleId: 'deploy',
    reasonCodes: ['RULE_MATCHED:deploy', 'OPERATOR_APPROVED'], decider, scope: { scope: 'deploy:production', scope_sha: sha },
  });
  const human: Decider = { kind: 'operator', operator: 'rod' };
  const write = (name: string, r: unknown) => { const p = join(dir, name); writeFileSync(p, JSON.stringify(r)); return p; };
  const gate = (file: string, extra: string[] = [], keys = keySetPath()) =>
    quiet(() => runVerify(['--receipt-file', file, '--keys', keys, '--trust', trust, '--scope', 'deploy:production', '--scope-sha', SHA, ...extra]));

  before(() => {
    dir = isolateKeys();
    const key = loadSigningKey();
    trust = `${key.keyId}=${key.fingerprint}`;
  });

  it('green: a human-approved receipt for this scope and commit', () => {
    const r = gate(write('ok.json', { artifact: deploy(human).artifact }));
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /VERIFIED \(jcs_v2, key pinned by --trust\)/);
  });

  it('accepts the JSONL line shape { artifact, record } as written by the guard', () => {
    assert.equal(gate(write('line.json', deploy(human))).code, 0);
  });

  it('red: a receipt for a different commit', () => {
    assert.equal(gate(write('sha.json', deploy(human, 'ffff'))).code, 1);
  });

  it('red: a receipt released by policy (countdown), not a person', () => {
    const r = gate(write('cd.json', deploy({ kind: 'policy' })));
    assert.equal(r.code, 1);
    assert.match(r.out, /PP_APPROVAL_NOT_HUMAN/);
  });

  it('red: a receipt forged with an attacker key, even in a key set the attacker supplies', () => {
    const attacker = generateKeyPairSync('ed25519');
    const raw = rawPublicKey(attacker.publicKey);
    const keyId = mcpgKeyId(raw);
    const forgedSet = write('attacker-keys.json', { keys: [{ key_id: keyId, alg: 'ed25519', public_key_b64: raw.toString('base64'), status: 'active', revoked_at: null }] });
    const record = { ...deploy(human).record, signatureKeyId: keyId, deciderId: 'local:ceo' };
    const file = write('forged.json', { artifact: buildArtifact(record, attacker.privateKey) });
    const r = gate(file, [], forgedSet);
    assert.equal(r.code, 1, 'refused: the attacker key is not the pinned one');
    assert.match(r.out, /KEY_NOT_TRUSTED/);
    // Without --trust the key set file is the only anchor; the template always pins.
    assert.equal(quiet(() => runVerify(['--receipt-file', file, '--keys', forgedSet, '--scope', 'deploy:production', '--scope-sha', SHA])).code, 0);
  });

  it('red: a receipt signed by a revoked key', () => {
    const revokedDir = isolateKeys();
    const key = loadSigningKey();
    const file = join(revokedDir, 'r.json');
    writeFileSync(file, JSON.stringify(deploy(human)));
    copyFileSync(keySetPath(), join(revokedDir, 'keys-before.json'));
    createKey({ rotate: true });
    revokeKey(key.keyId);
    const r = quiet(() => runVerify(['--receipt-file', file, '--keys', keySetPath(), '--trust', `${key.keyId}=${key.fingerprint}`, '--scope', 'deploy:production', '--scope-sha', SHA]));
    assert.equal(r.code, 1);
    assert.match(r.out, /KEY_REVOKED/);
    // Rotation alone keeps old receipts verifying.
    const before = quiet(() => runVerify(['--receipt-file', file, '--keys', join(revokedDir, 'keys-before.json'), '--trust', `${key.keyId}=${key.fingerprint}`, '--scope', 'deploy:production', '--scope-sha', SHA]));
    assert.equal(before.code, 0, before.out);
    // Restore the suite's key directory.
    process.env.PP_KEYS_DIR = join(dir, 'keys');
  });

  it('--call: the signed inputHash must recompute from the call', () => {
    const file = write('call.json', deploy(human));
    const good = write('good-call.json', { tool: 'deploy', operation: 'tools/call', input: { env: 'production', sha: SHA } });
    const bad = write('bad-call.json', { tool: 'deploy', operation: 'tools/call', input: { env: 'production', sha: SHA, force: true } });
    assert.equal(gate(file, ['--call', good]).code, 0);
    const r = gate(file, ['--call', bad]);
    assert.equal(r.code, 1);
    assert.match(r.out, /INPUT_HASH_MISMATCH/);
  });

  it('refuses to run without a scope expectation or with an empty one', () => {
    const file = write('ok2.json', deploy(human));
    assert.equal(quiet(() => runVerify(['--receipt-file', file, '--keys', keySetPath(), '--trust', trust])).code, 2);
    assert.equal(quiet(() => runVerify(['--receipt-file', file, '--keys', keySetPath(), '--trust', trust, '--scope', 'deploy:production', '--scope-sha', ''])).code, 2);
  });

  it('missing input exits 2, and --keys is required', () => {
    assert.equal(quiet(() => runVerify(['--receipt-file', join(dir, 'nope.json'), '--keys', keySetPath(), '--scope', 'x'])).code, 2);
    assert.equal(quiet(() => runVerify(['--receipt-file', write('x.json', deploy(human)), '--scope', 'deploy:production'])).code, 2);
  });
});

describe('mcp-guard verify on demo and legacy receipts', () => {
  it('refuses a demo-key receipt unless --allow-demo', () => {
    const dir = isolateKeys({ demo: true });
    const key = loadSigningKey();
    assert.match(key.keyId, /^mcpg-demo-[0-9a-f]{16}$/);
    const issued = testIssuer().issue({
      method: 'tools/call', tool: 'deploy', input: {}, status: 'APPROVED', ruleId: 'deploy', reasonCodes: ['OPERATOR_APPROVED'],
      decider: { kind: 'operator', operator: 'rod' }, scope: { scope: 'deploy:production', scope_sha: SHA },
    });
    assert.equal(issued.record.scope, 'demo');
    const file = join(dir, 'demo.json');
    writeFileSync(file, JSON.stringify(issued));
    const args = ['--receipt-file', file, '--keys', keySetPath(), '--trust', `${key.keyId}=${key.fingerprint}`, '--scope', 'deploy:production', '--scope-sha', SHA];
    const r = quiet(() => runVerify(args));
    assert.equal(r.code, 1);
    assert.match(r.out, /PP_DEMO_RECEIPT/);
    assert.equal(quiet(() => runVerify([...args, '--allow-demo'])).code, 0);
  });

  it('refuses a legacy 0.2 receipt unless --accept-legacy, then verifies it labelled legacy', () => {
    const base = ['--receipt-file', join(FIXTURE, 'receipt.json'), '--pubkey', join(FIXTURE, 'legacy.pub.pem'), '--scope', 'deploy:production', '--scope-sha', SHA];
    const refused = quiet(() => runVerify(base));
    assert.equal(refused.code, 1);
    assert.match(refused.out, /LEGACY_RECEIPT_REFUSED/);
    const accepted = quiet(() => runVerify([...base, '--accept-legacy']));
    assert.equal(accepted.code, 0, accepted.out);
    assert.match(accepted.out, /legacy mcp-guard 0\.2 receipt/);
  });
});
