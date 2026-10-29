import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { issueReceipt, signingBytes, type Receipt } from '../receipt.js';
import { exportPublicKey, keyIdForPublicKey } from '../signer.js';
import { runVerify } from '../verify-cli.js';
import { isolateKeys } from './helpers.js';

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
