import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';
import { addPending, _resetQueue, type PendingAction } from '../pending.js';
import { signHeld, forwardReleased } from '../release.js';
import { keySetPath } from '../keystore.js';
import { rawPublicKey } from '../signing/keys.js';
import { ReplayCache } from '../verify-core.js';
import { isolateKeys, testIssuer } from './helpers.js';

function held(resolve: (l: string) => void, over: { scope_sha?: string } = {}): PendingAction {
  return addPending({
    toolName: 'deploy',
    toolArgs: { env: 'production', sha: 'abc' },
    agentId: 'agent',
    ruleId: 'deploy',
    forwardLine: '{"jsonrpc":"2.0","id":7,"method":"tools/call"}',
    jsonrpcId: 7,
    resolve,
    enrichment: { lane: 'decide', reversibility: 'irreversible', summary: 's', args_preview: 'p' },
    scope: 'deploy:production',
    scope_sha: over.scope_sha ?? 'abc',
  });
}

describe('release path (B9): forwards only what verifies', () => {
  beforeEach(() => { isolateKeys(); _resetQueue(); });

  it('a verifying receipt forwards exactly once; a replay of it is refused', () => {
    const issuer = testIssuer();
    const forwarded: string[] = [];
    const answers: string[] = [];
    const action = held((l) => answers.push(l));
    const issued = signHeld(issuer, action, { kind: 'operator', operator: 'rod' }, 'APPROVED', 'OPERATOR_APPROVED');
    const cache = new ReplayCache();
    forwardReleased(issuer, action, issued, cache, (l) => forwarded.push(l));
    assert.deepEqual(forwarded, [action.forwardLine]);
    assert.equal(action.receipt_id, issued.record.id);
    assert.throws(() => forwardReleased(issuer, action, issued, cache, (l) => forwarded.push(l)), /PP_REPLAYED/);
    assert.equal(forwarded.length, 1);
    assert.match(answers[0], /"code":-32005/);
  });

  it('refuses when the key set no longer holds the signing key (broken key material)', () => {
    const issuer = testIssuer();
    const forwarded: string[] = [];
    const answers: string[] = [];
    const action = held((l) => answers.push(l));
    const issued = signHeld(issuer, action, { kind: 'policy' }, 'APPROVED', 'COUNTDOWN_AUTO_RELEASE');
    // Swap the listed public key for another one after signing.
    const set = JSON.parse(readFileSync(keySetPath(), 'utf-8'));
    set.keys[0].public_key_b64 = rawPublicKey(generateKeyPairSync('ed25519').publicKey).toString('base64');
    writeFileSync(keySetPath(), JSON.stringify(set));
    assert.throws(() => forwardReleased(issuer, action, issued, new ReplayCache(), (l) => forwarded.push(l)), /release refused/);
    assert.deepEqual(forwarded, []);
    assert.match(answers[0], /"code":-32005/);
  });

  it('refuses a tampered receipt', () => {
    const issuer = testIssuer();
    const forwarded: string[] = [];
    const action = held(() => {});
    const issued = signHeld(issuer, action, { kind: 'operator', operator: 'rod' }, 'APPROVED', 'OPERATOR_APPROVED');
    const bytes = JSON.parse(Buffer.from(issued.artifact!.payload_bytes_b64, 'base64').toString('utf8'));
    bytes.deciderId = 'local:ceo';
    issued.artifact!.payload_bytes_b64 = Buffer.from(JSON.stringify(bytes)).toString('base64');
    assert.throws(() => forwardReleased(issuer, action, issued, new ReplayCache(), (l) => forwarded.push(l)), /SIGNED_PAYLOAD_HASH_MISMATCH/);
    assert.deepEqual(forwarded, []);
  });

  it('refuses a receipt for another scope than the held call', () => {
    const issuer = testIssuer();
    const forwarded: string[] = [];
    const action = held(() => {});
    const other = held(() => {}, { scope_sha: 'def' });
    const issued = signHeld(issuer, other, { kind: 'operator', operator: 'rod' }, 'APPROVED', 'OPERATOR_APPROVED');
    assert.throws(() => forwardReleased(issuer, action, issued, new ReplayCache(), (l) => forwarded.push(l)), /PP_SCOPE_MISMATCH/);
    assert.deepEqual(forwarded, []);
  });

  it('refuses a DENIED receipt', () => {
    const issuer = testIssuer();
    const forwarded: string[] = [];
    const action = held(() => {});
    const issued = signHeld(issuer, action, { kind: 'operator', operator: 'rod' }, 'DENIED', 'OPERATOR_DENIED');
    assert.throws(() => forwardReleased(issuer, action, issued, new ReplayCache(), (l) => forwarded.push(l)), /PP_NOT_AUTHORIZED/);
    assert.deepEqual(forwarded, []);
  });
});
