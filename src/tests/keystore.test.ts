import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { createKey, keysDir, keySetPath, loadSigningKey, revokeKey, SigningError } from '../keystore.js';
import { fingerprintOf, mcpgKeyId } from '../signing/keys.js';
import { isolateKeys } from './helpers.js';

const code = (fn: () => unknown): string => {
  try { fn(); } catch (err) { assert.ok(err instanceof SigningError, String(err)); return err.code; }
  assert.fail('expected a SigningError');
};

describe('keystore: explicit keys, typed failures', () => {
  beforeEach(() => { isolateKeys({ init: false }); });

  it('keys init writes keys.json in the key-set shape and a 0600 private key', () => {
    const key = createKey();
    assert.match(key.keyId, /^mcpg-[0-9a-f]{16}$/);
    assert.equal(key.keyId, mcpgKeyId(key.rawPublicKey));
    assert.equal(key.fingerprint, fingerprintOf(key.rawPublicKey));
    const set = JSON.parse(readFileSync(keySetPath(), 'utf-8'));
    assert.equal(set.issuer, 'local:mcp-guard');
    assert.deepEqual(Object.keys(set.keys[0]).sort(), ['alg', 'created_at', 'key_id', 'public_key_b64', 'revoked_at', 'status']);
    assert.equal(set.keys[0].public_key_b64, key.rawPublicKey.toString('base64'));
    if (process.platform !== 'win32') {
      assert.equal(statSync(join(keysDir(), `${key.keyId}.private.pem`)).mode & 0o777, 0o600);
      assert.equal(statSync(keysDir()).mode & 0o777, 0o700);
    }
  });

  it('demo keys get the mcpg-demo- prefix', () => {
    const key = createKey({ demo: true });
    assert.match(key.keyId, /^mcpg-demo-[0-9a-f]{16}$/);
    assert.equal(key.demo, true);
  });

  it('defaults to the config directory, not cwd', () => {
    const saved = process.env.PP_KEYS_DIR;
    delete process.env.PP_KEYS_DIR;
    try {
      assert.ok(keysDir().endsWith(join('mcp-guard', 'keys')));
      assert.ok(!keysDir().startsWith(process.cwd()));
    } finally {
      process.env.PP_KEYS_DIR = saved;
    }
  });

  it('init refuses to overwrite; rotate adds a key and the signer uses the newest', () => {
    const first = createKey();
    assert.throws(() => createKey(), /already exists/);
    const second = createKey({ rotate: true });
    assert.notEqual(second.keyId, first.keyId);
    assert.equal(loadSigningKey().keyId, second.keyId);
    const set = JSON.parse(readFileSync(keySetPath(), 'utf-8'));
    assert.deepEqual(set.keys.map((k: any) => k.key_id), [first.keyId, second.keyId]);
  });

  it('SIGNING_KEY_MISSING: no key set, or no private key; the signer never creates one', () => {
    assert.equal(code(() => loadSigningKey()), 'SIGNING_KEY_MISSING');
    assert.ok(!existsSync(keySetPath()), 'nothing was created');
    const key = createKey();
    rmSync(join(keysDir(), `${key.keyId}.private.pem`));
    assert.equal(code(() => loadSigningKey()), 'SIGNING_KEY_MISSING');
  });

  it('SIGNING_KEY_REVOKED: the newest key is revoked; no fallback to an older key', () => {
    createKey();
    const second = createKey({ rotate: true });
    revokeKey(second.keyId);
    assert.equal(code(() => loadSigningKey()), 'SIGNING_KEY_REVOKED');
  });

  it('SIGNING_KEY_INVALID: wrong key type, mismatched id, mismatched key-set entry, bad JSON', () => {
    const key = createKey();
    const pem = join(keysDir(), `${key.keyId}.private.pem`);
    const original = readFileSync(pem, 'utf-8');

    chmodSync(pem, 0o600);
    writeFileSync(pem, generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString());
    assert.equal(code(() => loadSigningKey()), 'SIGNING_KEY_INVALID', 'a different key under this id');

    writeFileSync(pem, generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString());
    assert.equal(code(() => loadSigningKey()), 'SIGNING_KEY_INVALID', 'not ed25519');

    writeFileSync(pem, original);
    const set = JSON.parse(readFileSync(keySetPath(), 'utf-8'));
    set.keys[0].public_key_b64 = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }).subarray(12).toString('base64');
    writeFileSync(keySetPath(), JSON.stringify(set));
    assert.equal(code(() => loadSigningKey()), 'SIGNING_KEY_INVALID', 'key-set entry is another key');

    writeFileSync(keySetPath(), '{not json');
    assert.equal(code(() => loadSigningKey()), 'SIGNING_KEY_INVALID', 'unreadable keys.json');
  });

  it('SIGNING_KEY_INVALID: a private key or key directory others can access', { skip: process.platform === 'win32' }, () => {
    const key = createKey();
    const pem = join(keysDir(), `${key.keyId}.private.pem`);
    chmodSync(pem, 0o644);
    assert.equal(code(() => loadSigningKey()), 'SIGNING_KEY_INVALID');
    chmodSync(pem, 0o600);
    chmodSync(keysDir(), 0o777);
    assert.equal(code(() => loadSigningKey()), 'SIGNING_KEY_INVALID');
    chmodSync(keysDir(), 0o700);
    assert.equal(loadSigningKey().keyId, key.keyId);
  });

  it('SIGNING_KEY_INVALID: a keys.json others can write, so a revocation cannot be edited away', { skip: process.platform === 'win32' }, () => {
    const key = createKey();
    chmodSync(keysDir(), 0o755);
    revokeKey(key.keyId);
    chmodSync(keySetPath(), 0o666);
    assert.equal(code(() => loadSigningKey()), 'SIGNING_KEY_INVALID', 'a writable revoked key set');
    const set = JSON.parse(readFileSync(keySetPath(), 'utf-8'));
    set.keys[0].status = 'active';
    set.keys[0].revoked_at = null;
    writeFileSync(keySetPath(), JSON.stringify(set));
    assert.equal(code(() => loadSigningKey()), 'SIGNING_KEY_INVALID', 'the revocation edited away by another user');
    chmodSync(keySetPath(), 0o620);
    assert.equal(code(() => loadSigningKey()), 'SIGNING_KEY_INVALID', 'group-writable');
    chmodSync(keySetPath(), 0o644);
    assert.equal(loadSigningKey().keyId, key.keyId, 'the owner may still restore it');
  });

  it('SIGNING_KEY_INVALID: a key-set entry the verifier would reject (alg, duplicate id)', () => {
    const key = createKey();
    const good = readFileSync(keySetPath(), 'utf-8');

    const rsa = JSON.parse(good);
    rsa.keys[0].alg = 'rsa';
    writeFileSync(keySetPath(), JSON.stringify(rsa));
    assert.equal(code(() => loadSigningKey()), 'SIGNING_KEY_INVALID', 'alg is not ed25519');

    const dup = JSON.parse(good);
    dup.keys = [dup.keys[0], { ...dup.keys[0] }];
    writeFileSync(keySetPath(), JSON.stringify(dup));
    assert.equal(code(() => loadSigningKey()), 'SIGNING_KEY_INVALID', 'key id listed twice');

    writeFileSync(keySetPath(), good);
    assert.equal(loadSigningKey().keyId, key.keyId);
  });
});
