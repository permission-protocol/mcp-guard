import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { createPublicKey, verify } from 'node:crypto';
import { currentKeyId, getPublicKeyPem, keyIdForPublicKey, keysDir, signBytes, _resetSigner, KeyPermissionError } from '../signer.js';
import { isolateKeys } from './helpers.js';

describe('Dev signer', () => {
  beforeEach(() => { isolateKeys(); });

  it('keeps keys under PP_KEYS_DIR (never the working directory)', () => {
    signBytes('x');
    assert.ok(existsSync(join(keysDir(), 'signing.private.pem')));
    assert.ok(!existsSync(join(process.cwd(), '.keys', 'signing.private.pem')));
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

  it('creates a 0700 directory and a 0600 private key', { skip: process.platform === 'win32' }, () => {
    signBytes('x');
    assert.equal(statSync(keysDir()).mode & 0o777, 0o700);
    assert.equal(statSync(join(keysDir(), 'signing.private.pem')).mode & 0o777, 0o600);
  });

  it('refuses a private key readable by others', { skip: process.platform === 'win32' }, () => {
    signBytes('x');
    chmodSync(join(keysDir(), 'signing.private.pem'), 0o644);
    _resetSigner();
    assert.throws(() => signBytes('x'), KeyPermissionError);
  });

  it('refuses a key directory others can write', { skip: process.platform === 'win32' }, () => {
    signBytes('x');
    chmodSync(keysDir(), 0o777);
    _resetSigner();
    assert.throws(() => signBytes('x'), KeyPermissionError);
  });

  it('derives the key id from the public key fingerprint', () => {
    const id = currentKeyId();
    assert.match(id, /^pp-dev-[0-9a-f]{16}$/);
    assert.equal(keyIdForPublicKey(getPublicKeyPem()), id);
  });

  it('produces real Ed25519 signatures', () => {
    const { keyId, value } = signBytes('hello');
    assert.equal(keyId, currentKeyId());
    assert.ok(verify(null, Buffer.from('hello'), createPublicKey(getPublicKeyPem()), Buffer.from(value, 'hex')));
  });

  it('reuses the same key across loads', () => {
    const id = currentKeyId();
    _resetSigner();
    assert.equal(currentKeyId(), id);
  });
});
