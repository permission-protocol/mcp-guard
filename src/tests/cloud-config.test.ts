import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseConfig } from '../config.js';
import { PRODUCTION_API_URL } from '../cloud/pinned-keys.js';
import { InstallTokenError, loadInstallToken } from '../cloud/token.js';
import { testPpIssuer } from './cloud-helpers.js';

const BASE = 'default_action: block\nrules: []\n';
const key = testPpIssuer();
const trust = `  trust_keys:\n    - { key_id: ${key.keyId}, public_key_b64: "${key.publicKeyB64}" }\n`;
const cloud = (body: string) => parseConfig(`${BASE}cloud:\n${body}`);

describe('cloud config', () => {
  it('is absent by default: local-only', () => {
    assert.equal(parseConfig(BASE).cloud, undefined);
  });

  it('defaults to the production API, production label and a ten-minute wait', () => {
    assert.deepEqual(parseConfig(`${BASE}cloud: {}\n`).cloud, { api_url: PRODUCTION_API_URL, environment: 'production', approval_timeout_seconds: 600 });
  });

  it('the production keys cannot be replaced from the policy file', () => {
    assert.throws(() => cloud(trust), /pinned in this release/);
    assert.throws(() => cloud(`  api_url: ${PRODUCTION_API_URL}\n${trust}`), /pinned in this release/);
    assert.throws(() => cloud(`  api_url: ${PRODUCTION_API_URL}/\n${trust}`), /pinned in this release/);
  });

  it('another API must name the keys it pins', () => {
    assert.throws(() => cloud('  api_url: https://staging.example.test\n'), /trust_keys is required/);
    const parsed = cloud(`  api_url: http://127.0.0.1:4396\n  environment: staging\n  approval_timeout_seconds: 45\n${trust}`).cloud!;
    assert.equal(parsed.api_url, 'http://127.0.0.1:4396');
    assert.equal(parsed.environment, 'staging');
    assert.equal(parsed.approval_timeout_seconds, 45);
    assert.deepEqual(parsed.trust_keys, [{ key_id: key.keyId, alg: 'ed25519', public_key_b64: key.publicKeyB64 }]);
  });

  it('refuses anything it does not recognise', () => {
    assert.throws(() => cloud('  verify: false\n'), /Unknown cloud key/);
    assert.throws(() => cloud('  fail_open: true\n'), /Unknown cloud key/);
    assert.throws(() => cloud('  token: pp_live_abc\n'), /Unknown cloud key/);
    assert.throws(() => parseConfig(`${BASE}cloud: true\n`), /must be an object/);
    assert.throws(() => cloud('  environment: prod\n'), /cloud.environment/);
    assert.throws(() => cloud('  approval_timeout_seconds: 5\n'), /30 to 3600/);
    assert.throws(() => cloud('  approval_timeout_seconds: 86400\n'), /30 to 3600/);
    assert.throws(() => cloud('  api_url: http://staging.example.test\n'), /must be https/);
    assert.throws(() => cloud('  api_url: https://user:pw@example.test\n'), /must be an origin/);
    assert.throws(() => cloud('  api_url: https://example.test/api\n'), /must be an origin/);
    assert.throws(() => cloud('  api_url: not a url\n'), /must be a URL/);
    const other = '  api_url: https://staging.example.test\n';
    assert.throws(() => cloud(`${other}  trust_keys: []\n`), /non-empty list/);
    assert.throws(() => cloud(`${other}  trust_keys:\n    - { key_id: k, public_key_b64: "c2hvcnQ=" }\n`), /32-byte/);
    assert.throws(() => cloud(`${other}  trust_keys:\n    - { key_id: k, alg: rsa, public_key_b64: "${key.publicKeyB64}" }\n`), /ed25519/);
    assert.throws(() => cloud(`${other}  trust_keys:\n    - { key_id: k, public_key_b64: "${key.publicKeyB64}", status: active }\n`), /unknown key/);
    assert.throws(() => cloud(`${other}  trust_keys:\n    - { key_id: k, public_key_b64: "${key.publicKeyB64}" }\n    - { key_id: k, public_key_b64: "${key.publicKeyB64}" }\n`), /duplicates/);
  });
});

describe('install token', () => {
  const TOKEN = `pp_test_${'a'.repeat(32)}`;
  const dir = mkdtempSync(join(tmpdir(), 'mcp-guard-token-'));
  const file = join(dir, 'install-token');

  it('comes from PP_INSTALL_TOKEN first, then the token file', () => {
    assert.equal(loadInstallToken({ PP_INSTALL_TOKEN: ` ${TOKEN}\n` }, join(dir, 'missing')), TOKEN);
    writeFileSync(file, `${TOKEN}\n`, { mode: 0o600 });
    assert.equal(loadInstallToken({}, file), TOKEN);
  });

  it('missing, malformed or exposed is a typed error, never an anonymous run', () => {
    const code = (fn: () => unknown): string => {
      try { fn(); } catch (err) { assert.ok(err instanceof InstallTokenError); return err.code; }
      return 'no error';
    };
    assert.equal(code(() => loadInstallToken({}, join(dir, 'missing'))), 'INSTALL_TOKEN_MISSING');
    assert.equal(code(() => loadInstallToken({ PP_INSTALL_TOKEN: 'hunter2' }, file)), 'INSTALL_TOKEN_INVALID');
    assert.equal(code(() => loadInstallToken({ PP_INSTALL_TOKEN: 'sk_whatever_0123456789' }, file)), 'INSTALL_TOKEN_INVALID');
    if (process.platform !== 'win32') {
      const open = join(dir, 'open-token');
      writeFileSync(open, TOKEN);
      chmodSync(open, 0o644);
      assert.equal(code(() => loadInstallToken({}, open)), 'INSTALL_TOKEN_EXPOSED');
    }
  });
});
