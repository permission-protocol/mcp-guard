import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { argsPreviewOf, capUtf8, maskText, MASK, MAX_PREVIEW_BYTES, CUT_MARK } from '../cloud/preview.js';
import { argsHashOf, fingerprintOfCall } from '../cloud/fingerprint.js';
import { createCloudClient } from '../cloud/client.js';
import { decideInCloud } from '../cloud/hold.js';
import { pinsFor } from '../cloud/pinned-keys.js';
import { parseConfig } from '../config.js';
import { ReplayCache } from '../verify-core.js';
import { startFakePp, type FakePp } from './cloud-helpers.js';

/**
 * What a held call sends: the argument hash, and a preview the guard masks and caps
 * before upload. Sentinels below look like credentials and must never reach the
 * stand-in Permission Protocol; the hash and fingerprint are those of the exact call.
 */

// Visibly fake, secret-shaped values. Built at run time so no line reads as a credential assignment.
const fake = (prefix: string, body: string) => `${prefix}${body}`;
const GH = fake('ghp_', 'FAKEFAKEFAKEsentinelGH000000000000000000');
const SK = fake('sk-', 'FAKEsentinelOPENAI00000000000');
const AWS = fake('AKIA', 'FAKESENTINEL0000');
const PW = 'Sentinel-pw-not-real';
const BEARER = 'sentinelBearerValue.not.real';
const SECRETS = [GH, SK, AWS, PW, BEARER, 'sentinel-url-pass', 'SENTINELPEMBODY'];

const noSecret = (text: string): void => {
  for (const s of SECRETS) assert.equal(text.includes(s), false, `leaked ${s} in ${text}`);
};

describe('preview masking', () => {
  it('masks the formats a signer never needs to read', () => {
    const cases: Array<[string, string]> = [
      [`curl -H "Authorization: Bearer ${BEARER}" https://api.test`, 'https://api.test'],
      [`git push https://bot:sentinel-url-pass@github.com/acme/app.git main`, 'github.com/acme/app.git main'],
      [`export GITHUB_TOKEN=${GH}`, 'export GITHUB_TOKEN='],
      [`OPENAI_API_KEY=${SK} node run.js`, 'node run.js'],
      [`aws_access_key_id = ${AWS}`, 'aws_access_key_id'],
      [`psql "host=db password=${PW} dbname=app" -c "DROP TABLE users"`, 'DROP TABLE users'],
      [`mysqladmin --password ${PW} drop app`, 'drop app'],
      [`DATABASE_PASSWORD="${PW}"\nLOG_LEVEL=debug`, 'LOG_LEVEL=debug'],
      ['-----BEGIN OPENSSH PRIVATE KEY-----\nSENTINELPEMBODY\n-----END OPENSSH PRIVATE KEY-----\nrest', 'rest'],
      ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZW50aW5lbCJ9.c2lnbmF0dXJl', ''],
    ];
    for (const [input, kept] of cases) {
      const out = maskText(input);
      noSecret(out);
      assert.ok(out.includes(MASK), out);
      assert.ok(out.includes(kept), `${kept} kept in ${out}`);
    }
    assert.equal(maskText('rm -rf /srv/data'), 'rm -rf /srv/data');
    assert.equal(maskText('terraform destroy -auto-approve'), 'terraform destroy -auto-approve');
  });

  it('masks values under credential-like keys, at any depth', () => {
    const out = argsPreviewOf({ path: '/srv/x', options: { headers: { 'X-Api-Key': 'short1', Cookie: 'c=1' }, auth: { password: 'p' } }, token: 42 });
    assert.deepEqual(JSON.parse(out), { path: '/srv/x', token: MASK, options: { auth: MASK, headers: { Cookie: MASK, 'X-Api-Key': MASK } } });
  });

  it('orders short fields first, so the cap cuts content and keeps the path and command', () => {
    const content = 'A'.repeat(10) + ' line\n'.repeat(5000);
    const write = argsPreviewOf({ content, file_path: '/srv/app/config/production.yaml' });
    assert.ok(write.startsWith('{"file_path":"/srv/app/config/production.yaml","content":"'), write.slice(0, 80));
    assert.ok(Buffer.byteLength(write, 'utf8') <= MAX_PREVIEW_BYTES);
    assert.ok(write.endsWith(CUT_MARK));
    const edit = argsPreviewOf({ old_string: 'x '.repeat(3000), new_string: 'y '.repeat(3000), file_path: 'C:\\repo\\src\\db.ts', replace_all: false });
    assert.ok(edit.startsWith('{"replace_all":false,"file_path":"C:\\\\repo\\\\src\\\\db.ts","old_string":'), edit.slice(0, 90));
    const bash = argsPreviewOf({ description: 'clean up '.repeat(500), command: 'rm -rf ~/build' });
    assert.ok(bash.startsWith('{"command":"rm -rf ~/build"'), bash.slice(0, 60));
  });

  it('caps at 2,048 bytes of UTF-8 on a character boundary', () => {
    assert.equal(MAX_PREVIEW_BYTES, 2048);
    const out = capUtf8('é😀'.repeat(2000));
    assert.ok(Buffer.byteLength(out, 'utf8') <= 2048);
    assert.equal(out.includes('\uFFFD'), false);
    assert.equal(Buffer.from(out, 'utf8').toString('utf8'), out, 'no broken surrogate pair');
    assert.equal(capUtf8('short'), 'short');
  });

  it('never throws on what JSON cannot hold', () => {
    const cyclic: any = { a: 1 };
    cyclic.self = cyclic;
    assert.match(argsPreviewOf(cyclic), /"self":"\[masked\]"/);
    assert.match(argsPreviewOf({ n: 10n }), /"n":"\[masked\]"/);
    assert.equal(argsPreviewOf(undefined), '{}');
  });
});

describe('cloud.args_preview', () => {
  it('loads true or false through the strict loader; anything else is refused', () => {
    const base = 'default_action: allow\nrules: []\ncloud:\n  environment: staging\n';
    assert.equal(parseConfig(`${base}  args_preview: false\n`).cloud?.args_preview, false);
    assert.equal(parseConfig(`${base}  args_preview: true\n`).cloud?.args_preview, undefined);
    assert.equal(parseConfig(base).cloud?.args_preview, undefined);
    assert.throws(() => parseConfig(`${base}  args_preview: "no"\n`), /cloud\.args_preview: must be true or false/);
  });
});

describe('what a held call sends: the stand-in Permission Protocol receives no secret', () => {
  const TOKEN = `pp_test_${'prev'.repeat(8)}`;
  const CLI = join(__dirname, '..', 'cli.js');
  let pp: FakePp;
  before(async () => { pp = await startFakePp(TOKEN); pp.decision = 'reject'; });
  after(async () => { await pp.close(); });

  const creates = () => pp.calls.filter((c) => c.method === 'POST' && c.path === '/api/mcp/approval-requests');

  function workspace(extra = ''): string {
    const dir = mkdtempSync(join(tmpdir(), 'mcp-guard-preview-'));
    writeFileSync(join(dir, 'pp.config.yaml'), `default_action: require_approval
rules: []
cloud:
  api_url: ${pp.url}
  environment: staging
  approval_timeout_seconds: 60
  trust_keys:
    - { key_id: ${pp.issuer.keyId}, public_key_b64: "${pp.issuer.publicKeyB64}" }
${extra}`);
    assert.equal(spawnSync('node', [CLI, 'keys', 'init'], { env: { ...process.env, PP_KEYS_DIR: join(dir, 'keys') } }).status, 0);
    return dir;
  }

  function hook(dir: string, tool: string, input: Record<string, unknown>): Promise<number | null> {
    const env = { ...process.env, PP_KEYS_DIR: join(dir, 'keys'), PP_SHARED_RECEIPTS_PATH: join(dir, 'r.jsonl'), PP_INSTALL_TOKEN: TOKEN, MCP_GUARD_TOKEN_STORE: 'file', MCP_GUARD_HEARTBEAT: 'off' };
    return new Promise((resolve) => {
      const p = spawn('node', [CLI, 'hook', '--config', join(dir, 'pp.config.yaml'), '--wait', '5'], { env, cwd: dir, stdio: ['pipe', 'ignore', 'ignore'] });
      p.on('close', resolve);
      p.stdin.end(JSON.stringify({ session_id: 's', cwd: dir, permission_mode: 'default', hook_event_name: 'PreToolUse', tool_name: tool, tool_input: input, tool_use_id: 't' }));
    });
  }

  it('a held Bash command: masked command, exact hash', async () => {
    const dir = workspace();
    const input = { command: `GITHUB_TOKEN=${GH} curl -H "Authorization: Bearer ${BEARER}" https://bot:sentinel-url-pass@api.test/x && rm -rf ~/build`, description: 'cleanup' };
    assert.equal(await hook(dir, 'Bash', input), 2);
    const body = creates().at(-1)!.body;
    noSecret(JSON.stringify(body));
    assert.ok(body.argsPreview.includes('rm -rf ~/build'));
    // The hook signs the command (not the model's description): the hash is of that exact text, secrets included.
    assert.equal(body.argsHash, argsHashOf({ command: input.command }));
  });

  it('a held Write: masked file content, and the path survives the cap', async () => {
    const dir = workspace();
    const content = `# generated\nAWS_ACCESS_KEY_ID=${AWS}\nDB_PASSWORD=${PW}\nOPENAI_API_KEY=${SK}\n` + '# filler\n'.repeat(4000) + `-----BEGIN RSA PRIVATE KEY-----\nSENTINELPEMBODY\n-----END RSA PRIVATE KEY-----\n`;
    const input = { file_path: '/srv/app/.env.production', content };
    assert.equal(await hook(dir, 'Write', input), 2);
    const body = creates().at(-1)!.body;
    noSecret(JSON.stringify(body));
    assert.ok(body.argsPreview.startsWith('{"file_path":"/srv/app/.env.production"'), body.argsPreview.slice(0, 60));
    assert.ok(Buffer.byteLength(body.argsPreview, 'utf8') <= MAX_PREVIEW_BYTES);
    assert.equal(body.argsHash, argsHashOf(input));
  });

  it('a nested argument (MCP proxy path): masked; fingerprint unchanged', async () => {
    const args = { query: 'DELETE FROM sessions', connection: { host: 'db.internal', options: { auth: { user: 'svc', secret: PW } }, url: `postgres://svc:sentinel-url-pass@db.internal/app`, headers: [`x-api-key: ${SK}`] } };
    const before = creates().length;
    const outcome = await decideInCloud({
      client: createCloudClient({ apiUrl: pp.url, token: TOKEN }), keySet: pp.issuer.keySet, trust: pinsFor(pp.issuer.keySet), replayCache: new ReplayCache(),
      server: 'db', tool: 'run_sql', args, agentId: 'cursor', environment: 'staging', timeoutSeconds: 30, sleep: async () => undefined,
    });
    assert.equal(outcome.kind, 'denied');
    assert.equal(outcome.fingerprint, fingerprintOfCall('db', 'run_sql', args));
    assert.equal(creates().length, before + 1);
    const body = creates().at(-1)!.body;
    noSecret(JSON.stringify(body));
    assert.match(body.argsPreview, /DELETE FROM sessions/);
    assert.match(body.argsPreview, /db\.internal/);
    assert.deepEqual(Object.keys(body).sort(), ['agentId', 'argsHash', 'argsPreview', 'env', 'server', 'timeoutSec', 'tool']);
  });

  it('cloud.args_preview: false sends the hash only', async () => {
    const dir = workspace('  args_preview: false\n');
    const input = { command: 'rm -rf ~/build' };
    assert.equal(await hook(dir, 'Bash', input), 2);
    const body = creates().at(-1)!.body;
    assert.equal('argsPreview' in body, false);
    assert.equal(body.argsHash, argsHashOf(input));
    assert.deepEqual(Object.keys(body).sort(), ['agentId', 'argsHash', 'env', 'server', 'timeoutSec', 'tool']);
  });
});
