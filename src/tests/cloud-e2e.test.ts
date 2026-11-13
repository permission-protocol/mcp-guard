import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fingerprintOfCall } from '../cloud/fingerprint.js';
import { pinsFor } from '../cloud/pinned-keys.js';
import { verifyCloudReceipt } from '../cloud/verify.js';
import { startFakePp, type FakePp } from './cloud-helpers.js';

/**
 * End to end: the real CLI wrapping a logging echo server, with a local stand-in for
 * Permission Protocol that signs receipts with a test key the policy pins. A held call
 * reaches the server only after a verified, redeemed, human-signed receipt.
 */

const CLI = join(__dirname, '..', 'cli.js');
const ECHO = join(__dirname, 'fixtures-echo-server.js');
const TOKEN = `pp_test_${'e2e'.repeat(10)}`;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

interface Guard {
  proc: ChildProcess;
  dir: string;
  stderr: () => string;
  call: (id: number, name: string, args: Record<string, unknown>) => void;
  response: (id: number, timeoutMs?: number) => Promise<any>;
  serverLog: () => string[];
  cloudLines: () => any[];
  stop: () => void;
}

function policy(apiUrl: string | null, fake: FakePp | null): string {
  const cloud = apiUrl
    ? `cloud:
  api_url: ${apiUrl}
  environment: staging
  approval_timeout_seconds: 30
  trust_keys:
    - { key_id: ${fake!.issuer.keyId}, public_key_b64: "${fake!.issuer.publicKeyB64}" }
`
    : '';
  return `default_action: block
server_label: filesystem
rules:
  - { id: echo, tool: echo, action: allow }
  - { id: env, tool: env, action: allow }
  - { id: delete, tool: delete_file, action: require_approval, reversibility: irreversible }
  - { id: deploy, tool: deploy, action: require_approval, reversibility: reversible, countdown_seconds: 1 }
${cloud}`;
}

function startGuard(policyText: string, env: Record<string, string | undefined> = {}): Guard {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-guard-cloud-e2e-'));
  writeFileSync(join(dir, 'pp.config.yaml'), policyText);
  const base: NodeJS.ProcessEnv = {
    ...process.env,
    PP_KEYS_DIR: join(dir, 'keys'),
    PP_SHARED_RECEIPTS_PATH: join(dir, 'receipts.jsonl'),
    ECHO_LOG: join(dir, 'server.log'),
    PP_INSTALL_TOKEN: TOKEN,
    ...env,
  };
  for (const [key, value] of Object.entries(env)) if (value === undefined) delete base[key];
  assert.equal(spawnSync('node', [CLI, 'keys', 'init'], { env: base }).status, 0);
  const proc = spawn('node', [CLI, '--config', join(dir, 'pp.config.yaml'), '--agent-id', 'claude-code', '--', 'node', ECHO], { env: base, stdio: ['pipe', 'pipe', 'pipe'] });
  let stderr = '';
  let buffer = '';
  const responses = new Map<unknown, any>();
  proc.stderr!.on('data', (d) => { stderr += d.toString(); });
  proc.stdout!.on('data', (d) => {
    buffer += d.toString();
    let index;
    while ((index = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      try { const m = JSON.parse(line); responses.set(m.id, m); } catch { /* not a response */ }
    }
  });
  return {
    proc,
    dir,
    stderr: () => stderr,
    call: (id, name, args) => { proc.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }) + '\n'); },
    response: async (id, timeoutMs = 15_000) => {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        if (responses.has(id)) return responses.get(id);
        await sleep(50);
      }
      throw new Error(`no response to ${id} in ${timeoutMs} ms. stderr:\n${stderr}`);
    },
    serverLog: () => (existsSync(join(dir, 'server.log')) ? readFileSync(join(dir, 'server.log'), 'utf-8').trim().split('\n').filter(Boolean) : []),
    cloudLines: () => (existsSync(join(dir, 'receipts.jsonl')) ? readFileSync(join(dir, 'receipts.jsonl'), 'utf-8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)).filter((l) => l.cloud).map((l) => l.cloud) : []),
    stop: () => { proc.kill(); },
  };
}

describe('cloud approvals end to end', () => {
  let fake: FakePp;
  let guard: Guard;
  const forwarded = (marker: string) => guard.serverLog().filter((line) => line.includes(marker));

  before(async () => {
    fake = await startFakePp(TOKEN);
    guard = startGuard(policy(fake.url, fake));
    await sleep(600);
  });
  after(async () => {
    guard.stop();
    await fake.close();
  });

  it('starts in cloud mode and names the pinned key', () => {
    assert.match(guard.stderr(), /Cloud approvals on: held calls need a signature at http:\/\/127\.0\.0\.1:\d+ \(pinned keys: pp-test-cloud-k1\)/);
    assert.doesNotMatch(guard.stderr(), /local-only/);
  });

  it('an allowed call is forwarded without asking anyone', async () => {
    guard.call(1, 'echo', { text: 'hello-allowed' });
    assert.equal((await guard.response(1)).result.echoed, 'tools/call');
    assert.equal(fake.calls.length, 0);
  });

  it('a held call is released by a human-signed receipt: verified, redeemed once, forwarded once, logged with the receipt id', async () => {
    fake.decision = 'approve';
    const args = { path: '/srv/approved-marker.csv', recursive: false };
    guard.call(2, 'delete_file', args);
    await sleep(300);
    assert.equal(forwarded('approved-marker').length, 0, 'not forwarded while held');
    assert.match(guard.stderr(), /Held "delete_file" for signature \(mcpreq_\d+\)\. Sign or reject: http:\/\/127\.0\.0\.1:\d+\/sign\/mcpreq_\d+/);

    const response = await guard.response(2);
    assert.equal(response.result.echoed, 'tools/call');
    assert.deepEqual(response.result.params.arguments, args);
    assert.equal(forwarded('approved-marker').length, 1);

    const create = fake.calls.find((c) => c.method === 'POST' && c.path === '/api/mcp/approval-requests')!;
    assert.equal(create.authorization, `Bearer ${TOKEN}`);
    assert.deepEqual(Object.keys(create.body).sort(), ['agentId', 'argsHash', 'argsPreview', 'env', 'server', 'timeoutSec', 'tool']);
    assert.deepEqual({ tool: create.body.tool, server: create.body.server, agentId: create.body.agentId, env: create.body.env, timeoutSec: create.body.timeoutSec }, { tool: 'delete_file', server: 'filesystem', agentId: 'claude-code', env: 'staging', timeoutSec: 30 });
    assert.equal(fake.redeemed.length, 1);

    const [line] = guard.cloudLines();
    assert.equal(line.decision, 'released');
    assert.match(line.receiptId, /^rcpt_fake_/);
    assert.match(line.receiptUrl, /\/r\/rcpt_fake_/);
    assert.equal(line.fingerprint, fingerprintOfCall('filesystem', 'delete_file', args));
    assert.deepEqual(line.decider, { id: 'user:u_maria', display: 'Maria Signer', authMethod: 'session_stepup_webauthn' });
    assert.deepEqual({ tool: line.tool, server: line.server, agentId: line.agentId, ruleId: line.ruleId }, { tool: 'delete_file', server: 'filesystem', agentId: 'claude-code', ruleId: 'delete' });
    // The logged artifact is the signed receipt: it re-verifies offline, against the same pin, for this call.
    const again = verifyCloudReceipt(line.artifact, { keySet: fake.issuer.keySet, trust: pinsFor(fake.issuer.keySet), fingerprint: line.fingerprint, requestId: line.requestId, expect: 'APPROVED' });
    assert.equal(again.ok, true);
    // The log holds no argument values.
    assert.doesNotMatch(readFileSync(join(guard.dir, 'receipts.jsonl'), 'utf-8'), /approved-marker/);
    assert.match(guard.stderr(), /cloud RELEASED "delete_file" by Maria Signer: receipt rcpt_fake_/);
  });

  it('a rejection blocks with the signed DENIED receipt recorded', async () => {
    fake.decision = 'reject';
    guard.call(3, 'delete_file', { path: '/srv/rejected-marker.csv' });
    const response = await guard.response(3);
    assert.equal(response.error.code, -32003);
    assert.match(response.error.message, /Denied: Approval was denied/);
    assert.equal(forwarded('rejected-marker').length, 0);
    const line = guard.cloudLines().at(-1);
    assert.equal(line.decision, 'denied');
    assert.match(line.receiptId, /^rcpt_fake_/);
    assert.equal(line.decider.id, 'user:u_maria');
  });

  it('a frozen workspace blocks at once with a signed DENIED', async () => {
    fake.decision = 'frozen';
    const before = fake.calls.length;
    guard.call(4, 'delete_file', { path: '/srv/frozen-marker.csv' });
    const response = await guard.response(4);
    assert.equal(response.error.code, -32003);
    assert.match(response.error.message, /Global freeze is active/);
    assert.equal(forwarded('frozen-marker').length, 0);
    assert.equal(fake.calls.length - before, 1, 'one create, no polling, no redeem');
    const line = guard.cloudLines().at(-1);
    assert.equal(line.decision, 'denied');
    assert.equal(line.decider.id, 'system/pp-engine');
  });

  it('a tampered receipt blocks and is never redeemed', async () => {
    fake.decision = 'tampered';
    const redeemedBefore = fake.redeemed.length;
    guard.call(5, 'delete_file', { path: '/srv/tampered-marker.csv' });
    const response = await guard.response(5);
    assert.equal(response.error.code, -32005);
    assert.match(response.error.message, /receipt was refused/);
    assert.equal(forwarded('tampered-marker').length, 0);
    assert.equal(fake.redeemed.length, redeemedBefore);
    const line = guard.cloudLines().at(-1);
    assert.deepEqual({ decision: line.decision, code: line.code, receiptId: line.receiptId }, { decision: 'blocked', code: 'RECEIPT_SIGNATURE_INVALID', receiptId: null });
  });

  it('a real signature over another call does not release this one', async () => {
    fake.decision = 'wrong-fingerprint';
    const redeemedBefore = fake.redeemed.length;
    guard.call(6, 'delete_file', { path: '/srv/swapped-marker.csv' });
    const response = await guard.response(6);
    assert.equal(response.error.code, -32005);
    assert.equal(forwarded('swapped-marker').length, 0);
    assert.equal(fake.redeemed.length, redeemedBefore);
    assert.equal(guard.cloudLines().at(-1).code, 'RECEIPT_FINGERPRINT_MISMATCH');
  });

  it('"approved" with no receipt does not release', async () => {
    fake.decision = 'unsigned-approve';
    guard.call(7, 'delete_file', { path: '/srv/unsigned-marker.csv' });
    const response = await guard.response(7);
    assert.equal(response.error.code, -32005);
    assert.equal(forwarded('unsigned-marker').length, 0);
    assert.equal(guard.cloudLines().at(-1).code, 'RECEIPT_MALFORMED');
  });

  it('a reversible rule with a countdown still needs the signature: nothing auto-releases', async () => {
    fake.decision = 'reject';
    guard.call(8, 'deploy', { env: 'countdown-marker' });
    await sleep(1500);
    const response = await guard.response(8);
    assert.equal(response.error.code, -32003);
    assert.equal(forwarded('countdown-marker').length, 0);
  });

  it('the wrapped server never sees the install token', async () => {
    guard.call(9, 'env', {});
    const keys: string[] = (await guard.response(9)).result.env;
    assert.equal(keys.some((key) => key.startsWith('PP_')), false);
  });
});

describe('cloud approvals fail closed', () => {
  it('API down: the held call is blocked, not forwarded', async () => {
    const fake = await startFakePp(TOKEN);
    const text = policy(fake.url, fake);
    await fake.close(); // nothing listens on that port any more
    const guard = startGuard(text);
    try {
      await sleep(600);
      guard.call(1, 'delete_file', { path: '/srv/down-marker.csv' });
      const response = await guard.response(1, 20_000);
      assert.equal(response.error.code, -32007);
      assert.match(response.error.message, /Blocked: Permission Protocol is unreachable/);
      assert.equal(guard.serverLog().filter((l) => l.includes('down-marker')).length, 0);
      const [line] = guard.cloudLines();
      assert.deepEqual({ decision: line.decision, code: line.code, receiptId: line.receiptId }, { decision: 'blocked', code: 'API_UNREACHABLE', receiptId: null });
      // The guard is still up and still enforcing.
      guard.call(2, 'echo', { text: 'still-here' });
      assert.equal((await guard.response(2)).result.echoed, 'tools/call');
    } finally {
      guard.stop();
    }
  });

  it('a revoked or wrong token: blocked', async () => {
    const fake = await startFakePp(`pp_test_${'other'.repeat(6)}`);
    const guard = startGuard(policy(fake.url, fake));
    try {
      await sleep(600);
      guard.call(1, 'delete_file', { path: '/srv/badtoken-marker.csv' });
      const response = await guard.response(1);
      assert.equal(response.error.code, -32007);
      assert.equal(guard.serverLog().filter((l) => l.includes('badtoken-marker')).length, 0);
      assert.equal(guard.cloudLines()[0].code, 'API_401_UNAUTHORIZED');
    } finally {
      guard.stop();
      await fake.close();
    }
  });

  it('no install token: enforce mode refuses to start', async () => {
    const fake = await startFakePp(TOKEN);
    // No variable, no keychain, and a config directory with no token file.
    const guard = startGuard(policy(fake.url, fake), { PP_INSTALL_TOKEN: undefined, XDG_CONFIG_HOME: undefined, MCP_GUARD_TOKEN_STORE: 'file' });
    try {
      const code = await new Promise<number | null>((resolve) => {
        guard.proc.on('exit', resolve);
        setTimeout(() => resolve(-1), 5_000);
      });
      assert.equal(code, 1);
      assert.match(guard.stderr(), /no install token: run `mcp-guard init`, or set PP_INSTALL_TOKEN/);
      assert.equal(guard.serverLog().length, 0);
    } finally {
      guard.stop();
      await fake.close();
    }
  });

  it('no environment variable turns verification off', async () => {
    const fake = await startFakePp(TOKEN);
    fake.decision = 'tampered';
    const guard = startGuard(policy(fake.url, fake), {
      PP_CLOUD_VERIFY: 'off', PP_SKIP_VERIFY: '1', PP_FAIL_OPEN: 'true', PP_INSECURE: '1', MCP_GUARD_FAIL_OPEN: '1', NODE_ENV: 'development',
    });
    try {
      await sleep(600);
      guard.call(1, 'delete_file', { path: '/srv/override-marker.csv' });
      assert.equal((await guard.response(1)).error.code, -32005);
      assert.equal(guard.serverLog().filter((l) => l.includes('override-marker')).length, 0);
    } finally {
      guard.stop();
      await fake.close();
    }
  });
});

describe('local-only mode is unchanged and says it is unsigned', () => {
  it('labels startup and the held answer', async () => {
    const guard = startGuard(policy(null, null));
    try {
      await sleep(600);
      assert.match(guard.stderr(), /Mode: local-only, unsigned by Permission Protocol/);
      guard.call(1, 'delete_file', { path: '/srv/local-marker.csv' });
      const response = await guard.response(1);
      assert.equal(response.error.code, -32002);
      assert.match(response.error.message, /^Held for approval \(local-only, unsigned by Permission Protocol\): Matched rule "delete"/);
      assert.equal(guard.serverLog().filter((l) => l.includes('local-marker')).length, 0);
      assert.equal(guard.cloudLines().length, 0);
    } finally {
      guard.stop();
    }
  });
});
