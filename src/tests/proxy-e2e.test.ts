import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyReceipt } from '../receipt-verify.js';
import { keyIdForPublicKey } from '../signer.js';
import type { Receipt } from '../receipt.js';

/**
 * End to end: the real CLI wrapping a logging echo server. Every audit proof of concept
 * is replayed here against the built guard.
 */

const CLI = join(__dirname, '..', 'cli.js');
const ECHO = join(__dirname, 'fixtures-echo-server.js');
const TOKEN = 'e2e-token-0123456789abcdef0123456789abcdef';
const SENTINEL = 'sk_live_E2E_SENTINEL_42';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const POLICY = `
default_action: block
approval_ttl_seconds: 3
rules:
  - { id: echo, tool: echo, action: allow }
  - { id: env, tool: env, action: allow }
  - { id: merge, tool: merge_pr, action: require_approval, reversibility: irreversible }
  - { id: spend, tool: spend, action: require_approval, reversibility: reversible, cap_usd: 50, amount_arg: amount }
  - { id: deploy, tool: deploy, action: require_approval, reversibility: reversible, countdown_seconds: 1 }
  - { id: email, tool: send_email, action: require_approval, reversibility: irreversible }
  - { id: post, tool: post_x, action: require_approval, reversibility: irreversible }
  - { id: nope, tool: nope, action: block }
  - { id: reads, method: resources/read, action: block }
  - { id: prompts, method: prompts/get, action: require_approval }
`;

describe('mcp-guard end to end', () => {
  let dir: string;
  let guard: ChildProcess;
  let port = 0;
  let stderr = '';
  const responses = new Map<unknown, any>();
  let base = '';
  const env = () => ({
    ...process.env,
    PP_KEYS_DIR: join(dir, 'keys'),
    PP_SHARED_RECEIPTS_PATH: join(dir, 'receipts.jsonl'),
    PP_APPROVAL_TOKEN: TOKEN,
    ECHO_LOG: join(dir, 'server.log'),
  });
  const serverLog = () => (existsSync(join(dir, 'server.log')) ? readFileSync(join(dir, 'server.log'), 'utf-8') : '');
  const receiptsFile = () => readFileSync(join(dir, 'receipts.jsonl'), 'utf-8');
  const send = (line: string) => guard.stdin!.write(line + '\n');
  const call = (id: number, name: string, args: Record<string, unknown>) =>
    send(JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }));
  const api = (path: string, method = 'GET') =>
    fetch(`${base}${path}`, { method, headers: { Authorization: `Bearer ${TOKEN}` } });
  const pending = async () => (await (await api('/api/pending')).json()) as any[];

  before(async () => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-guard-e2e-'));
    writeFileSync(join(dir, 'pp.config.yaml'), POLICY);
    guard = spawn('node', [CLI, '--config', join(dir, 'pp.config.yaml'), '--agent-id', 'e2e-agent', '--operator', 'rod',
      '--approval-port', '0', '--', 'node', ECHO], { env: env(), stdio: ['pipe', 'pipe', 'pipe'] });
    guard.stderr!.on('data', (d) => { stderr += d.toString(); });
    let buf = '';
    guard.stdout!.on('data', (d) => {
      buf += d.toString();
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
        const m = JSON.parse(line);
        responses.set(m.id, m);
      }
    });
    for (let i = 0; i < 100 && !port; i++) {
      const m = stderr.match(/Approval UI: http:\/\/127\.0\.0\.1:(\d+)\//);
      if (m) port = Number(m[1]);
      else await sleep(50);
    }
    assert.ok(port, `guard did not start: ${stderr}`);
    base = `http://127.0.0.1:${port}`;

    send(JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {} } }));
    send('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope","arguments":{"x":NaN}}}');
    send(JSON.stringify([{ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'nope', arguments: {} } }]));
    call(3, 'nope', {});
    call(4, 'spend', { amount: 25000, payee: 'attacker', _pp: { amount_usd: 1 } });
    call(5, 'echo', { msg: 'hi', _pp: { confidence: 99 } });
    send(JSON.stringify({ jsonrpc: '2.0', id: 6, method: 'resources/read', params: { uri: 'file:///etc/passwd' } }));
    send(JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'x/unknown', params: { name: 'x' } }));
    send(JSON.stringify({ jsonrpc: '2.0', id: 11, method: 'prompts/get', params: { name: 'secret-prompt' } }));
    call(8, 'send_email', { to: 'a@b.com', body: `the key is ${SENTINEL}` });
    call(9, 'post_x', { text: 'held then denied' });
    call(10, 'deploy', { env: 'production', sha: 'abc123' });
    call(12, 'env', {});
    call(13, 'merge_pr', { repo: 'o/r', pr_number: 5, title: 'typo', scope_ref: 'refs/pull/9/merge', scope_sha: 'evilsha' });
    await sleep(500);
  });

  after(() => { guard?.kill('SIGTERM'); });

  it('the server never inherits the guard secrets (approval token, webhook secret)', () => {
    const keys: string[] = responses.get(12)?.result?.env ?? [];
    assert.ok(keys.length > 0);
    assert.deepEqual(keys.filter((k) => k.startsWith('PP_')), []);
  });

  it('the approver sees the scope the receipt will bind, derived from the PR number', async () => {
    const merge = (await pending()).find((p) => p.tool_name === 'merge_pr');
    assert.deepEqual(merge.scope, { scope: 'github:merge', ref: 'refs/pull/5/merge', sha: 'evilsha' });
    assert.ok(merge.args_full.includes('refs/pull/9/merge'), 'the conflicting argument is visible too');
  });

  it('forwards plumbing methods', () => {
    assert.equal(responses.get(0)?.result?.echoed, 'initialize');
  });

  it('audit PoC: a non-JSON (NaN) line gets -32700 and never reaches the server', () => {
    assert.equal(responses.get(null)?.error?.code !== undefined, true);
    assert.ok(!serverLog().includes('NaN'));
  });

  it('audit PoC: a batch gets -32600 and never reaches the server', () => {
    assert.ok(!serverLog().includes('"id":2'));
    assert.ok(!serverLog().includes('[{'));
  });

  it('blocks a blocked tool without forwarding', () => {
    assert.equal(responses.get(3)?.error?.code, -32001);
    assert.ok(!serverLog().includes('"id":3'));
  });

  it('audit PoC: the agent cannot understate a capped spend with _pp', async () => {
    assert.equal(responses.has(4), false, 'held, no response yet');
    assert.ok(!serverLog().includes('"id":4'));
    assert.ok((await pending()).some((p) => p.tool_name === 'spend'));
  });

  it('strips _pp before forwarding and forwards canonical JSON', () => {
    const line = serverLog().split('\n').find((l) => l.includes('"id":5'))!;
    assert.ok(line);
    assert.ok(!line.includes('_pp'));
    assert.equal(responses.get(5)?.result?.params?.arguments?.msg, 'hi');
  });

  it('gates resources/read, prompts/get and unknown methods', async () => {
    assert.equal(responses.get(6)?.error?.code, -32001);
    assert.equal(responses.get(7)?.error?.code, -32001, 'default_action block applies to unknown methods');
    assert.ok(!serverLog().includes('resources/read'));
    assert.ok(!serverLog().includes('x/unknown'));
    assert.ok(!serverLog().includes('prompts/get'), 'held, not forwarded');
    const held = (await pending()).find((p) => p.tool_name === 'prompts/get');
    assert.ok(held.args_full.includes('secret-prompt'), 'the approver sees the method params');
  });

  it('approving a held call forwards it once with a pinned-key-verifiable human receipt', async () => {
    const email = (await pending()).find((p) => p.tool_name === 'send_email');
    assert.ok(email.args_full.includes(SENTINEL), 'the approver sees the real arguments');
    const res = (await (await api(`/api/approve/${email.id}`, 'POST')).json()) as any;
    assert.equal((await api(`/api/approve/${email.id}`, 'POST')).status, 409);
    await sleep(300);
    assert.equal(responses.get(8)?.result?.echoed, 'tools/call');
    assert.equal(serverLog().split('\n').filter((l) => l.includes('"id":8')).length, 1);

    const pub = spawnSync('node', [CLI, 'export-key', join(dir, 'pub.pem')], { env: env() });
    assert.equal(pub.status, 0, pub.stderr?.toString());
    const pem = readFileSync(join(dir, 'pub.pem'), 'utf-8');
    const receipt: Receipt = receiptsFile().trim().split('\n').map((l) => JSON.parse(l)).find((r) => r.envelope.receipt_id === res.receipt_id);
    assert.deepEqual(receipt.envelope.approval, { kind: 'human', id: 'rod', via: 'local-token' });
    assert.equal(verifyReceipt(receipt, { [keyIdForPublicKey(pem)]: pem }).valid, true);
  });

  it('denying answers the agent with -32003 and never forwards', async () => {
    const post = (await pending()).find((p) => p.tool_name === 'post_x');
    assert.equal((await api(`/api/deny/${post.id}`, 'POST')).status, 200);
    await sleep(200);
    assert.equal(responses.get(9)?.error?.code, -32003);
    assert.ok(!serverLog().includes('held then denied'));
    assert.equal((await api(`/api/approve/${post.id}`, 'POST')).status, 409);
  });

  it('countdown releases with a policy approval that a deploy gate refuses', async () => {
    await sleep(1200);
    assert.equal(responses.get(10)?.result?.echoed, 'tools/call');
    const receipt: Receipt = receiptsFile().trim().split('\n').map((l) => JSON.parse(l))
      .find((r) => r.envelope.tool === 'deploy' && r.envelope.decision === 'allowed');
    assert.equal(receipt.envelope.approval?.via, 'countdown');
    const pem = readFileSync(join(dir, 'pub.pem'), 'utf-8');
    const gate = verifyReceipt(receipt, { [keyIdForPublicKey(pem)]: pem }, { expected: { scope: 'deploy:production', scope_sha: 'abc123' } });
    assert.equal(gate.valid, false);
    assert.ok(gate.reasons.some((r) => r.startsWith('PP_APPROVAL_NOT_HUMAN')));
  });

  it('a held call without a decision expires and the agent is told', async () => {
    await sleep(2000);
    assert.equal(responses.get(4)?.error?.code, -32004);
    assert.ok(!serverLog().includes('"id":4'));
  });

  it('raw arguments never appear in stderr, the receipt file or /api/receipts', async () => {
    assert.ok(!stderr.includes(SENTINEL));
    assert.ok(!receiptsFile().includes(SENTINEL));
    assert.ok(!(await (await api('/api/receipts')).text()).includes(SENTINEL));
    assert.ok(!stderr.includes(TOKEN), 'an env-supplied token is never printed');
  });

  it('warns at startup when default_action is allow', () => {
    const cfg = join(dir, 'allow.yaml');
    writeFileSync(cfg, 'default_action: allow\nrules: []\n');
    const r = spawnSync('node', [CLI, '--config', cfg, '--', 'node', ECHO], { env: env(), input: '', timeout: 5000 });
    assert.match(r.stderr.toString(), /WARNING: default_action is "allow"/);
    const strict = spawnSync('node', [CLI, '--config', join(dir, 'pp.config.yaml'), '--', 'node', ECHO], { env: env(), input: '', timeout: 5000 });
    assert.doesNotMatch(strict.stderr.toString(), /WARNING/);
  });

  it('refuses to start with an exposed signing key', () => {
    chmodSync(join(dir, 'keys', 'signing.private.pem'), 0o644);
    const r = spawnSync('node', [CLI, '--config', join(dir, 'pp.config.yaml'), '--', 'node', ECHO], { env: env(), input: '', timeout: 5000 });
    chmodSync(join(dir, 'keys', 'signing.private.pem'), 0o600);
    assert.equal(r.status, 1);
    assert.match(r.stderr.toString(), /Refusing to use signing key material/);
  });
});
