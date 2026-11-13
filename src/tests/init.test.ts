import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseConfig } from '../config.js';
import { awaitLogin, DeviceLoginError, startLogin } from '../cloud/device-login.js';
import { PRODUCTION_API_URL } from '../cloud/pinned-keys.js';
import { InstallTokenError, KEYCHAIN_ACCOUNT, KEYCHAIN_SERVICE, loadInstallToken, saveInstallToken, type KeychainRunner } from '../cloud/token.js';
import { policyText } from '../init/init.js';
import { findServers, isWrapped, wrapServer, wrappedCommand } from '../init/mcp-clients.js';
import { startFakePp, type FakePp } from './cloud-helpers.js';
import { settingsPath } from '../hook/install.js';

const CLI = join(__dirname, '..', 'cli.js');
const ECHO = join(__dirname, 'fixtures-echo-server.js');
const TOKEN = `pp_test_${'init'.repeat(8)}`;
const temp = (name: string) => mkdtempSync(join(tmpdir(), `mcp-guard-${name}-`));

// ---------------------------------------------------------------------------
// Where the token is kept
// ---------------------------------------------------------------------------

describe('install token storage', () => {
  /** A keychain that works like `security` / `secret-tool`: records what it was given and where. */
  function fakeKeychain(platform: 'darwin' | 'linux') {
    const seen: Array<{ command: string; args: string[]; input?: string }> = [];
    let stored: string | null = null;
    const run: KeychainRunner = (command, args, input) => {
      seen.push({ command, args, input });
      if (platform === 'darwin' && command === 'security') {
        if (args[0] === '-i') { stored = /-w (\S+)/.exec(input ?? '')?.[1] ?? null; return { status: 0, stdout: '' }; }
        if (args[0] === 'find-generic-password') return stored ? { status: 0, stdout: `${stored}\n` } : { status: 44, stdout: '' };
      }
      if (platform === 'linux' && command === 'secret-tool') {
        if (args[0] === 'store') { stored = input ?? null; return { status: 0, stdout: '' }; }
        if (args[0] === 'lookup') return stored ? { status: 0, stdout: stored } : { status: 1, stdout: '' };
      }
      return { status: null, stdout: '' };
    };
    return { run, seen, platform, env: {} as NodeJS.ProcessEnv };
  }

  for (const platform of ['darwin', 'linux'] as const) {
    it(`${platform}: goes to the OS keychain, and the token is never a command-line argument`, () => {
      const keychain = fakeKeychain(platform);
      const dir = temp('token');
      const file = join(dir, 'install-token');
      assert.deepEqual(saveInstallToken(TOKEN, { ...keychain, path: file }), { kind: 'keychain' });
      assert.equal(existsSync(file), false);
      for (const call of keychain.seen) assert.equal(call.args.join(' ').includes(TOKEN), false, `${call.command} ${call.args[0]} got the token as an argument`);
      assert.ok(keychain.seen.some((call) => call.args.includes(KEYCHAIN_SERVICE) || (call.input ?? '').includes(KEYCHAIN_SERVICE)));
      assert.ok(keychain.seen.some((call) => call.args.includes(KEYCHAIN_ACCOUNT) || (call.input ?? '').includes(KEYCHAIN_ACCOUNT)));
      // The guard finds it there at startup, with no variable and no file.
      assert.equal(loadInstallToken({}, file, keychain), TOKEN);
    });
  }

  it('no keychain (Windows, or the helper is missing): a file only the owner can read', () => {
    const dir = temp('token');
    const file = join(dir, 'nested', 'install-token');
    const unavailable: KeychainRunner = () => ({ status: null, stdout: '' });
    for (const platform of ['win32', 'linux', 'darwin'] as const) {
      assert.deepEqual(saveInstallToken(TOKEN, { platform, run: unavailable, env: {}, path: file }), { kind: 'file', path: file });
    }
    assert.equal(readFileSync(file, 'utf-8'), `${TOKEN}\n`);
    if (process.platform !== 'win32') assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.equal(loadInstallToken({}, file, { platform: 'win32', run: unavailable }), TOKEN);
  });

  it('a keychain that did not keep the token falls back to the file', () => {
    const file = join(temp('token'), 'install-token');
    const forgetful: KeychainRunner = (_command, args) => (args[0] === 'store' ? { status: 0, stdout: '' } : { status: 1, stdout: '' });
    assert.deepEqual(saveInstallToken(TOKEN, { platform: 'linux', run: forgetful, env: {}, path: file }), { kind: 'file', path: file });
  });

  it('MCP_GUARD_TOKEN_STORE=file keeps it out of the keychain; PP_INSTALL_TOKEN wins over both', () => {
    const keychain = fakeKeychain('darwin');
    const file = join(temp('token'), 'install-token');
    const env = { MCP_GUARD_TOKEN_STORE: 'file' };
    assert.deepEqual(saveInstallToken(TOKEN, { ...keychain, env, path: file }), { kind: 'file', path: file });
    assert.equal(keychain.seen.length, 0);
    const other = `pp_test_${'x'.repeat(32)}`;
    assert.equal(loadInstallToken({ PP_INSTALL_TOKEN: other }, file, keychain), other);
  });

  it('never stores something that is not a token', () => {
    assert.throws(() => saveInstallToken('hunter2', { platform: 'win32', path: join(temp('token'), 't') }), InstallTokenError);
    assert.throws(() => saveInstallToken(`${TOKEN} -s other-service`, { platform: 'darwin', run: () => ({ status: 0, stdout: '' }), env: {}, path: join(temp('token'), 't') }), InstallTokenError);
  });
});

// ---------------------------------------------------------------------------
// Finding and wrapping servers
// ---------------------------------------------------------------------------

describe('MCP client configs', () => {
  function machine() {
    const home = temp('home');
    const cwd = join(home, 'work', 'repo');
    mkdirSync(join(cwd, '.cursor'), { recursive: true });
    mkdirSync(join(home, '.cursor'), { recursive: true });
    writeFileSync(join(cwd, '.mcp.json'), JSON.stringify({ mcpServers: { filesystem: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/srv'], env: { A: 'b' } }, remote: { url: 'https://example.test/mcp' } } }, null, 2) + '\n');
    writeFileSync(join(home, '.claude.json'), JSON.stringify({ numStartups: 7, mcpServers: { github: { command: 'docker', args: ['run', 'ghcr.io/github/github-mcp-server'] } }, projects: { [cwd]: { mcpServers: { db: { command: 'node', args: ['db.js'] } } }, '/somewhere/else': { mcpServers: { other: { command: 'node', args: ['x.js'] } } } } }));
    writeFileSync(join(home, '.cursor', 'mcp.json'), JSON.stringify({ mcpServers: { linear: { command: 'node', args: ['linear.js'] }, guarded: { command: 'npx', args: ['-y', '@permission-protocol/mcp-guard@0.4.0', '--config', 'p.yaml', '--', 'node', 's.js'] } } }));
    writeFileSync(join(cwd, '.cursor', 'mcp.json'), '{ not json');
    return { home, cwd };
  }

  it('finds stdio servers of both clients, project and user level, and says what it skipped', () => {
    const { home, cwd } = machine();
    const { servers, skipped } = findServers({ home, cwd });
    assert.deepEqual(servers.map((s) => `${s.client}:${s.name}:${s.wrapped}`).sort(), ['claude-code:db:false', 'claude-code:filesystem:false', 'claude-code:github:false', 'cursor:guarded:true', 'cursor:linear:false']);
    assert.deepEqual(skipped.map((s) => s.reason), ['not valid JSON']);
    assert.deepEqual(findServers({ home, cwd, client: 'cursor' }).servers.map((s) => s.name).sort(), ['guarded', 'linear']);
    assert.deepEqual(findServers({ home: temp('empty'), cwd: temp('empty') }), { servers: [], skipped: [] });
  });

  it('wraps one server, keeps everything else, and copies the file aside first', () => {
    const { home, cwd } = machine();
    const file = join(cwd, '.mcp.json');
    const before = readFileSync(file, 'utf-8');
    const server = findServers({ home, cwd }).servers.find((s) => s.name === 'filesystem')!;
    const result = wrapServer(server, { policyPath: '/cfg/policies/filesystem.yaml', agentId: 'claude-code', version: '0.4.0', now: new Date('2026-11-10T12:00:00.000Z') });

    assert.equal(readFileSync(result.backup, 'utf-8'), before);
    assert.match(result.backup, /\.mcp\.json\.mcp-guard-backup-2026-11-10T12-00-00-000Z$/);
    const after = JSON.parse(readFileSync(file, 'utf-8'));
    const expected = wrappedCommand(server, { policyPath: '/cfg/policies/filesystem.yaml', agentId: 'claude-code', version: '0.4.0' });
    assert.deepEqual(after.mcpServers.filesystem, { ...expected, env: { A: 'b' } });
    assert.deepEqual(after.mcpServers.remote, { url: 'https://example.test/mcp' });
    assert.equal(readFileSync(file, 'utf-8').endsWith('\n'), true);
    // The original command survives, in order, after `--`.
    const tail = expected.args.slice(expected.args.indexOf('--') + 1);
    assert.deepEqual(tail, ['npx', '-y', '@modelcontextprotocol/server-filesystem', '/srv']);

    // It is now seen as wrapped, and wrapping it twice is refused.
    const again = findServers({ home, cwd }).servers.find((s) => s.name === 'filesystem')!;
    assert.equal(again.wrapped, true);
    assert.throws(() => wrapServer(again, { policyPath: 'p', agentId: 'a', version: '0.4.0' }), /already wrapped/);
  });

  it('wraps a project-scoped server in ~/.claude.json without touching other projects', () => {
    const { home, cwd } = machine();
    const server = findServers({ home, cwd }).servers.find((s) => s.name === 'db')!;
    wrapServer(server, { policyPath: 'p.yaml', agentId: 'claude-code', version: '0.4.0' });
    const after = JSON.parse(readFileSync(join(home, '.claude.json'), 'utf-8'));
    assert.equal(isWrapped(after.projects[cwd].mcpServers.db.command, after.projects[cwd].mcpServers.db.args), true);
    assert.deepEqual(after.projects['/somewhere/else'].mcpServers.other, { command: 'node', args: ['x.js'] });
    assert.deepEqual(after.mcpServers.github, { command: 'docker', args: ['run', 'ghcr.io/github/github-mcp-server'] });
    assert.equal(after.numStartups, 7);
  });

  it('refuses to write when the file changed since it was read', () => {
    const { home, cwd } = machine();
    const server = findServers({ home, cwd }).servers.find((s) => s.name === 'filesystem')!;
    writeFileSync(join(cwd, '.mcp.json'), JSON.stringify({ mcpServers: { filesystem: { command: 'python', args: ['other.py'] } } }));
    assert.throws(() => wrapServer(server, { policyPath: 'p', agentId: 'a', version: '0.4.0' }), /changed since it was read/);
    assert.equal(readdirSync(cwd).some((name) => name.includes('mcp-guard-backup')), false);
  });

  it('pins the guard version and goes through cmd on Windows', () => {
    const server = { command: 'node', args: ['s.js'] };
    const options = { policyPath: 'p.yaml', agentId: 'cursor', version: '0.4.0' };
    assert.deepEqual(wrappedCommand(server, options, 'linux'), { command: 'npx', args: ['-y', '@permission-protocol/mcp-guard@0.4.0', '--config', 'p.yaml', '--agent-id', 'cursor', '--', 'node', 's.js'] });
    assert.deepEqual(wrappedCommand(server, options, 'win32').command, 'cmd');
    assert.deepEqual(wrappedCommand(server, options, 'win32').args.slice(0, 3), ['/c', 'npx', '-y']);
    assert.equal(isWrapped('cmd', wrappedCommand(server, options, 'win32').args), true);
    assert.equal(isWrapped('node', ['@permission-protocol/mcp-guard-lookalike', '--']), false);
  });
});

describe('the policy init writes', () => {
  it('loads, holds exactly the chosen tool, and turns cloud approvals on', () => {
    const config = parseConfig(policyText({ serverLabel: 'filesystem', tool: 'delete_file', environment: 'production', apiUrl: PRODUCTION_API_URL, trustKeys: [] }));
    assert.equal(config.default_action, 'allow');
    assert.deepEqual(config.rules, [{ id: 'hold-delete_file', method: 'tools/call', tool: 'delete_file', action: 'require_approval', reversibility: 'irreversible' }]);
    assert.deepEqual(config.cloud, { api_url: PRODUCTION_API_URL, environment: 'production', approval_timeout_seconds: 600 });
    assert.equal(config.server_label, 'filesystem');
  });

  it('with no tool to name, holds everything', () => {
    const config = parseConfig(policyText({ serverLabel: 'db', tool: null, environment: 'staging', apiUrl: PRODUCTION_API_URL, trustKeys: [] }));
    assert.equal(config.default_action, 'require_approval');
    assert.deepEqual(config.rules, []);
  });

  it('quotes names so a tool name cannot add policy', () => {
    const config = parseConfig(policyText({ serverLabel: 'fs', tool: 'x: y\n    action: allow', environment: 'production', apiUrl: PRODUCTION_API_URL, trustKeys: [] }));
    assert.equal(config.rules.length, 1);
    assert.equal(config.rules[0].action, 'require_approval');
    assert.equal(config.rules[0].tool, 'x: y\n    action: allow');
  });
});

// ---------------------------------------------------------------------------
// Device login
// ---------------------------------------------------------------------------

describe('device login', () => {
  const fast = { sleep: async () => undefined };

  it('polls until a person connects it, then returns the token and the workspace', async () => {
    const fake = await startFakePp(TOKEN);
    try {
      fake.device.pollsBeforeDecision = 3;
      const login = await startLogin(fake.url, 'laptop');
      assert.equal(login.userCode, 'ABCD-EFGH');
      assert.equal(login.verificationUrlComplete, `${fake.url}/mcp/connect?code=ABCD-EFGH`);
      const done = await awaitLogin(fake.url, login, fast);
      assert.deepEqual(done, { token: TOKEN, tokenId: 'key_fake_1', workspace: { name: 'Acme Eng', slug: 'acme-eng' } });
      assert.equal(fake.calls.filter((c) => c.path === '/api/mcp/device/token').length, 4);
      assert.deepEqual(fake.calls[0].body, { clientLabel: 'laptop' });
      assert.equal(fake.calls.every((c) => c.authorization === null), true);
    } finally { await fake.close(); }
  });

  it('cancelled in the browser, or never completed: no token', async () => {
    const fake = await startFakePp(TOKEN);
    try {
      fake.device.decision = 'cancel';
      await assert.rejects(awaitLogin(fake.url, await startLogin(fake.url, null), fast), (err: unknown) => err instanceof DeviceLoginError && err.code === 'DEVICE_LOGIN_CANCELLED');
      fake.device.decision = 'never';
      let clock = 0;
      const login = await startLogin(fake.url, null);
      await assert.rejects(
        awaitLogin(fake.url, { ...login, expiresInSec: 5 }, { sleep: async (ms) => { clock += ms; }, now: () => clock }),
        (err: unknown) => err instanceof DeviceLoginError && err.code === 'DEVICE_CODE_EXPIRED',
      );
    } finally { await fake.close(); }
  });

  it('refuses a sign-in link on another site', async () => {
    const evil = (async () => new Response(JSON.stringify({ deviceCode: 'ppdc_x', userCode: 'AAAA-BBBB', verificationUrl: 'https://evil.test/mcp/connect', verificationUrlComplete: 'https://evil.test/mcp/connect?code=AAAA-BBBB' }), { status: 201 })) as typeof fetch;
    await assert.rejects(startLogin('https://app.permissionprotocol.com', null, { fetchImpl: evil }), /another site/);
    const down = (async () => { throw new TypeError('fetch failed'); }) as typeof fetch;
    await assert.rejects(startLogin('https://app.permissionprotocol.com', null, { fetchImpl: down }), (err: unknown) => err instanceof DeviceLoginError && err.code === 'UNREACHABLE');
  });
});

// ---------------------------------------------------------------------------
// The whole command, as a process, against a stand-in Permission Protocol
// ---------------------------------------------------------------------------

interface Run { code: number | null; stdout: string; stderr: string; ms: number }

function freshMachine(servers: Record<string, unknown> = { filesystem: { command: process.execPath, args: [ECHO], env: { KEEP: 'me' } } }) {
  const root = temp('fresh');
  const project = join(root, 'project');
  mkdirSync(project, { recursive: true });
  const mcpConfig = join(project, '.mcp.json');
  writeFileSync(mcpConfig, JSON.stringify({ mcpServers: servers }, null, 2) + '\n');
  const config = join(root, 'config');
  const env: NodeJS.ProcessEnv = { ...process.env, XDG_CONFIG_HOME: config, MCP_GUARD_TOKEN_STORE: 'file', ECHO_LOG: join(root, 'server.log'), HOME: root, USERPROFILE: root };
  for (const key of Object.keys(env)) if (key.startsWith('PP_')) delete env[key];
  return { root, project, mcpConfig, guardDir: join(config, 'mcp-guard'), env };
}

function runCli(args: string[], env: NodeJS.ProcessEnv, cwd: string): Promise<Run> {
  const started = Date.now();
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { env, cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('exit', (code) => resolve({ code, stdout, stderr, ms: Date.now() - started }));
  });
}

const initArgs = (fake: FakePp, mcpConfig: string, extra: string[] = []) => [
  'init', '--api-url', fake.url, '--trust-key', `${fake.issuer.keyId}=${fake.issuer.publicKeyB64}`,
  '--mcp-config', mcpConfig, '--tool', 'delete_file', '--label', 'ci-machine', '--yes', '--no-browser', ...extra,
];

describe('mcp-guard init, end to end', () => {
  it('fresh machine to first signed receipt, in well under ten minutes', async () => {
    const fake = await startFakePp(TOKEN);
    const machine = freshMachine();
    try {
      const run = await runCli(initArgs(fake, machine.mcpConfig), machine.env, machine.project);
      assert.equal(run.code, 0, `${run.stdout}\n${run.stderr}`);

      // What the person saw, in order.
      const out = run.stdout;
      const order = ['Server: filesystem', `Open ${fake.url}/mcp/connect?code=ABCD-EFGH`, 'this code: ABCD-EFGH', 'Connected to workspace: Acme Eng (acme-eng)', 'Install token: stored in', 'Local signing key: created mcpg-', 'Hold rule: "delete_file" needs a signature', 'Policy: ', 'Wrapped "filesystem"', 'Self-test: holding a do-nothing call', 'Sign it here: ', 'Signed receipt: rcpt_fake_', 'Verify it: npx @permission-protocol/mcp-guard receipt verify rcpt_fake_', 'Time to first signed receipt: '];
      let at = 0;
      for (const piece of order) {
        const found = out.indexOf(piece, at);
        assert.notEqual(found, -1, `missing or out of order: "${piece}"\n${out}`);
        at = found;
      }
      assert.match(out, /signed by Maria Signer/);
      // Neither the token nor the device code is ever printed.
      assert.equal(`${run.stdout}${run.stderr}`.includes(TOKEN), false);
      assert.equal(/ppdc_/.test(`${run.stdout}${run.stderr}`), false);

      // The ten-minute goal, measured two ways: wall clock and what init reports.
      assert.ok(run.ms < 10 * 60_000, `took ${run.ms} ms`);
      const reported = /Time to first signed receipt: (?:(\d+)m )?(\d+)s\./.exec(out)!;
      assert.ok(Number(reported[1] ?? 0) * 60 + Number(reported[2]) < 600);

      // What is on the machine afterwards.
      const tokenFile = join(machine.guardDir, 'install-token');
      assert.equal(readFileSync(tokenFile, 'utf-8').trim(), TOKEN);
      if (process.platform !== 'win32') assert.equal(statSync(tokenFile).mode & 0o777, 0o600);
      assert.equal(existsSync(join(machine.guardDir, 'keys', 'keys.json')), true);
      const policyPath = join(machine.guardDir, 'policies', 'filesystem.yaml');
      const policy = parseConfig(readFileSync(policyPath, 'utf-8'));
      assert.equal(policy.cloud?.api_url, fake.url);
      assert.deepEqual(policy.rules.map((r) => [r.tool, r.action]), [['delete_file', 'require_approval']]);

      const wrapped = JSON.parse(readFileSync(machine.mcpConfig, 'utf-8')).mcpServers.filesystem;
      assert.equal(isWrapped(wrapped.command, wrapped.args), true);
      assert.deepEqual(wrapped.env, { KEEP: 'me' });
      assert.deepEqual(wrapped.args.slice(wrapped.args.indexOf('--') + 1), [process.execPath, ECHO]);
      assert.ok(wrapped.args.includes(policyPath));
      assert.equal(readdirSync(machine.project).filter((name) => name.includes('mcp-guard-backup')).length, 1);

      // The API saw a device login, then one held call opened, read and redeemed with the stored token.
      const paths = fake.calls.map((c) => `${c.method} ${c.path.replace(/mcpreq_\d+/, ':id')}`);
      assert.deepEqual([...new Set(paths)], ['POST /api/mcp/device/start', 'POST /api/mcp/device/token', 'POST /api/mcp/approval-requests', 'GET /api/mcp/approval-requests/:id', 'POST /api/mcp/approval-requests/:id/redeem']);
      assert.deepEqual(fake.calls.find((c) => c.path === '/api/mcp/device/start')!.body, { clientLabel: 'ci-machine' });
      const create = fake.calls.find((c) => c.path === '/api/mcp/approval-requests')!;
      assert.equal(create.authorization, `Bearer ${TOKEN}`);
      assert.equal(create.body.tool, 'mcp_guard_self_test');
      assert.equal(fake.redeemed.length, 1);

      // The verify command init printed works as printed (through this build instead of npx).
      const verify = /Verify it: npx @permission-protocol\/mcp-guard (receipt verify \S+) --receipts-path "([^"]+)" --config "([^"]+)"/.exec(out)!;
      assert.equal(verify[3], policyPath);
      const verifyArgs = [...verify[1].split(' '), '--receipts-path', verify[2], '--config', verify[3]];
      const verified = spawnSync(process.execPath, [CLI, ...verifyArgs], { env: machine.env, encoding: 'utf-8' });
      assert.equal(verified.status, 0, verified.stderr);
      assert.match(verified.stdout, /VERIFIED rcpt_fake_/);
      assert.match(verified.stdout, /signed by:\s+Maria Signer \(user:u_maria, session_stepup_webauthn\)/);
      assert.match(verified.stdout, /call:\s+mcp_guard_self_test on mcp-guard-self-test, requested by claude-code/);

      // An edited log line is refused; an unknown id is not found; production pins do not accept a test key.
      const tampered = join(machine.root, 'tampered.jsonl');
      writeFileSync(tampered, readFileSync(verify[2], 'utf-8').replace(/"fingerprint":"sha256:[0-9a-f]{4}/, '"fingerprint":"sha256:0000'));
      assert.equal(spawnSync(process.execPath, [CLI, 'receipt', 'verify', verify[1].split(' ')[2], '--receipts-path', tampered, '--config', policyPath], { env: machine.env }).status, 1);
      assert.equal(spawnSync(process.execPath, [CLI, 'receipt', 'verify', 'rcpt_missing', '--receipts-path', verify[2]], { env: machine.env }).status, 2);
      assert.equal(spawnSync(process.execPath, [CLI, 'receipt', 'verify', verify[1].split(' ')[2], '--receipts-path', verify[2]], { env: machine.env }).status, 1);

      // Running init again finds nothing left to wrap and changes nothing.
      const before = readFileSync(machine.mcpConfig, 'utf-8');
      const again = await runCli(initArgs(fake, machine.mcpConfig), machine.env, machine.project);
      assert.equal(again.code, 1);
      assert.match(again.stderr, /already wrapped by mcp-guard/);
      assert.equal(readFileSync(machine.mcpConfig, 'utf-8'), before);
    } finally { await fake.close(); }
  });

  it('the wrapped server then holds the chosen tool and forwards the rest', async () => {
    const fake = await startFakePp(TOKEN);
    const machine = freshMachine();
    try {
      assert.equal((await runCli(initArgs(fake, machine.mcpConfig, ['--skip-self-test']), machine.env, machine.project)).code, 0);
      // Start the server the way the client now would, through this build of the guard.
      const wrapped = JSON.parse(readFileSync(machine.mcpConfig, 'utf-8')).mcpServers.filesystem;
      const guardArgs: string[] = wrapped.args.slice(wrapped.args.indexOf('--config'));
      const child = spawn(process.execPath, [CLI, ...guardArgs], { env: machine.env, stdio: ['pipe', 'pipe', 'pipe'] });
      const responses = new Map<number, any>();
      let buffer = '';
      child.stdout.on('data', (d) => {
        buffer += d.toString();
        for (const line of buffer.split('\n')) { try { const m = JSON.parse(line); responses.set(m.id, m); } catch { /* partial */ } }
      });
      const wait = async (id: number) => { for (let i = 0; i < 300 && !responses.has(id); i++) await new Promise((r) => setTimeout(r, 50)); return responses.get(id); };
      try {
        child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: { path: '/a' } } }) + '\n');
        assert.equal((await wait(1)).result.echoed, 'tools/call');
        fake.decision = 'reject';
        child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'delete_file', arguments: { path: '/held-marker' } } }) + '\n');
        assert.equal((await wait(2)).error.code, -32003);
        assert.equal(readFileSync(join(machine.root, 'server.log'), 'utf-8').includes('held-marker'), false);
      } finally { child.kill(); }
    } finally { await fake.close(); }
  });

  it('a cancelled login changes nothing on the machine', async () => {
    const fake = await startFakePp(TOKEN);
    const machine = freshMachine();
    try {
      fake.device.decision = 'cancel';
      const before = readFileSync(machine.mcpConfig, 'utf-8');
      const run = await runCli(initArgs(fake, machine.mcpConfig), machine.env, machine.project);
      assert.equal(run.code, 1);
      assert.match(run.stderr, /cancelled in the browser/);
      assert.equal(readFileSync(machine.mcpConfig, 'utf-8'), before);
      assert.equal(existsSync(join(machine.guardDir, 'install-token')), false);
      assert.equal(existsSync(join(machine.guardDir, 'policies')), false);
    } finally { await fake.close(); }
  });

  it('no server to wrap: says where it looked, before asking anyone to log in', async () => {
    const fake = await startFakePp(TOKEN);
    const machine = freshMachine({ remote: { url: 'https://example.test/mcp' } });
    try {
      const run = await runCli(initArgs(fake, machine.mcpConfig), machine.env, machine.project);
      assert.equal(run.code, 1);
      assert.match(run.stderr, /No stdio MCP server was found/);
      assert.equal(fake.calls.length, 0);
    } finally { await fake.close(); }
  });

  it('a rejected self-test is a failed init that says the setup fails closed', async () => {
    const fake = await startFakePp(TOKEN);
    const machine = freshMachine();
    try {
      fake.decision = 'reject';
      const run = await runCli(initArgs(fake, machine.mcpConfig), machine.env, machine.project);
      assert.equal(run.code, 1);
      assert.match(run.stderr, /Self-test did not produce a signed receipt: Denied/);
      assert.match(run.stderr, /fails closed/);
      assert.doesNotMatch(run.stdout, /Time to first signed receipt/);
    } finally { await fake.close(); }
  });

  it('refuses key overrides for production and a non-production API without a pinned key', async () => {
    const machine = freshMachine();
    const prod = await runCli(['init', '--trust-key', `k=${Buffer.alloc(32, 1).toString('base64')}`, '--mcp-config', machine.mcpConfig, '--yes', '--no-browser'], machine.env, machine.project);
    assert.equal(prod.code, 1);
    assert.match(prod.stderr, /pinned in this release/);
    const other = await runCli(['init', '--api-url', 'https://staging.example.test', '--mcp-config', machine.mcpConfig, '--yes', '--no-browser'], machine.env, machine.project);
    assert.equal(other.code, 1);
    assert.match(other.stderr, /needs at least one --trust-key/);
    const unknown = await runCli(['init', '--fail-open'], machine.env, machine.project);
    assert.equal(unknown.code, 2);
    assert.match(unknown.stderr, /unknown option: --fail-open/);
    assert.equal(readdirSync(machine.project).some((name) => name.includes('backup')), false);
  });
});

// ---------------------------------------------------------------------------
// init --preset coding-agent: the policy, the Claude Code hook and its self-test
// ---------------------------------------------------------------------------

/** This build, started the way the installed hook starts the guard. Contains "mcp-guard", as install requires. */
const LAUNCHER = `${process.execPath} ${join(__dirname, '..', '..', '..', 'bin', 'mcp-guard')}`;

const presetArgs = (fake: FakePp, mcpConfig: string, extra: string[] = []) => [
  'init', '--api-url', fake.url, '--trust-key', `${fake.issuer.keyId}=${fake.issuer.publicKeyB64}`,
  '--mcp-config', mcpConfig, '--preset', 'coding-agent', '--launcher', LAUNCHER, '--label', 'ci-machine', '--yes', '--no-browser', ...extra,
];

/** A fresh machine whose project is a Claude Code project. */
function claudeProject(servers?: Record<string, unknown>) {
  const machine = freshMachine(servers);
  mkdirSync(join(machine.project, '.claude'), { recursive: true });
  return machine;
}

const ourEntries = (project: string): number => {
  const settings = JSON.parse(readFileSync(settingsPath(project), 'utf-8'));
  return settings.hooks.PreToolUse.flatMap((g: any) => g.hooks).filter((h: any) => / hook --config /.test(h.command) && h.command.includes('mcp-guard')).length;
};

describe('mcp-guard init --preset coding-agent', () => {
  it('in a Claude Code project: writes the preset, installs the hook, checks it locally, then signs a first receipt', async () => {
    const fake = await startFakePp(TOKEN);
    const machine = claudeProject();
    try {
      writeFileSync(settingsPath(machine.project), JSON.stringify({ permissions: { allow: ['Bash(ls)'] } }, null, 2) + '\n');
      const run = await runCli(presetArgs(fake, machine.mcpConfig), machine.env, machine.project);
      assert.equal(run.code, 0, `${run.stdout}\n${run.stderr}`);
      const out = run.stdout;
      const order = ['Server: filesystem', 'Connected to workspace', 'Policy preset: coding-agent', 'Policy: ', 'Hook policy: ', 'Claude Code hook: installed in ', 'undo:   npx mcp-guard hook uninstall', 'Wrapped "filesystem"', 'Restart Claude Code so it starts "filesystem" through the guard and loads the hook.', 'Hook self-test (local', 'ok   allowed: Bash "git status"', 'ok   held: Bash "terraform destroy -auto-approve": denied by rule "terraform-destroy"', 'Guarded now:', 'Claude Code in ', 'MCP server "filesystem"', 'Signed receipt: rcpt_fake_', 'Time to first signed receipt: '];
      let at = 0;
      for (const piece of order) {
        const found = out.indexOf(piece, at);
        assert.notEqual(found, -1, `missing or out of order: "${piece}"\n${out}`);
        at = found;
      }
      assert.equal(`${run.stdout}${run.stderr}`.includes(TOKEN), false, 'the install token is never printed');

      // The hook's policy: the preset, with cloud approvals, and it loads.
      const hookPolicy = parseConfig(readFileSync(join(machine.project, 'pp.config.yaml'), 'utf-8'));
      assert.equal(hookPolicy.cloud?.api_url, fake.url);
      assert.ok(hookPolicy.rules.some((r) => r.id === 'terraform-destroy'));
      assert.deepEqual(hookPolicy.rules.filter((r) => r.observe).map((r) => r.id), ['secret-read']);
      // The wrapped server's policy is the preset too.
      const serverPolicy = parseConfig(readFileSync(join(machine.guardDir, 'policies', 'filesystem.yaml'), 'utf-8'));
      assert.ok(serverPolicy.rules.some((r) => r.id === 'destructive-shell'));

      // The hook entry is there, once, and the other settings are kept.
      const settings = JSON.parse(readFileSync(settingsPath(machine.project), 'utf-8'));
      assert.deepEqual(settings.permissions, { allow: ['Bash(ls)'] });
      assert.equal(ourEntries(machine.project), 1);
      const handler = settings.hooks.PreToolUse[0].hooks[0];
      assert.equal(handler.onFailure, 'block');
      assert.ok(handler.command.startsWith(`${LAUNCHER} hook --config "\${CLAUDE_PROJECT_DIR}"/pp.config.yaml`));

      // The hook self-test sent nothing: the only approval request is the do-nothing self-test tool.
      const created = fake.calls.filter((c) => c.method === 'POST' && c.path === '/api/mcp/approval-requests');
      assert.equal(created.length, 1);
      assert.equal(created[0].body.tool, 'mcp_guard_self_test');
      // Its receipts went to the self-test log, not the project's.
      assert.equal(existsSync(join(machine.project, 'pp-receipts.jsonl')), false);
      const selfTestLog = readFileSync(join(machine.guardDir, 'self-test-receipts.jsonl'), 'utf-8');
      assert.match(selfTestLog, /"tool":"Bash"/);
      assert.doesNotMatch(selfTestLog, /terraform destroy|git status/, 'no argument text in the log');

      // hook uninstall recognises the entry init wrote.
      const removed = spawnSync(process.execPath, [CLI, 'hook', 'uninstall', '--project', machine.project], { env: machine.env, encoding: 'utf-8' });
      assert.equal(removed.status, 0, removed.stderr);
      assert.match(removed.stdout, /removed 1 mcp-guard PreToolUse hook/);
      assert.deepEqual(JSON.parse(readFileSync(settingsPath(machine.project), 'utf-8')), { permissions: { allow: ['Bash(ls)'] } });
    } finally { await fake.close(); }
  });

  it('running it again is safe: no second entry, no overwritten policy', async () => {
    const fake = await startFakePp(TOKEN);
    const machine = claudeProject();
    try {
      assert.equal((await runCli(presetArgs(fake, machine.mcpConfig, ['--skip-self-test']), machine.env, machine.project)).code, 0);
      const policyFile = join(machine.project, 'pp.config.yaml');
      const files = [policyFile, settingsPath(machine.project), machine.mcpConfig];
      const snapshot = () => files.map((f) => readFileSync(f, 'utf-8'));
      const before = snapshot();
      const calls = fake.calls.length;

      // Everything is in place: nothing to do, and no new login.
      const again = await runCli(presetArgs(fake, machine.mcpConfig, ['--skip-self-test']), machine.env, machine.project);
      assert.equal(again.code, 1);
      assert.match(again.stderr, /Already set up/);
      assert.deepEqual(snapshot(), before);
      assert.equal(fake.calls.length, calls);

      // The person edited the policy: init refuses to overwrite it, before any login.
      const edited = before[0].replace('databases: []', 'databases: [prod-db.internal]');
      writeFileSync(policyFile, edited);
      spawnSync(process.execPath, [CLI, 'hook', 'uninstall', '--project', machine.project], { env: machine.env });
      const settingsBefore = readFileSync(settingsPath(machine.project), 'utf-8');
      const refused = await runCli(presetArgs(fake, machine.mcpConfig, ['--skip-self-test']), machine.env, machine.project);
      assert.equal(refused.code, 1);
      assert.match(refused.stderr, /already exists and is not the coding-agent preset init would write\. init never overwrites a policy/);
      assert.equal(readFileSync(policyFile, 'utf-8'), edited);
      assert.equal(readFileSync(settingsPath(machine.project), 'utf-8'), settingsBefore);
      assert.equal(fake.calls.length, calls);

      // Policy restored, hook removed: init puts the hook back, once, and leaves the policy alone.
      writeFileSync(policyFile, before[0]);
      const restored = await runCli(presetArgs(fake, machine.mcpConfig, ['--skip-self-test']), machine.env, machine.project);
      assert.equal(restored.code, 0, `${restored.stdout}\n${restored.stderr}`);
      assert.match(restored.stdout, /every one found is already wrapped; setting up the Claude Code hook only/);
      assert.match(restored.stdout, /Hook policy: .*already the coding-agent preset; unchanged/);
      assert.equal(readFileSync(policyFile, 'utf-8'), before[0]);
      assert.equal(ourEntries(machine.project), 1);
      assert.equal(readFileSync(machine.mcpConfig, 'utf-8'), before[2]);
    } finally { await fake.close(); }
  });

  it('refuses a settings file that is not valid JSON, before login, and changes nothing', async () => {
    const fake = await startFakePp(TOKEN);
    const machine = claudeProject();
    try {
      writeFileSync(settingsPath(machine.project), '{ "hooks": { not json');
      const mcpBefore = readFileSync(machine.mcpConfig, 'utf-8');
      const run = await runCli(presetArgs(fake, machine.mcpConfig), machine.env, machine.project);
      assert.equal(run.code, 1);
      assert.match(run.stderr, /SETTINGS_INVALID_JSON: .*settings\.json is not valid JSON.*init stopped before changing anything/);
      assert.equal(readFileSync(settingsPath(machine.project), 'utf-8'), '{ "hooks": { not json');
      assert.equal(existsSync(join(machine.project, 'pp.config.yaml')), false);
      assert.equal(readFileSync(machine.mcpConfig, 'utf-8'), mcpBefore);
      assert.equal(existsSync(join(machine.guardDir, 'install-token')), false);
      assert.equal(fake.calls.length, 0);

      // The documented shape is checked too.
      writeFileSync(settingsPath(machine.project), JSON.stringify({ hooks: { PreToolUse: { matcher: 'Bash' } } }));
      const shape = await runCli(presetArgs(fake, machine.mcpConfig), machine.env, machine.project);
      assert.equal(shape.code, 1);
      assert.match(shape.stderr, /SETTINGS_UNEXPECTED_SHAPE/);
      assert.equal(fake.calls.length, 0);
    } finally { await fake.close(); }
  });

  it('a launcher that cannot start the guard is refused before anything changes', async () => {
    const fake = await startFakePp(TOKEN);
    const machine = claudeProject();
    try {
      const args = presetArgs(fake, machine.mcpConfig);
      args[args.indexOf('--launcher') + 1] = '/nonexistent/bin/mcp-guard';
      const run = await runCli(args, machine.env, machine.project);
      assert.equal(run.code, 1);
      assert.match(run.stderr, /did not start mcp-guard.*npm install --save-dev @permission-protocol\/mcp-guard/);
      assert.equal(existsSync(settingsPath(machine.project)), false);
      assert.equal(existsSync(join(machine.project, 'pp.config.yaml')), false);
      assert.equal(fake.calls.length, 0);
    } finally { await fake.close(); }
  });

  it('with no MCP server, --hook claude-code sets up the hook alone; without a Claude Code project and no --hook, no hook', async () => {
    const fake = await startFakePp(TOKEN);
    const machine = freshMachine({ remote: { url: 'https://example.test/mcp' } });
    try {
      const plain = await runCli(presetArgs(fake, machine.mcpConfig, ['--skip-self-test']), machine.env, machine.project);
      assert.equal(plain.code, 1, 'no hook and no server: the existing refusal');
      assert.match(plain.stderr, /No stdio MCP server was found/);
      assert.equal(fake.calls.length, 0);

      const run = await runCli(presetArgs(fake, machine.mcpConfig, ['--hook', 'claude-code', '--skip-self-test']), machine.env, machine.project);
      assert.equal(run.code, 0, `${run.stdout}\n${run.stderr}`);
      assert.match(run.stdout, /MCP servers: none found to wrap; setting up the Claude Code hook only/);
      assert.match(run.stdout, /ok   held: Bash "terraform destroy -auto-approve"/);
      assert.match(run.stdout, /Restart Claude Code so it loads the hook\./);
      assert.doesNotMatch(run.stdout, /Wrapped "/);
      assert.equal(ourEntries(machine.project), 1);
      assert.equal(existsSync(join(machine.guardDir, 'policies')), false);
      assert.equal(fake.calls.filter((c) => c.path === '/api/mcp/approval-requests').length, 0);
    } finally { await fake.close(); }
  });

  it('flag rules: --hook needs --preset; --hook and --no-hook conflict; --no-hook keeps the old behaviour', async () => {
    const machine = claudeProject();
    const noPreset = await runCli(['init', '--hook', 'claude-code'], machine.env, machine.project);
    assert.equal(noPreset.code, 2);
    assert.match(noPreset.stderr, /--hook needs --preset coding-agent/);
    const both = await runCli(['init', '--preset', 'coding-agent', '--hook', 'claude-code', '--no-hook'], machine.env, machine.project);
    assert.equal(both.code, 2);
    const unknown = await runCli(['init', '--preset', 'coding-agent', '--hook', 'cursor'], machine.env, machine.project);
    assert.equal(unknown.code, 2);
    assert.match(unknown.stderr, /--hook must be one of: claude-code/);

    const fake = await startFakePp(TOKEN);
    try {
      const run = await runCli(presetArgs(fake, machine.mcpConfig, ['--no-hook', '--skip-self-test']), machine.env, machine.project);
      assert.equal(run.code, 0, run.stderr);
      assert.match(run.stdout, /Claude Code's own tools \(shell, file edits\) are not guarded: --no-hook was passed/);
      assert.equal(existsSync(settingsPath(machine.project)), false);
      assert.equal(existsSync(join(machine.project, 'pp.config.yaml')), false);
    } finally { await fake.close(); }
  });
});
