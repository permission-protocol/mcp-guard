import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseConfig } from '../config.js';
import { awaitLogin, DeviceLoginError, startLogin } from '../cloud/device-login.js';
import { PRODUCTION_API_URL } from '../cloud/pinned-keys.js';
import { InstallTokenError, KEYCHAIN_ACCOUNT, KEYCHAIN_SERVICE, loadInstallToken, saveInstallToken, type KeychainRunner } from '../cloud/token.js';
import { keyProtectionMessage, policyText, selfTestEnv, tokenStoredMessage } from '../init/init.js';
import { heartbeatEnvOff } from '../heartbeat/launch.js';
import { findServers, isWrapped, probeWrapLauncher, splitLauncher, wrapLauncher, wrapServer, wrappedCommand } from '../init/mcp-clients.js';
import { restrictToCurrentUser, type ExecFile } from '../win-protect.js';
import { createKey } from '../keystore.js';
import { startFakePp, type FakePp } from './cloud-helpers.js';
import { fakeNpx } from './fake-npx.js';
import { settingsPath } from '../hook/install.js';

const CLI = join(__dirname, '..', 'cli.js');
const ECHO = join(__dirname, 'fixtures-echo-server.js');
const TOKEN = `pp_test_${'init'.repeat(8)}`;
const temp = (name: string) => mkdtempSync(join(tmpdir(), `mcp-guard-${name}-`));
const VERSION: string = JSON.parse(readFileSync(join(__dirname, '..', '..', '..', 'package.json'), 'utf-8')).version;
const BIN = join(__dirname, '..', '..', '..', 'bin', 'mcp-guard');


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
    for (const platform of ['linux', 'darwin'] as const) {
      assert.deepEqual(saveInstallToken(TOKEN, { platform, run: unavailable, env: {}, path: file }), { kind: 'file', path: file });
    }
    const icacls: ExecFile = () => ({ status: 0 });
    assert.deepEqual(saveInstallToken(TOKEN, { platform: 'win32', run: unavailable, env: { USERNAME: 'maria' }, path: file, exec: icacls }), { kind: 'file', path: file, windows: 'restricted' });
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
    assert.throws(() => saveInstallToken('hunter2', { platform: 'win32', path: join(temp('token'), 't'), exec: () => ({ status: 0 }) }), InstallTokenError);
    assert.throws(() => saveInstallToken(`${TOKEN} -s other-service`, { platform: 'darwin', run: () => ({ status: 0, stdout: '' }), env: {}, path: join(temp('token'), 't') }), InstallTokenError);
  });
});

describe('Windows: the token and private key restricted with icacls', () => {
  function recorder(status: number | null, throws = false) {
    const calls: Array<{ file: string; args: string[]; timeout: number }> = [];
    const exec: ExecFile = (file, args, options) => {
      calls.push({ file, args, timeout: options.timeout });
      if (throws) throw new Error('spawn icacls ENOENT');
      return { status };
    };
    return { exec, calls };
  }
  const tricky = (dir: string) => join(dir, 'a dir & "x"; del *', 'install-token');

  it('icacls succeeds: the file is restricted to the current user, and init says so', () => {
    const dir = temp('win');
    const file = tricky(dir);
    const { exec, calls } = recorder(0);
    const stored = saveInstallToken(TOKEN, { platform: 'win32', env: { USERNAME: 'maria', USERDOMAIN: 'ACME' }, path: file, exec });
    assert.deepEqual(stored, { kind: 'file', path: file, windows: 'restricted' });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].file, 'icacls');
    assert.deepEqual(calls[0].args, [file, '/inheritance:r', '/grant:r', 'ACME\\maria:F'], 'the path is its own argument, never part of a command string');
    assert.ok(calls[0].timeout > 0);
    assert.equal(tokenStoredMessage(stored), `Install token: stored in ${file} (restricted to the current user (icacls)).`);
    assert.equal(keyProtectionMessage('restricted'), '  Private key: restricted to the current user (icacls).');
  });

  it('icacls fails or is missing: init does not fail, and never says owner-only', () => {
    for (const [status, throws] of [[5, false], [null, false], [0, true]] as const) {
      const file = tricky(temp('win'));
      const { exec } = recorder(status, throws);
      const stored = saveInstallToken(TOKEN, { platform: 'win32', env: { USERNAME: 'maria' }, path: file, exec });
      assert.deepEqual(stored, { kind: 'file', path: file, windows: 'profile-only' });
      const message = tokenStoredMessage(stored);
      assert.equal(message, `Install token: stored in ${file} (not restricted (icacls failed or is missing); protected only by the permissions of your user profile folder).`);
      assert.equal(message.includes('owner-only'), false);
      assert.equal(readFileSync(file, 'utf-8'), `${TOKEN}\n`);
    }
    assert.equal(keyProtectionMessage('profile-only'), '  Private key: not restricted (icacls failed or is missing); protected only by the permissions of your user profile folder.');
    assert.equal(restrictToCurrentUser('C:\\x', { platform: 'win32', env: {}, user: '', exec: () => ({ status: 0 }) }), 'profile-only', 'no user name: nothing to grant');
  });

  it('the private key gets the same treatment; POSIX runs nothing and keeps its wording', () => {
    const { exec, calls } = recorder(0);
    let seen: string | null = null;
    const key = createKey({ dir: join(temp('win'), 'keys'), protect: { platform: 'win32', exec, user: 'maria' }, onWindowsProtection: (p) => { seen = p; } });
    assert.equal(seen, 'restricted');
    assert.equal(calls.length, 1);
    assert.equal(calls[0].args[0].endsWith(`${key.keyId}.private.pem`), true);
    assert.deepEqual(calls[0].args.slice(1), ['/inheritance:r', '/grant:r', 'maria:F']);

    const posix = recorder(0);
    let posixSeen: string | null = null;
    createKey({ dir: join(temp('posix'), 'keys'), protect: { platform: 'linux', exec: posix.exec }, onWindowsProtection: (p) => { posixSeen = p; } });
    const file = join(temp('posix'), 'install-token');
    const stored = saveInstallToken(TOKEN, { platform: 'linux', run: () => ({ status: null, stdout: '' }), env: {}, path: file, exec: posix.exec });
    assert.equal(posix.calls.length, 0);
    assert.equal(posixSeen, null);
    assert.equal(tokenStoredMessage(stored), `Install token: stored in ${file} (owner-only).`);
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
    writeFileSync(join(home, '.cursor', 'mcp.json'), JSON.stringify({ mcpServers: { linear: { command: 'node', args: ['linear.js'] }, guarded: { command: 'npx', args: ['-y', '@permission-protocol/mcp-guard@0.5.1', '--config', 'p.yaml', '--', 'node', 's.js'] } } }));
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
    const result = wrapServer(server, { policyPath: '/cfg/policies/filesystem.yaml', agentId: 'claude-code', version: '0.5.1', now: new Date('2026-11-10T12:00:00.000Z') });

    assert.equal(readFileSync(result.backup, 'utf-8'), before);
    assert.match(result.backup, /\.mcp\.json\.mcp-guard-backup-2026-11-10T12-00-00-000Z$/);
    const after = JSON.parse(readFileSync(file, 'utf-8'));
    const expected = wrappedCommand(server, { policyPath: '/cfg/policies/filesystem.yaml', agentId: 'claude-code', version: '0.5.1' });
    assert.deepEqual(after.mcpServers.filesystem, { ...expected, env: { A: 'b' } });
    assert.deepEqual(after.mcpServers.remote, { url: 'https://example.test/mcp' });
    assert.equal(readFileSync(file, 'utf-8').endsWith('\n'), true);
    // The original command survives, in order, after `--`.
    const tail = expected.args.slice(expected.args.indexOf('--') + 1);
    assert.deepEqual(tail, ['npx', '-y', '@modelcontextprotocol/server-filesystem', '/srv']);

    // It is now seen as wrapped, and wrapping it twice is refused.
    const again = findServers({ home, cwd }).servers.find((s) => s.name === 'filesystem')!;
    assert.equal(again.wrapped, true);
    assert.throws(() => wrapServer(again, { policyPath: 'p', agentId: 'a', version: '0.5.1' }), /already wrapped/);
  });

  it('wraps a project-scoped server in ~/.claude.json without touching other projects', () => {
    const { home, cwd } = machine();
    const server = findServers({ home, cwd }).servers.find((s) => s.name === 'db')!;
    wrapServer(server, { policyPath: 'p.yaml', agentId: 'claude-code', version: '0.5.1' });
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
    assert.throws(() => wrapServer(server, { policyPath: 'p', agentId: 'a', version: '0.5.1' }), /changed since it was read/);
    assert.equal(readdirSync(cwd).some((name) => name.includes('mcp-guard-backup')), false);
  });

  it('pins the guard version and goes through cmd on Windows', () => {
    const server = { command: 'node', args: ['s.js'] };
    const options = { policyPath: 'p.yaml', agentId: 'cursor', version: '0.5.1' };
    assert.deepEqual(wrappedCommand(server, options, 'linux'), { command: 'npx', args: ['-y', '@permission-protocol/mcp-guard@0.5.1', '--config', 'p.yaml', '--agent-id', 'cursor', '--', 'node', 's.js'] });
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
  // The wrap step checks its `npx -y @permission-protocol/mcp-guard@<version>` launcher: a stand-in runs this build.
  const npx = fakeNpx(join(root, 'wrap'));
  const env: NodeJS.ProcessEnv = { ...process.env, XDG_CONFIG_HOME: config, MCP_GUARD_TOKEN_STORE: 'file', ECHO_LOG: join(root, 'server.log'), HOME: root, USERPROFILE: root, ...npx.env };
  for (const key of Object.keys(env)) if (key.startsWith('PP_')) delete env[key];
  return { root, project, mcpConfig, guardDir: join(config, 'mcp-guard'), env, npxLog: npx.log };
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

describe('init self-test environment', () => {
  it('sends its receipts to the self-test log and never starts a usage heartbeat', () => {
    const env = selfTestEnv({ PATH: '/usr/bin', MCP_GUARD_HEARTBEAT: 'on' }, '/tmp/self-test-receipts.jsonl');
    assert.equal(env.PP_SHARED_RECEIPTS_PATH, '/tmp/self-test-receipts.jsonl');
    assert.equal(env.MCP_GUARD_HEARTBEAT, 'off');
    assert.equal(env.PATH, '/usr/bin');
    assert.equal(heartbeatEnvOff(env), true);
  });
});

describe('mcp-guard init, end to end', () => {
  it('fresh machine to first signed receipt, in well under ten minutes', async () => {
    const fake = await startFakePp(TOKEN);
    const machine = freshMachine();
    try {
      const run = await runCli(initArgs(fake, machine.mcpConfig), machine.env, machine.project);
      assert.equal(run.code, 0, `${run.stdout}\n${run.stderr}`);

      // What the person saw, in order.
      const out = run.stdout;
      // Progress first (the login and the self-test need the person), then what is guarded,
      // what happens next time, the commands worth knowing, how to undo, and the setup details.
      const order = ['Server: filesystem', `Open ${fake.url}/mcp/connect?code=ABCD-EFGH`, 'this code: ABCD-EFGH', 'Connected to workspace: Acme Eng (acme-eng)', 'Self-test: holding a do-nothing call', 'Sign it here: ', 'Self-test: ok. Signed receipt: rcpt_fake_', 'Guarded now:', 'MCP server "filesystem"', 'Next time, a call to "delete_file" on "filesystem" is held', 'Restart Claude Code', 'Worth knowing:', `Verify it: npx @permission-protocol/mcp-guard@${VERSION} receipt verify rcpt_fake_`, 'To undo:', 'Unwrap "filesystem": copy ', 'Set up:', 'Install token: stored in', 'Local signing key: created mcpg-', 'Hold rule: "delete_file" needs a signature', 'Policy: ', 'Wrapped "filesystem"', 'Time to first signed receipt: '];
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
      const printed = /Verify it: npx @permission-protocol\/mcp-guard@(\S+) (receipt verify \S+) --receipts-path "([^"]+)" --config "([^"]+)"/.exec(out)!;
      assert.equal(printed[1], VERSION, 'the printed command is pinned to the running version, not latest');
      const verify = [printed[0], printed[2], printed[3], printed[4]];
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
      // Start the server exactly as the client now would: the written command and args (npx is the stand-in running this build).
      const wrapped = JSON.parse(readFileSync(machine.mcpConfig, 'utf-8')).mcpServers.filesystem;
      assert.deepEqual(wrapped.args.slice(0, 2), ['-y', `@permission-protocol/mcp-guard@${VERSION}`]);
      const child = spawn(wrapped.command, wrapped.args, { env: { ...machine.env, ...wrapped.env }, stdio: ['pipe', 'pipe', 'pipe'] });
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

  it('the wrap launcher is checked before the login: an unstartable or wrong version is refused and nothing changes', async () => {
    const cases: Array<[string, string, RegExp]> = [
      ['unpublished', '#!/bin/sh\necho "npm error 404 Not Found - @permission-protocol/mcp-guard@x" >&2\nexit 1\n', /did not start mcp-guard \S+ \(exit 1\)/],
      ['other version', '#!/bin/sh\necho 0.3.1\n', /reported version "0\.3\.1", not /],
    ];
    for (const [name, script, problem] of cases) {
      const fake = await startFakePp(TOKEN);
      const machine = freshMachine();
      try {
        const bin = join(machine.root, `bad-npx-${name.replace(' ', '-')}`);
        mkdirSync(bin, { recursive: true });
        writeFileSync(join(bin, 'npx'), script);
        chmodSync(join(bin, 'npx'), 0o755);
        const before = readFileSync(machine.mcpConfig, 'utf-8');
        const run = await runCli(initArgs(fake, machine.mcpConfig), { ...machine.env, PATH: `${bin}:${machine.env.PATH}` }, machine.project);
        assert.equal(run.code, 1, name);
        assert.match(run.stderr, problem, name);
        assert.match(run.stderr, /Nothing was changed, and init stopped before the login/);
        assert.match(run.stderr, /--wrap-launcher/);
        assert.equal(readFileSync(machine.mcpConfig, 'utf-8'), before, 'client config untouched');
        assert.equal(readdirSync(machine.project).some((f) => f.includes('backup')), false);
        assert.equal(existsSync(join(machine.guardDir, 'install-token')), false);
        assert.equal(fake.calls.length, 0, 'no login was started');
      } finally { await fake.close(); }
    }
  });

  it('the probe ran the pinned launcher with --version and no PP_* variables', async () => {
    const fake = await startFakePp(TOKEN);
    const machine = freshMachine();
    try {
      const run = await runCli(initArgs(fake, machine.mcpConfig, ['--skip-self-test']), machine.env, machine.project);
      assert.equal(run.code, 0, run.stderr);
      assert.ok(run.stdout.includes(`Wrap launcher: npx -y @permission-protocol/mcp-guard@${VERSION} (checked: starts mcp-guard ${VERSION})`), run.stdout);
      assert.equal(readFileSync(machine.npxLog, 'utf-8').trim().split('\n')[0], `-y @permission-protocol/mcp-guard@${VERSION} --version`);
    } finally { await fake.close(); }
    // The probe's environment: a launcher that reports the version only when it sees no PP_* variable.
    const script = join(temp('probe'), 'launcher.js');
    writeFileSync(script, `console.log(Object.keys(process.env).some((k) => k.startsWith('PP_')) ? 'leak' : ${JSON.stringify(VERSION)});\n`);
    const saved = process.env.PP_INSTALL_TOKEN;
    process.env.PP_INSTALL_TOKEN = TOKEN;
    let leaked: string | null;
    try { leaked = probeWrapLauncher([process.execPath, script], VERSION); } finally { if (saved === undefined) delete process.env.PP_INSTALL_TOKEN; else process.env.PP_INSTALL_TOKEN = saved; }
    const tagged = { status: leaked === null ? 0 : 3 };
    assert.equal(tagged.status, 0, 'the probe environment carries no PP_* variable');
  });

  it('--wrap-launcher: checked the same way, written as given, detected as wrapped', async () => {
    const fake = await startFakePp(TOKEN);
    const machine = freshMachine();
    try {
      const launcher = `"${process.execPath}" "${BIN}"`;
      const run = await runCli(initArgs(fake, machine.mcpConfig, ['--skip-self-test', '--wrap-launcher', launcher]), machine.env, machine.project);
      assert.equal(run.code, 0, run.stderr);
      const wrapped = JSON.parse(readFileSync(machine.mcpConfig, 'utf-8')).mcpServers.filesystem;
      assert.equal(wrapped.command, process.execPath);
      assert.equal(wrapped.args[0], BIN);
      assert.equal(isWrapped(wrapped.command, wrapped.args), true);
      assert.equal(existsSync(machine.npxLog), false, 'npx was not used');
      const bad = await runCli(initArgs(fake, machine.mcpConfig, ['--wrap-launcher', '/nonexistent/mcp-guard']), freshMachine().env, machine.project);
      assert.equal(bad.code, 1);
    } finally { await fake.close(); }
    assert.deepEqual(splitLauncher('node "C:\\Program Files\\x\\bin\\mcp-guard"'), ['node', 'C:\\Program Files\\x\\bin\\mcp-guard']);
    assert.throws(() => splitLauncher('   '), /needs a command/);
    assert.deepEqual(wrapLauncher('9.9.9', undefined, 'win32'), ['cmd', '/c', 'npx', '-y', '@permission-protocol/mcp-guard@9.9.9']);
    assert.deepEqual(wrapLauncher('9.9.9', ['node', 'x/bin/mcp-guard'], 'win32'), ['node', 'x/bin/mcp-guard']);
    assert.equal(probeWrapLauncher(['/nonexistent/launcher'], '1.0.0')!.includes('could not be run (ENOENT)'), true);
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
      const order = ['Server: filesystem', 'Connected to workspace', 'Hook self-test (local, nothing sent): ok. "git status" got no decision; "terraform destroy -auto-approve" was stopped by rule "terraform-destroy"', 'Self-test: ok. Signed receipt: rcpt_fake_', 'Guarded now:', 'Claude Code in ', 'MCP server "filesystem"', 'Next time Claude Code tries something destructive here', 'Restart Claude Code so it starts "filesystem" through the guard and loads the hook.', 'Worth knowing:', `See what the guard decided: npx @permission-protocol/mcp-guard@${VERSION} report --config `, 'To undo:', `Remove the Claude Code hook: ${LAUNCHER} hook uninstall --project `, 'Set up:', 'Policy preset: coding-agent', 'Policy: ', 'Hook policy: ', 'Claude Code hook: installed in ', 'Wrapped "filesystem"', 'Time to first signed receipt: '];
      // One line per self-test: the per-check lines appear only when a check fails.
      assert.doesNotMatch(out, /ok   allowed: Bash/);
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

  it('running it again is safe: per item, no second entry, a kept policy, exit 0 when all is in place', async () => {
    const fake = await startFakePp(TOKEN);
    const machine = claudeProject();
    try {
      assert.equal((await runCli(presetArgs(fake, machine.mcpConfig, ['--skip-self-test']), machine.env, machine.project)).code, 0);
      const policyFile = join(machine.project, 'pp.config.yaml');
      const files = [policyFile, settingsPath(machine.project), machine.mcpConfig];
      const snapshot = () => files.map((f) => readFileSync(f, 'utf-8'));
      const before = snapshot();
      const calls = fake.calls.length;

      // Everything is in place: nothing to do, no new login, exit 0.
      const again = await runCli(presetArgs(fake, machine.mcpConfig, ['--skip-self-test']), machine.env, machine.project);
      assert.equal(again.code, 0, again.stderr);
      assert.match(again.stdout, /Install token: already stored on this machine; not logging in again/);
      assert.match(again.stdout, /Claude Code hook: already installed/);
      assert.match(again.stdout, /Already set up: .*nothing was changed/);
      assert.deepEqual(snapshot(), before);
      assert.equal(fake.calls.length, calls);

      // The person edited the preset (added a target): re-running keeps it byte for byte.
      const edited = before[0].replace('databases: []', 'databases: [prod-db.internal]');
      writeFileSync(policyFile, edited);
      const kept = await runCli(presetArgs(fake, machine.mcpConfig, ['--skip-self-test']), machine.env, machine.project);
      assert.equal(kept.code, 0, kept.stderr);
      assert.match(kept.stdout, /your own policy, kept byte for byte/);
      assert.match(kept.stdout, /Hook self-test \(local, nothing sent\): ok\. "git status" got no decision; "terraform destroy -auto-approve" was stopped/);
      assert.equal(readFileSync(policyFile, 'utf-8'), edited);
      assert.equal(fake.calls.length, calls);

      // Hook removed: init puts it back, once, and leaves the edited policy alone.
      spawnSync(process.execPath, [CLI, 'hook', 'uninstall', '--project', machine.project], { env: machine.env });
      const restored = await runCli(presetArgs(fake, machine.mcpConfig, ['--skip-self-test']), machine.env, machine.project);
      assert.equal(restored.code, 0, `${restored.stdout}\n${restored.stderr}`);
      assert.match(restored.stdout, /every one found is already wrapped; setting up the Claude Code hook only/);
      assert.match(restored.stdout, /Claude Code hook: installed/);
      assert.equal(readFileSync(policyFile, 'utf-8'), edited);
      assert.equal(ourEntries(machine.project), 1);
      assert.equal(readFileSync(machine.mcpConfig, 'utf-8'), before[2]);
      assert.equal(fake.calls.length, calls);
    } finally { await fake.close(); }
  });

  it('teammate with the committed policy and settings, but no token: logs in, creates a key, changes neither file', async () => {
    const fake = await startFakePp(TOKEN);
    const machine = claudeProject({ remote: { url: 'https://example.test/mcp' } });
    try {
      const policyFile = join(machine.project, 'pp.config.yaml');
      // What a teammate committed: an edited preset, and the hook entry for this launcher.
      const committed = policyText({ serverLabel: 'claude-code', tool: null, environment: 'production', apiUrl: fake.url, trustKeys: [{ key_id: fake.issuer.keyId, alg: 'ed25519', public_key_b64: fake.issuer.publicKeyB64 }], preset: 'coding-agent' }).replace('git_branches: []', 'git_branches: [release]');
      writeFileSync(policyFile, committed);
      const install = spawnSync(process.execPath, [CLI, 'hook', 'install', '--project', machine.project, '--launcher', LAUNCHER], { env: machine.env, encoding: 'utf-8' });
      assert.equal(install.status, 0, install.stderr);
      const settings = readFileSync(settingsPath(machine.project), 'utf-8');

      const run = await runCli(presetArgs(fake, machine.mcpConfig, ['--skip-self-test']), machine.env, machine.project);
      assert.equal(run.code, 0, `${run.stdout}\n${run.stderr}`);
      assert.match(run.stdout, /Connected to workspace: Acme Eng/);
      assert.match(run.stdout, /Local signing key: created/);
      assert.match(run.stdout, /your own policy, kept byte for byte/);
      assert.match(run.stdout, /Claude Code hook: already installed/);
      assert.doesNotMatch(run.stdout, /Already set up/);
      assert.equal(readFileSync(policyFile, 'utf-8'), committed);
      assert.equal(readFileSync(settingsPath(machine.project), 'utf-8'), settings);
      assert.equal(readFileSync(join(machine.guardDir, 'install-token'), 'utf-8').trim(), TOKEN);
      assert.equal(`${run.stdout}${run.stderr}`.includes(TOKEN), false);
    } finally { await fake.close(); }
  });

  it('an existing policy that does not load is refused with the loader\'s message, before login, nothing changed', async () => {
    const fake = await startFakePp(TOKEN);
    const machine = claudeProject();
    try {
      const policyFile = join(machine.project, 'pp.config.yaml');
      writeFileSync(policyFile, 'default_action: allow\nfail_open: true\n');
      const mcpBefore = readFileSync(machine.mcpConfig, 'utf-8');
      const run = await runCli(presetArgs(fake, machine.mcpConfig), machine.env, machine.project);
      assert.equal(run.code, 1);
      assert.match(run.stderr, /pp\.config\.yaml exists but does not load: .*fail_open.*init never overwrites a policy/);
      assert.equal(readFileSync(policyFile, 'utf-8'), 'default_action: allow\nfail_open: true\n');
      assert.equal(existsSync(settingsPath(machine.project)), false);
      assert.equal(readFileSync(machine.mcpConfig, 'utf-8'), mcpBefore);
      assert.equal(fake.calls.length, 0);
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
      assert.equal(plain.code, 1, 'no hook and no server: refused, and the hook is not installed unasked');
      assert.match(plain.stderr, /No Claude Code project was found in .* and no MCP server to wrap/);
      assert.match(plain.stderr, /To guard Claude Code's own tools \(shell, file edits\) in this directory: run init again with --hook claude-code/);
      assert.match(plain.stderr, /To guard an MCP server: add one to Claude Code or Cursor/);
      assert.equal(existsSync(settingsPath(machine.project)), false);
      assert.equal(existsSync(join(machine.project, 'pp.config.yaml')), false);
      assert.equal(fake.calls.length, 0);

      const run = await runCli(presetArgs(fake, machine.mcpConfig, ['--hook', 'claude-code', '--skip-self-test']), machine.env, machine.project);
      assert.equal(run.code, 0, `${run.stdout}\n${run.stderr}`);
      assert.match(run.stdout, /MCP servers: none found to wrap; setting up the Claude Code hook only/);
      assert.match(run.stdout, /"terraform destroy -auto-approve" was stopped by rule "terraform-destroy"/);
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

  describe('the default launcher', () => {
    const noLauncher = (fake: FakePp, mcpConfig: string, extra: string[]) => {
      const args = presetArgs(fake, mcpConfig, extra);
      args.splice(args.indexOf('--launcher'), 2);
      return args;
    };

    it('not installed in the project: npx -y with the exact running version, pinned in settings; uninstall finds it', async () => {
      const fake = await startFakePp(TOKEN);
      const machine = claudeProject({ remote: { url: 'https://example.test/mcp' } });
      const npx = fakeNpx(machine.root);
      try {
        const env = { ...machine.env, ...npx.env };
        const run = await runCli(noLauncher(fake, machine.mcpConfig, ['--skip-self-test']), env, machine.project);
        assert.equal(run.code, 0, `${run.stdout}\n${run.stderr}`);
        const pinned = `npx -y @permission-protocol/mcp-guard@${VERSION}`;
        assert.match(VERSION, /^\d+\.\d+\.\d+/);
        assert.ok(run.stdout.includes(`Launcher: ${pinned} (@permission-protocol/mcp-guard is not installed in this project`), run.stdout);
        const handler = JSON.parse(readFileSync(settingsPath(machine.project), 'utf-8')).hooks.PreToolUse[0].hooks[0];
        assert.ok(handler.command.startsWith(`${pinned} hook --config `), handler.command);
        assert.ok(run.stdout.includes(`Remove the Claude Code hook: ${pinned} hook uninstall --project ${machine.project}`), 'the undo hint runs the resolved launcher, not a bare npx mcp-guard');
        assert.match(run.stdout, /Hook self-test \(local, nothing sent\): ok\. "git status" got no decision; "terraform destroy -auto-approve" was stopped/);
        // The probe and both self-test runs went through the stand-in, with the pinned spec.
        const calls = readFileSync(npx.log, 'utf-8').trim().split('\n');
        assert.ok(calls.length >= 3);
        for (const line of calls) assert.ok(line.startsWith(`-y @permission-protocol/mcp-guard@${VERSION} hook`), line);
        // Re-running resolves the same launcher: nothing changes.
        const again = await runCli(noLauncher(fake, machine.mcpConfig, ['--skip-self-test']), env, machine.project);
        assert.equal(again.code, 0, again.stderr);
        assert.match(again.stdout, /Already set up/);
        assert.equal(ourEntries(machine.project), 1);
        const removed = spawnSync(process.execPath, [CLI, 'hook', 'uninstall', '--project', machine.project], { env, encoding: 'utf-8' });
        assert.match(removed.stdout, /removed 1 mcp-guard PreToolUse hook/);
      } finally { await fake.close(); }
    });

    it('installed in the project: npx --no-install mcp-guard', async () => {
      const fake = await startFakePp(TOKEN);
      const machine = claudeProject({ remote: { url: 'https://example.test/mcp' } });
      const npx = fakeNpx(machine.root);
      try {
        const pkg = join(machine.project, 'node_modules', '@permission-protocol', 'mcp-guard');
        mkdirSync(pkg, { recursive: true });
        writeFileSync(join(pkg, 'package.json'), JSON.stringify({ name: '@permission-protocol/mcp-guard', version: VERSION }));
        const run = await runCli(noLauncher(fake, machine.mcpConfig, ['--skip-self-test']), { ...machine.env, ...npx.env }, machine.project);
        assert.equal(run.code, 0, `${run.stdout}\n${run.stderr}`);
        assert.ok(run.stdout.includes(`Launcher: npx --no-install mcp-guard (@permission-protocol/mcp-guard is installed in ${machine.project})`), run.stdout);
        const handler = JSON.parse(readFileSync(settingsPath(machine.project), 'utf-8')).hooks.PreToolUse[0].hooks[0];
        assert.ok(handler.command.startsWith('npx --no-install mcp-guard hook --config '));
      } finally { await fake.close(); }
    });

    it('a launcher that cannot be started (offline, unpublished version) is refused before anything changes', async () => {
      const fake = await startFakePp(TOKEN);
      const machine = claudeProject({ remote: { url: 'https://example.test/mcp' } });
      try {
        const bin = join(machine.root, 'failing-bin');
        mkdirSync(bin, { recursive: true });
        writeFileSync(join(bin, 'npx'), '#!/bin/sh\necho "npm error 404 Not Found" >&2\nexit 1\n');
        chmodSync(join(bin, 'npx'), 0o755);
        const run = await runCli(noLauncher(fake, machine.mcpConfig, []), { ...machine.env, PATH: `${bin}:${process.env.PATH}` }, machine.project);
        assert.equal(run.code, 1);
        assert.match(run.stderr, /did not start mcp-guard .*check the network/);
        assert.equal(existsSync(settingsPath(machine.project)), false);
        assert.equal(existsSync(join(machine.project, 'pp.config.yaml')), false);
        assert.equal(fake.calls.length, 0);
      } finally { await fake.close(); }
    });
  });
});
