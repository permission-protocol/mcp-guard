import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, win32 } from 'node:path';
import { hookHandler, isAbsoluteConfigPath, SettingsError } from '../hook/install.js';
import { claudeCodeVersionNote, findPosixShell, noShellMessage, runHookSelfTest } from '../init/hook-setup.js';
import { runInit, undoHook, type InitIo } from '../init/init.js';
import { parseConfig } from '../config.js';
import { codingAgentPolicyBody } from '../presets/coding-agent.js';
import { createKey } from '../keystore.js';

/**
 * Windows: the hook command's --config for drive-letter and UNC paths (the self-test's
 * temporary policy was appended to the project directory), Git Bash lookup, the old
 * Claude Code note, and the undo hint. Nothing here runs on real Windows: paths use
 * path.win32 rules and the shell is this machine's sh, as Git Bash would run it.
 */

const temp = (name: string) => mkdtempSync(join(tmpdir(), `mcp-guard-${name}-`));
const BIN = join(__dirname, '..', '..', '..', 'bin', 'mcp-guard');
const LAUNCHER = `${process.execPath} ${BIN}`;

describe('hook --config: absolute paths for the target platform', () => {
  it('win32: drive-letter and UNC paths are absolute; relative and POSIX rules unchanged', () => {
    for (const p of ['C:\\Users\\rodri\\AppData\\Local\\Temp\\mcp-guard-hook-self-test-M5Yy2Y\\pp.config.yaml', 'C:/Users/x/pp.config.yaml', 'd:\\pp.yaml', '\\\\server\\share\\pp.config.yaml', '//server/share/pp.yaml']) {
      assert.equal(isAbsoluteConfigPath(p, 'win32'), true, p);
      assert.equal(win32.isAbsolute(p), true, p);
    }
    for (const p of ['pp.config.yaml', 'sub\\pp.config.yaml', 'sub/pp.config.yaml', '.\\pp.yaml']) assert.equal(isAbsoluteConfigPath(p, 'win32'), false, p);
    assert.throws(() => isAbsoluteConfigPath('C:pp.yaml', 'win32'), SettingsError, 'drive-relative is refused, not guessed');
    assert.equal(isAbsoluteConfigPath('/etc/pp.yaml', 'linux'), true);
    assert.equal(isAbsoluteConfigPath('C:\\x\\pp.yaml', 'linux'), false, 'POSIX unchanged');
    assert.equal(isAbsoluteConfigPath('pp.config.yaml', 'darwin'), false);
  });

  it('the command uses an absolute Windows path as given, never joined to the project directory', () => {
    const tempPolicy = 'C:\\Users\\rodri\\AppData\\Local\\Temp\\mcp-guard-hook-self-test-M5Yy2Y\\pp.config.yaml';
    const abs = hookHandler({ projectDir: 'C:\\Users\\rodri\\proj', launcher: 'npx -y @permission-protocol/mcp-guard@0.5.2', configPath: tempPolicy, waitSeconds: 0, platform: 'win32' }).command;
    assert.ok(abs.startsWith(`npx -y @permission-protocol/mcp-guard@0.5.2 hook --config '${tempPolicy}' --wait 0;`), abs);
    assert.equal(abs.includes('CLAUDE_PROJECT_DIR'), false);
    const unc = hookHandler({ projectDir: 'C:\\p', launcher: 'npx mcp-guard', configPath: '\\\\fs01\\team\\pp.config.yaml', platform: 'win32' }).command;
    assert.ok(unc.includes(`--config '\\\\fs01\\team\\pp.config.yaml'`), unc);
    const rel = hookHandler({ projectDir: 'C:\\p', launcher: 'npx mcp-guard', platform: 'win32' }).command;
    assert.ok(rel.includes('--config "${CLAUDE_PROJECT_DIR}"/pp.config.yaml'), rel);
    // The same call on POSIX is what it always was.
    assert.equal(
      hookHandler({ projectDir: '/p', launcher: 'npx mcp-guard', configPath: '/tmp/x/pp.config.yaml', platform: 'linux' }).command,
      hookHandler({ projectDir: '/p', launcher: 'npx mcp-guard', configPath: '/tmp/x/pp.config.yaml' }).command,
    );
  });

  it('through sh -c (as Git Bash runs it), the guard receives the Windows path exactly', () => {
    const dir = temp('winpath');
    // A stand-in launcher whose name contains mcp-guard: prints the arguments it received.
    const script = join(dir, 'print-args-mcp-guard.js');
    writeFileSync(script, 'process.stdout.write(JSON.stringify(process.argv.slice(2)));\n');
    const launcher = `${process.execPath} ${script}`;
    const cases: Array<[string, string]> = [
      ["C:\\Users\\Rod O'Neil\\AppData\\Local\\Temp\\mcp-guard-hook-self-test-M5Yy2Y\\pp.config.yaml", "C:\\Users\\Rod O'Neil\\AppData\\Local\\Temp\\mcp-guard-hook-self-test-M5Yy2Y\\pp.config.yaml"],
      ['\\\\fs01\\team share\\pp.config.yaml', '\\\\fs01\\team share\\pp.config.yaml'],
      ['C:/Program Files/x/$HOME/pp.yaml', 'C:/Program Files/x/$HOME/pp.yaml'],
      ['pp.config.yaml', 'C:\\Users\\rodri\\my proj/pp.config.yaml'],
    ];
    for (const [config, expected] of cases) {
      const command = hookHandler({ projectDir: 'C:\\Users\\rodri\\my proj', launcher, configPath: config, waitSeconds: 0, platform: 'win32' }).command;
      const r = spawnSync('sh', ['-c', command], { encoding: 'utf8', env: { ...process.env, CLAUDE_PROJECT_DIR: 'C:\\Users\\rodri\\my proj' } });
      assert.equal(r.status, 0, r.stderr);
      const args: string[] = JSON.parse(r.stdout);
      assert.deepEqual(args, ['hook', '--config', expected, '--wait', '0'], config);
    }
  });
});

describe('hook self-test: could not run vs the installed hook does not work', () => {
  const policy = parseConfig(codingAgentPolicyBody());
  const localPolicy = codingAgentPolicyBody().trimEnd() + '\nserver_label: "claude-code"\n';

  function project(launcher: string): string {
    const dir = temp('selftest');
    mkdirSync(join(dir, '.claude'), { recursive: true });
    writeFileSync(join(dir, '.claude', 'settings.json'), JSON.stringify({ hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [hookHandler({ projectDir: dir, launcher })] }] } }));
    writeFileSync(join(dir, 'pp.config.yaml'), localPolicy);
    createKey({ dir: join(dir, 'keys') });
    return dir;
  }

  it('passes with this build', () => {
    const dir = project(LAUNCHER);
    const r = runHookSelfTest({ projectDir: dir, launcher: LAUNCHER, policy, localPolicy, receiptsPath: join(dir, 'self.jsonl'), env: { ...process.env, PP_KEYS_DIR: join(dir, 'keys') } });
    assert.equal(r.ok, true, JSON.stringify(r));
  });

  it('no shell: could_not_run', () => {
    const dir = project(LAUNCHER);
    const r = runHookSelfTest({ projectDir: dir, launcher: LAUNCHER, policy, localPolicy, receiptsPath: join(dir, 'self.jsonl'), shell: join(dir, 'no-such-bash.exe'), env: { ...process.env, PP_KEYS_DIR: join(dir, 'keys') } });
    assert.equal(r.ok, false);
    assert.equal(r.failure, 'could_not_run');
  });

  it("the test's own policy does not load: could_not_run, not a verdict on the hook", () => {
    const dir = project(LAUNCHER);
    const r = runHookSelfTest({ projectDir: dir, launcher: LAUNCHER, policy, localPolicy: 'not: [valid', receiptsPath: join(dir, 'self.jsonl'), env: { ...process.env, PP_KEYS_DIR: join(dir, 'keys') } });
    assert.equal(r.ok, false);
    assert.equal(r.failure, 'could_not_run');
    assert.match(r.reason!, /temporary policy/);
  });

  it('a hook that answers wrongly: hook_failed', () => {
    const dir = temp('selftest-bad');
    const script = join(dir, 'deny-all-mcp-guard.js');
    writeFileSync(script, 'process.stderr.write("nope\\n"); process.exit(2);\n');
    const launcher = `${process.execPath} ${script}`;
    const p = project(launcher);
    const r = runHookSelfTest({ projectDir: p, launcher, policy, localPolicy, receiptsPath: join(p, 'self.jsonl') });
    assert.equal(r.ok, false);
    assert.equal(r.failure, 'hook_failed');
  });
});

describe('Git Bash lookup on Windows', () => {
  const fs = (...files: string[]) => (p: string) => files.includes(p);

  it('POSIX: sh, nothing probed', () => {
    assert.deepEqual(findPosixShell({ platform: 'linux', isFile: () => { throw new Error('not probed'); } }), { shell: 'sh', source: 'sh on PATH' });
  });

  it('CLAUDE_CODE_GIT_BASH_PATH first, if it names a file', () => {
    const bash = 'D:\\Tools\\Git\\bin\\bash.exe';
    assert.deepEqual(findPosixShell({ platform: 'win32', env: { CLAUDE_CODE_GIT_BASH_PATH: bash, PATH: 'C:\\Git\\usr\\bin', ProgramFiles: 'C:\\Program Files' }, isFile: fs(bash, 'C:\\Git\\usr\\bin\\sh.exe') }), { shell: bash, source: 'CLAUDE_CODE_GIT_BASH_PATH' });
  });

  it('then sh.exe / bash.exe on PATH, skipping WSL bash in System32', () => {
    const env = { Path: 'C:\\Windows\\System32;C:\\Program Files\\Git\\usr\\bin', ProgramFiles: 'C:\\Program Files' };
    assert.deepEqual(findPosixShell({ platform: 'win32', env, isFile: fs('C:\\Windows\\System32\\bash.exe', 'C:\\Program Files\\Git\\usr\\bin\\sh.exe') }), { shell: 'C:\\Program Files\\Git\\usr\\bin\\sh.exe', source: 'sh.exe on PATH' });
    assert.equal(findPosixShell({ platform: 'win32', env: { PATH: 'C:\\Windows\\System32' }, isFile: fs('C:\\Windows\\System32\\bash.exe') }).shell, null);
  });

  it('then the standard Git for Windows places', () => {
    assert.equal(findPosixShell({ platform: 'win32', env: { PATH: '', ProgramFiles: 'C:\\Program Files' }, isFile: fs('C:\\Program Files\\Git\\bin\\bash.exe') }).shell, 'C:\\Program Files\\Git\\bin\\bash.exe');
    assert.equal(findPosixShell({ platform: 'win32', env: { 'ProgramFiles(x86)': 'C:\\Program Files (x86)' }, isFile: fs('C:\\Program Files (x86)\\Git\\bin\\bash.exe') }).shell, 'C:\\Program Files (x86)\\Git\\bin\\bash.exe');
    assert.equal(findPosixShell({ platform: 'win32', env: { LOCALAPPDATA: 'C:\\Users\\rodri\\AppData\\Local' }, isFile: fs('C:\\Users\\rodri\\AppData\\Local\\Programs\\Git\\bin\\bash.exe') }).shell, 'C:\\Users\\rodri\\AppData\\Local\\Programs\\Git\\bin\\bash.exe');
  });

  it('then beside git.exe on PATH', () => {
    const r = findPosixShell({ platform: 'win32', env: { PATH: 'E:\\PortableGit\\cmd' }, isFile: fs('E:\\PortableGit\\cmd\\git.exe', 'E:\\PortableGit\\bin\\bash.exe') });
    assert.deepEqual(r, { shell: 'E:\\PortableGit\\bin\\bash.exe', source: 'beside E:\\PortableGit\\cmd\\git.exe' });
  });

  it('none found: the refusal says where it looked', () => {
    const r = findPosixShell({ platform: 'win32', env: { PATH: 'C:\\x', ProgramFiles: 'C:\\Program Files', CLAUDE_CODE_GIT_BASH_PATH: 'C:\\missing\\bash.exe' }, isFile: () => false });
    assert.equal(r.shell, null);
    const message = noShellMessage(r as { looked: string[] });
    for (const piece of ['C:\\missing\\bash.exe', 'sh.exe and bash.exe on PATH', 'C:\\Program Files\\Git\\bin\\bash.exe', 'git.exe', 'CLAUDE_CODE_GIT_BASH_PATH', '--no-hook']) assert.ok(message.includes(piece), piece);
  });

  it('init refuses the hook step before anything changes when there is no Git Bash', async () => {
    const dir = temp('noshell');
    mkdirSync(join(dir, '.claude'));
    const out: string[] = [];
    const io: InitIo = { out: (l) => out.push(l), err: (l) => out.push(l), ask: async () => '', openBrowser: () => undefined, interactive: false };
    const code = await runInit(['--preset', 'coding-agent', '--project', dir, '--launcher', LAUNCHER, '--yes', '--no-browser'], io, {
      cwd: dir, home: dir, shellLookup: { platform: 'win32', env: { PATH: 'C:\\x' }, isFile: () => false },
    });
    assert.equal(code, 1);
    assert.match(out.join('\n'), /Git Bash was not found .*init stopped before changing anything/);
    assert.equal(existsSync(join(dir, 'pp.config.yaml')), false);
    assert.equal(existsSync(join(dir, '.claude', 'settings.json')), false);
  });
});

describe('Claude Code older than 2.1.295, and the undo hint', () => {
  it('one line for an older version; nothing for newer, unreadable or failing', () => {
    assert.match(claudeCodeVersionNote(() => '2.1.86 (Claude Code)\n')!, /^Note: Claude Code 2\.1\.86 is older than 2\.1\.295/);
    assert.match(claudeCodeVersionNote(() => '1.9.999')!, /older/);
    for (const v of ['2.1.295 (Claude Code)', '2.1.323', '2.2.0', '3.0.0']) assert.equal(claudeCodeVersionNote(() => v), null, v);
    assert.equal(claudeCodeVersionNote(() => null), null);
    assert.equal(claudeCodeVersionNote(() => 'garbage'), null);
    assert.equal(claudeCodeVersionNote(() => { throw new Error('ENOENT'); }), null);
  });

  it('the undo command uses the launcher the hook was installed with', () => {
    assert.equal(undoHook('npx -y @permission-protocol/mcp-guard@0.5.2', 'C:\\Users\\rodri\\proj'), 'npx -y @permission-protocol/mcp-guard@0.5.2 hook uninstall --project C:\\Users\\rodri\\proj');
    assert.equal(undoHook('npx --no-install mcp-guard', '/home/a/my proj'), 'npx --no-install mcp-guard hook uninstall --project "/home/a/my proj"');
  });
});
