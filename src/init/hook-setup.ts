import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, win32 } from 'node:path';
import { TOOLS_CALL, type Config } from '../config.js';
import { evaluate } from '../engine.js';
import { DEFAULT_LAUNCHER, hookHandler, settingsPath } from '../hook/install.js';

/**
 * The coding-agent half of `mcp-guard init`: where the hook's policy lives, whether a
 * directory is a Claude Code project, a launcher probe, and a local self-test of the
 * installed hook. Installing the hook itself is `installHook` (hook/install.ts).
 */

/** The hook's policy, at the project root, where `hook install` points by default. */
export const HOOK_POLICY_FILE = 'pp.config.yaml';
export const HOOK_AGENTS = ['claude-code'] as const;
export type HookAgent = (typeof HOOK_AGENTS)[number];

/** A Claude Code project: it has a `.claude/` directory or a `CLAUDE.md` at its root. */
export function isClaudeCodeProject(dir: string): boolean {
  return existsSync(join(dir, '.claude')) || existsSync(join(dir, 'CLAUDE.md'));
}

export const PACKAGE_NAME = '@permission-protocol/mcp-guard';
const EXACT_VERSION = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;

/** Is the package installed in `dir` or a directory above it (where `npx --no-install` finds it)? Returns that directory. */
export function localInstallDir(dir: string): string | null {
  for (let at = dir; ; at = dirname(at)) {
    if (existsSync(join(at, 'node_modules', ...PACKAGE_NAME.split('/'), 'package.json'))) return at;
    if (dirname(at) === at) return null;
  }
}

export interface LauncherChoice {
  launcher: string;
  why: string;
}

/**
 * How the installed hook starts the guard, in this order: `--launcher`; the project's own
 * install (`npx --no-install mcp-guard`); else this exact version through npx, pinned in
 * the settings file (never a range or `latest`).
 */
export function chooseLauncher(projectDir: string, explicit: string | undefined, version: string): LauncherChoice {
  if (explicit !== undefined) return { launcher: explicit, why: 'given with --launcher' };
  const local = localInstallDir(projectDir);
  if (local) return { launcher: DEFAULT_LAUNCHER, why: `${PACKAGE_NAME} is installed in ${local}` };
  if (!EXACT_VERSION.test(version)) throw new Error(`the running package version "${version}" is not an exact version; pass --launcher`);
  return {
    launcher: `npx -y ${PACKAGE_NAME}@${version}`,
    why: `${PACKAGE_NAME} is not installed in this project, so the hook runs this exact version through npx (downloaded on the first guarded call, then from npx's cache)`,
  };
}

/** Harmless Bash commands, tried in order, for the self-test's allowed call. */
const HARMLESS = ['git status', 'ls', 'pwd'];

/** The first harmless command this policy allows outright, or null. Evaluated in-process: never sent anywhere. */
export function harmlessAllowedCommand(config: Config): string | null {
  return HARMLESS.find((command) => evaluate('Bash', { command }, config, TOOLS_CALL).decision === 'allowed') ?? null;
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** The POSIX shell init runs the hook command with, as Claude Code will: `sh` on macOS and Linux, Git Bash on Windows. */
export type ShellLookup = { shell: string; source: string } | { shell: null; looked: string[] };

export interface ShellLookupDeps {
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  /** Is there a file at this path? (tests inject a fake filesystem) */
  isFile?: (path: string) => boolean;
}

const fileExists = (path: string): boolean => {
  try { return statSync(path).isFile(); } catch { return false; }
};

/**
 * Find the shell for the launcher probe and the hook self-test. On macOS and Linux:
 * `sh`. On Windows, Claude Code runs shell-form hooks through Git Bash even when Git
 * for Windows' `bin` is not on PATH, so init looks where Git Bash is, in this order:
 *
 *   1. CLAUDE_CODE_GIT_BASH_PATH, the override Claude Code documents for this
 *      (https://code.claude.com/docs/en/setup), if it names a file;
 *   2. `sh.exe` or `bash.exe` on PATH (never `C:\Windows\System32\bash.exe`, which is WSL);
 *   3. Git for Windows' standard places: `Git\bin\bash.exe` under ProgramFiles,
 *      ProgramFiles(x86) and LocalAppData\Programs;
 *   4. beside `git.exe` on PATH (`Git\cmd\git.exe` -> `Git\bin\bash.exe`).
 *
 * Nothing is run: only file paths are checked. None found: `looked` lists every place.
 */
export function findPosixShell(deps: ShellLookupDeps = {}): ShellLookup {
  const platform = deps.platform ?? process.platform;
  if (platform !== 'win32') return { shell: 'sh', source: 'sh on PATH' };
  const env = deps.env ?? process.env;
  const isFile = deps.isFile ?? fileExists;
  const get = (name: string): string | undefined => {
    const key = Object.keys(env).find((k) => k.toLowerCase() === name.toLowerCase());
    const value = key ? env[key] : undefined;
    return value && value.trim() ? value.trim() : undefined;
  };
  const looked: string[] = [];
  const tryAt = (path: string, source: string): ShellLookup | null => {
    looked.push(path);
    return isFile(path) ? { shell: path, source } : null;
  };

  const override = get('CLAUDE_CODE_GIT_BASH_PATH');
  if (override) {
    const hit = tryAt(override, 'CLAUDE_CODE_GIT_BASH_PATH');
    if (hit) return hit;
  } else {
    looked.push('CLAUDE_CODE_GIT_BASH_PATH (not set)');
  }

  const pathDirs = (get('PATH') ?? '').split(';').map((d) => d.trim().replace(/^"(.*)"$/, '$1')).filter(Boolean);
  const isWsl = (dir: string): boolean => /[\\/]windows[\\/](system32|sysnative)[\\/]?$/i.test(dir);
  for (const dir of pathDirs) {
    if (isWsl(dir)) continue;
    for (const name of ['sh.exe', 'bash.exe']) {
      const path = win32.join(dir, name);
      if (isFile(path)) return { shell: path, source: `${name} on PATH` };
    }
  }
  looked.push('sh.exe and bash.exe on PATH');

  for (const base of [get('ProgramFiles'), get('ProgramW6432'), get('ProgramFiles(x86)'), get('LocalAppData') && win32.join(get('LocalAppData')!, 'Programs')]) {
    if (!base) continue;
    const hit = tryAt(win32.join(base, 'Git', 'bin', 'bash.exe'), 'Git for Windows');
    if (hit) return hit;
  }

  for (const dir of pathDirs) {
    if (!isFile(win32.join(dir, 'git.exe'))) continue;
    // git.exe lives in Git\cmd, Git\bin or Git\mingw64\bin; Git Bash in Git\bin.
    for (const up of [['..', 'bin'], [], ['..', '..', 'bin']]) {
      const hit = tryAt(win32.resolve(dir, ...up, 'bash.exe'), `beside ${win32.join(dir, 'git.exe')}`);
      if (hit) return hit;
    }
  }
  if (!looked.some((l) => l.startsWith('beside'))) looked.push('beside git.exe on PATH (git not found)');
  return { shell: null, looked: [...new Set(looked)] };
}

/** What init says when it found no shell on Windows. */
export function noShellMessage(lookup: { looked: string[] }): string {
  return `Git Bash was not found (looked at: ${lookup.looked.join('; ')}). The Claude Code hook runs through Git Bash on Windows: install Git for Windows (https://git-scm.com/downloads/win), or set CLAUDE_CODE_GIT_BASH_PATH to its bash.exe, then run init again. Or pass --no-hook`;
}

/**
 * Can the launcher start mcp-guard from the project directory, the way Claude Code
 * will? Runs `<launcher> hook --help` under `<shell> -c`. Returns null when it can, else
 * what went wrong (fixed text and an exit code; the launcher is the person's own input).
 */
export function probeLauncher(projectDir: string, launcher: string = DEFAULT_LAUNCHER, shell: string = 'sh'): string | null {
  const run = spawnSync(shell, ['-c', `${launcher} hook --help`], { cwd: projectDir, encoding: 'utf8', timeout: 60_000, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  if (run.error) return `could not run ${shell} to start "${launcher}" (${(run.error as NodeJS.ErrnoException).code ?? run.error.name})`;
  if (run.status === 0 && /mcp-guard hook/.test(run.stdout)) return null;
  return `"${launcher}" did not start mcp-guard from ${projectDir} (exit ${run.status ?? run.signal})`;
}

export interface HookCheck {
  name: string;
  /** The synthetic event's command: fixed text written here, never the person's input. */
  command: string;
  expected: 'pass' | 'deny';
  ok: boolean;
  /** What the hook answered, in words. */
  detail: string;
}

export interface HookSelfTestResult {
  ok: boolean;
  checks: HookCheck[];
  reason: string | null;
  /**
   * When not ok: `could_not_run` means the test itself could not be carried out (no shell,
   * its temporary policy not written or not loaded), which says nothing about the installed
   * hook; `hook_failed` means the installed hook gave a wrong answer.
   */
  failure?: 'could_not_run' | 'hook_failed';
}

/** Held by the coding-agent preset's `terraform-destroy` rule. Never run: the hook only decides. */
export const SELF_TEST_DESTRUCTIVE = 'terraform destroy -auto-approve';
const EXPECTED_HOLD_RULE = 'terraform-destroy';

const event = (command: string): string =>
  JSON.stringify({ session_id: 'mcp-guard-init-self-test', cwd: '/', permission_mode: 'default', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, tool_use_id: 'toolu_mcp_guard_self_test' });

/** The first line of what the hook said, bounded. The events are ours, so it holds no user input. */
const firstLine = (text: string | null | undefined): string => ((text ?? '').trim().split('\n')[0] ?? '').slice(0, 300) || 'no output';

/**
 * Prove the installed hook works, locally and with nothing sent to Permission Protocol:
 *
 *   1. the command exactly as installed in .claude/settings.json, with a harmless `Bash`
 *      event that the project's policy allows (checked in-process first; an allowed call
 *      touches no network, decide.ts): the answer must be "no decision" (exit 0, empty
 *      stdout). If the policy allows none of the harmless commands, this run is skipped
 *      rather than risk a held call opening a request; the launcher was probed already.
 *   2. the same launcher and the same hook code with a destructive `Bash` event, against
 *      a copy of the preset's rules with no `cloud:` section (not the person's policy,
 *      whose rule ids it cannot assume): the hold is answered `deny` locally instead of
 *      opening a signing request. The answer must be a deny naming the hold rule.
 *
 * Receipts go to the self-test log (`receiptsPath`), not the project's log.
 */
export function runHookSelfTest(input: { projectDir: string; launcher?: string; policy: Config; localPolicy: string; receiptsPath: string; env?: NodeJS.ProcessEnv; shell?: string; platform?: NodeJS.Platform }): HookSelfTestResult {
  const checks: HookCheck[] = [];
  // The self-test says nothing is sent to Permission Protocol: that includes the usage
  // heartbeat, which a hook run could otherwise start when a send is due.
  const env: NodeJS.ProcessEnv = { ...(input.env ?? process.env), CLAUDE_PROJECT_DIR: input.projectDir, PP_SHARED_RECEIPTS_PATH: input.receiptsPath, MCP_GUARD_HEARTBEAT: 'off' };
  const fail = (reason: string, failure: 'could_not_run' | 'hook_failed' = 'hook_failed'): HookSelfTestResult => ({ ok: false, checks, reason, failure });
  const shell = input.shell ?? 'sh';

  // The command Claude Code will run, read back from the settings file.
  const expected = hookHandler({ projectDir: input.projectDir, launcher: input.launcher, platform: input.platform }).command;
  let installed: string | null = null;
  try {
    const settings = JSON.parse(readFileSync(settingsPath(input.projectDir), 'utf8'));
    const groups = isRecord(settings) && isRecord(settings.hooks) && Array.isArray(settings.hooks.PreToolUse) ? settings.hooks.PreToolUse : [];
    for (const g of groups) {
      if (isRecord(g) && Array.isArray(g.hooks)) for (const h of g.hooks) if (isRecord(h) && h.command === expected) installed = expected;
    }
  } catch { /* reported below */ }
  if (!installed) return fail(`the mcp-guard hook entry was not found in ${settingsPath(input.projectDir)} after installing it`);

  const run = (command: string, stdin: string) => spawnSync(shell, ['-c', command], { cwd: input.projectDir, input: stdin, encoding: 'utf8', env, timeout: 120_000, windowsHide: true });
  const couldNotStart = (r: ReturnType<typeof run>): boolean => (r.error as NodeJS.ErrnoException | undefined)?.code === 'ENOENT';

  const harmless = harmlessAllowedCommand(input.policy);
  if (!harmless) {
    checks.push({ name: 'allowed', command: HARMLESS[0], expected: 'pass', ok: true, detail: 'not run: the project policy allows none of git status, ls, pwd outright, and a held test call could open a signing request' });
  } else {
    const allowed = run(installed, event(harmless));
    const allowedOk = !allowed.error && allowed.status === 0 && (allowed.stdout ?? '').trim() === '';
    checks.push({
      name: 'allowed', command: harmless, expected: 'pass', ok: allowedOk,
      detail: allowedOk ? 'no decision: it runs as before, through Claude Code\'s own permission prompt' : `exit ${allowed.status ?? allowed.signal ?? allowed.error?.message}: ${firstLine(allowed.stderr || allowed.stdout)}`,
    });
    if (couldNotStart(allowed)) return fail(`${shell} could not be started to run the hook command (${checks[0].detail})`, 'could_not_run');
    if (!allowedOk) return fail(`the installed hook did not let a harmless call through (${checks[0].detail})`);
  }

  let dir: string;
  let local: string;
  try {
    dir = mkdtempSync(join(tmpdir(), 'mcp-guard-hook-self-test-'));
  } catch (err: any) {
    return fail(`its temporary policy could not be written (${err?.code ?? err?.message})`, 'could_not_run');
  }
  try {
    const policy = join(dir, HOOK_POLICY_FILE);
    try {
      writeFileSync(policy, input.localPolicy);
      // The temporary policy is absolute (a drive-letter or UNC path on Windows): used as given, never joined to the project.
      local = hookHandler({ projectDir: input.projectDir, launcher: input.launcher, configPath: policy, waitSeconds: 0, platform: input.platform }).command;
    } catch (err: any) {
      return fail(`its temporary policy could not be written or passed to the hook (${err?.code ?? err?.message})`, 'could_not_run');
    }
    const held = run(local, event(SELF_TEST_DESTRUCTIVE));
    let decision: unknown = null;
    try { decision = JSON.parse(held.stdout ?? '').hookSpecificOutput?.permissionDecision; } catch { /* not JSON */ }
    const heldOk = !held.error && held.status === 2 && decision === 'deny' && (held.stderr ?? '').includes(`rule "${EXPECTED_HOLD_RULE}"`);
    checks.push({
      name: 'held', command: SELF_TEST_DESTRUCTIVE, expected: 'deny', ok: heldOk,
      detail: heldOk ? `denied by rule "${EXPECTED_HOLD_RULE}" (in use it waits for a signature in Permission Protocol)` : `exit ${held.status ?? held.signal ?? held.error?.message}: ${firstLine(held.stderr || held.stdout)}`,
    });
    if (couldNotStart(held)) return fail(`${shell} could not be started to run the hook command (${checks[checks.length - 1].detail})`, 'could_not_run');
    // The test's own policy did not load: a problem with the test, not with the installed hook (which reads the project's policy).
    if (!heldOk && /the policy could not be loaded/.test(held.stderr ?? '')) return fail(`the hook could not read the self-test's temporary policy (${checks[checks.length - 1].detail})`, 'could_not_run');
    if (!heldOk) return fail(`the hook did not hold a destructive call (${checks[checks.length - 1].detail})`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  return { ok: true, checks, reason: null };
}

/** Claude Code honours `onFailure: "block"` from this version (https://code.claude.com/docs/en/hooks; docs/hooks.md). */
export const ON_FAILURE_MIN_VERSION: readonly [number, number, number] = [2, 1, 295];

/** Runs `claude --version`; returns its stdout, or null if it could not run. */
export type VersionRunner = () => string | null;

const defaultVersionRunner: VersionRunner = () => {
  // Fixed arguments, no user input. On Windows `claude` may be a .cmd shim, which only cmd can start.
  const [file, args] = process.platform === 'win32' ? ['cmd', ['/d', '/c', 'claude', '--version']] : ['claude', ['--version']];
  const r = spawnSync(file, args, { encoding: 'utf8', timeout: 5_000, stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true, shell: false });
  return r.error || r.status !== 0 ? null : r.stdout;
};

/**
 * One line when the installed Claude Code is older than 2.1.295, where `onFailure` does
 * nothing; null otherwise, and null whenever the version cannot be read (optional, never
 * a failure of init).
 */
export function claudeCodeVersionNote(run: VersionRunner = defaultVersionRunner): string | null {
  let out: string | null;
  try { out = run(); } catch { return null; }
  const m = out ? /(\d+)\.(\d+)\.(\d+)/.exec(out) : null;
  if (!m) return null;
  const v = [Number(m[1]), Number(m[2]), Number(m[3])];
  const [a, b, c] = ON_FAILURE_MIN_VERSION;
  const older = v[0] !== a ? v[0] < a : v[1] !== b ? v[1] < b : v[2] < c;
  if (!older) return null;
  return `Note: Claude Code ${v.join('.')} is older than ${ON_FAILURE_MIN_VERSION.join('.')}, which ignores the hook's onFailure: "block"; the installed command's own wrapper still blocks a guard that fails to run, and the guard denies a held call before Claude Code's timeout (docs/hooks.md#limits).`;
}
