import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * Can the launcher start mcp-guard from the project directory, the way Claude Code
 * will? Runs `<launcher> hook --help` under `sh -c`. Returns null when it can, else
 * what went wrong (fixed text and an exit code; the launcher is the person's own input).
 */
export function probeLauncher(projectDir: string, launcher: string = DEFAULT_LAUNCHER): string | null {
  const run = spawnSync('sh', ['-c', `${launcher} hook --help`], { cwd: projectDir, encoding: 'utf8', timeout: 60_000, stdio: ['ignore', 'pipe', 'pipe'] });
  if (run.error) return `could not run sh to start "${launcher}" (${(run.error as NodeJS.ErrnoException).code ?? run.error.name})`;
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
}

/** Allowed by the coding-agent preset: no rule matches it. */
export const SELF_TEST_HARMLESS = 'git status';
/** Held by the coding-agent preset's `terraform-destroy` rule. Never run: the hook only decides. */
export const SELF_TEST_DESTRUCTIVE = 'terraform destroy -auto-approve';
const EXPECTED_HOLD_RULE = 'terraform-destroy';

const event = (command: string): string =>
  JSON.stringify({ session_id: 'mcp-guard-init-self-test', cwd: '/', permission_mode: 'default', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, tool_use_id: 'toolu_mcp_guard_self_test' });

/** The first line of what the hook said, bounded. The events are ours, so it holds no user input. */
const firstLine = (text: string): string => (text.trim().split('\n')[0] ?? '').slice(0, 300) || 'no output';

/**
 * Prove the installed hook works, locally and with nothing sent to Permission Protocol:
 *
 *   1. the command exactly as installed in .claude/settings.json, with a harmless `Bash`
 *      event: the preset allows it, and an allowed call touches no network (decide.ts);
 *      the answer must be "no decision" (exit 0, empty stdout).
 *   2. the same launcher and the same hook code with a destructive `Bash` event, against
 *      a copy of the policy's rules with no `cloud:` section: the hold is answered `deny`
 *      locally (a hook cannot wait for the local approval UI) instead of opening a
 *      signing request. The answer must be a deny naming the hold rule.
 *
 * Receipts go to the self-test log (`receiptsPath`), not the project's log.
 */
export function runHookSelfTest(input: { projectDir: string; launcher?: string; localPolicy: string; receiptsPath: string; env?: NodeJS.ProcessEnv }): HookSelfTestResult {
  const checks: HookCheck[] = [];
  const env: NodeJS.ProcessEnv = { ...(input.env ?? process.env), CLAUDE_PROJECT_DIR: input.projectDir, PP_SHARED_RECEIPTS_PATH: input.receiptsPath };
  const fail = (reason: string): HookSelfTestResult => ({ ok: false, checks, reason });

  // The command Claude Code will run, read back from the settings file.
  const expected = hookHandler({ projectDir: input.projectDir, launcher: input.launcher }).command;
  let installed: string | null = null;
  try {
    const settings = JSON.parse(readFileSync(settingsPath(input.projectDir), 'utf8'));
    const groups = isRecord(settings) && isRecord(settings.hooks) && Array.isArray(settings.hooks.PreToolUse) ? settings.hooks.PreToolUse : [];
    for (const g of groups) {
      if (isRecord(g) && Array.isArray(g.hooks)) for (const h of g.hooks) if (isRecord(h) && h.command === expected) installed = expected;
    }
  } catch { /* reported below */ }
  if (!installed) return fail(`the mcp-guard hook entry was not found in ${settingsPath(input.projectDir)} after installing it`);

  const run = (command: string, stdin: string) => spawnSync('sh', ['-c', command], { cwd: input.projectDir, input: stdin, encoding: 'utf8', env, timeout: 120_000 });

  const allowed = run(installed, event(SELF_TEST_HARMLESS));
  const allowedOk = !allowed.error && allowed.status === 0 && allowed.stdout.trim() === '';
  checks.push({
    name: 'allowed', command: SELF_TEST_HARMLESS, expected: 'pass', ok: allowedOk,
    detail: allowedOk ? 'no decision: it runs as before, through Claude Code\'s own permission prompt' : `exit ${allowed.status ?? allowed.signal ?? allowed.error?.message}: ${firstLine(allowed.stderr || allowed.stdout)}`,
  });
  if (!allowedOk) return fail(`the installed hook did not let a harmless call through (${checks[0].detail})`);

  const dir = mkdtempSync(join(tmpdir(), 'mcp-guard-hook-self-test-'));
  try {
    const policy = join(dir, HOOK_POLICY_FILE);
    writeFileSync(policy, input.localPolicy);
    const local = hookHandler({ projectDir: input.projectDir, launcher: input.launcher, configPath: policy, waitSeconds: 0 }).command;
    const held = run(local, event(SELF_TEST_DESTRUCTIVE));
    let decision: unknown = null;
    try { decision = JSON.parse(held.stdout).hookSpecificOutput?.permissionDecision; } catch { /* not JSON */ }
    const heldOk = !held.error && held.status === 2 && decision === 'deny' && held.stderr.includes(`rule "${EXPECTED_HOLD_RULE}"`);
    checks.push({
      name: 'held', command: SELF_TEST_DESTRUCTIVE, expected: 'deny', ok: heldOk,
      detail: heldOk ? `denied by rule "${EXPECTED_HOLD_RULE}" (in use it waits for a signature in Permission Protocol)` : `exit ${held.status ?? held.signal ?? held.error?.message}: ${firstLine(held.stderr || held.stdout)}`,
    });
    if (!heldOk) return fail(`the hook did not hold a destructive call (${checks[1].detail})`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  return { ok: true, checks, reason: null };
}
