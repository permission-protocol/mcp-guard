import { ADAPTERS, type HookAdapter, type HookAnswer, type HookVerdict } from './adapter.js';
import { decideHook, DEFAULT_HOOK_WAIT_SECONDS, MAX_HOOK_WAIT_SECONDS } from './decide.js';
import { installHook, uninstallHook, DEFAULT_MATCHER } from './install.js';
import { heartbeatAfterHook } from '../heartbeat/hook.js';

/** A hook event is a few KB; anything this large is refused, not parsed. */
export const MAX_HOOK_INPUT_BYTES = 8 * 1024 * 1024;
/** The guard answers deny on its own this long after the wait, well before the install step's hook timeout. */
const WATCHDOG_MARGIN_SECONDS = 25;

const HELP = `
mcp-guard hook — guard a coding agent's built-in tools (shell, file edits) with the same policy

Usage:
  mcp-guard hook [--config <path>] [--wait <seconds>] [--mode enforce|observe] [--agent claude-code]
      Reads one PreToolUse event on stdin and answers in Claude Code's hook format.
  mcp-guard hook install [--project <dir>] [--config <path>] [--wait <seconds>] [--matcher <m>] [--launcher <cmd>]
      Adds the hook to <dir>/.claude/settings.json (default: the current directory).
  mcp-guard hook uninstall [--project <dir>]

Options:
  --config <path>    Policy file (default: ./pp.config.yaml; install: relative to the project root)
  --wait <seconds>   How long a held call waits for a signature in one hook run (default ${DEFAULT_HOOK_WAIT_SECONDS}, at most the policy's cloud.approval_timeout_seconds)
  --matcher <m>      Claude Code tools to guard (default "${DEFAULT_MATCHER}")
  --launcher <cmd>   How Claude Code starts mcp-guard (default "npx --no-install mcp-guard")

See docs/hooks.md.
`.trim();

function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

function waitFrom(args: string[]): number | Error {
  const raw = flag(args, '--wait');
  if (raw === undefined) return DEFAULT_HOOK_WAIT_SECONDS;
  const n = Number(raw);
  if (!/^\d+$/.test(raw) || !Number.isInteger(n) || n > MAX_HOOK_WAIT_SECONDS) return new Error(`--wait must be a whole number of seconds, 0 to ${MAX_HOOK_WAIT_SECONDS}`);
  return n;
}

function readStdin(limit: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    process.stdin.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error('too large'));
        process.stdin.destroy();
        return;
      }
      chunks.push(chunk);
    });
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', reject);
  });
}

function send(answer: HookAnswer): Promise<number> {
  return new Promise((resolve) => {
    const done = (): void => resolve(answer.exitCode);
    const out = (): void => { if (answer.stdout) process.stdout.write(answer.stdout, done); else done(); };
    if (answer.stderr) process.stderr.write(answer.stderr, out); else out();
  });
}

/**
 * Answer one hook event. Diagnostics the shared code writes to stderr (receipt lines,
 * the signing link) are held back while deciding: on a deny, stderr carries only the
 * reason, because that is what the agent shows; otherwise they are written after.
 */
async function answerEvent(adapter: HookAdapter, args: string[]): Promise<number> {
  const wait = waitFrom(args);
  const denyNow = (reason: string): Promise<number> => send(adapter.answer({ kind: 'deny', reason: `mcp-guard: ${reason}` }));
  if (wait instanceof Error) return denyNow(`denied: ${wait.message}`);
  const mode = flag(args, '--mode');
  if (mode !== undefined && mode !== 'enforce' && mode !== 'observe') return denyNow('denied: --mode must be enforce or observe');

  const realWrite = process.stderr.write.bind(process.stderr);
  const held: string[] = [];
  (process.stderr as any).write = (chunk: unknown, ...rest: unknown[]): boolean => {
    held.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk as Uint8Array).toString('utf8'));
    const cb = rest.find((r) => typeof r === 'function') as (() => void) | undefined;
    cb?.();
    return true;
  };
  const restore = (): void => { (process.stderr as any).write = realWrite; };

  let watchdog: NodeJS.Timeout | undefined;
  const timedOut = new Promise<HookVerdict>((resolve) => {
    watchdog = setTimeout(() => resolve({
      kind: 'deny',
      reason: `mcp-guard: denied: no decision within ${wait + WATCHDOG_MARGIN_SECONDS} seconds. If a signing request was opened, sign it, then run exactly the same call again.`,
    }), (wait + WATCHDOG_MARGIN_SECONDS) * 1000);
  });

  let verdict: HookVerdict;
  try {
    const decided = (async (): Promise<HookVerdict> => {
      let raw: string;
      try {
        raw = await readStdin(MAX_HOOK_INPUT_BYTES);
      } catch {
        return { kind: 'deny', reason: 'mcp-guard: denied: HOOK_INPUT_MALFORMED: the hook event on stdin could not be read or is too large.' };
      }
      return decideHook(raw, {
        adapter,
        configPath: flag(args, '--config') ?? './pp.config.yaml',
        waitSeconds: wait,
        ...(mode ? { modeOverride: mode as 'enforce' | 'observe' } : {}),
      });
    })();
    verdict = await Promise.race([decided, timedOut]);
  } catch (err: any) {
    verdict = { kind: 'deny', reason: `mcp-guard: denied: internal error (${err?.name ?? 'Error'}).` };
  } finally {
    clearTimeout(watchdog);
    restore();
  }

  if (verdict.kind !== 'deny' && held.length) await new Promise<void>((r) => process.stderr.write(held.join(''), () => r()));
  return send(adapter.answer(verdict));
}

export async function runHook(args: string[]): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    console.log(HELP);
    return 0;
  }
  if (args[0] === 'install' || args[0] === 'uninstall') {
    const rest = args.slice(1);
    const projectDir = flag(rest, '--project') ?? process.cwd();
    try {
      let change;
      if (args[0] === 'install') {
        const wait = waitFrom(rest);
        if (wait instanceof Error) throw wait;
        change = installHook({ projectDir, configPath: flag(rest, '--config'), waitSeconds: wait, matcher: flag(rest, '--matcher'), launcher: flag(rest, '--launcher') });
      } else {
        change = uninstallHook(projectDir);
      }
      console.log(change.message);
      return 0;
    } catch (err: any) {
      process.stderr.write(`[mcp-guard] Error: ${err?.code ? `${err.code}: ` : ''}${err?.message ?? err}\n`);
      return 1;
    }
  }

  const agent = flag(args, '--agent') ?? 'claude-code';
  const adapter = ADAPTERS[agent];
  if (!adapter) {
    // Unknown agent: answer in the only format we know, and refuse.
    return send(ADAPTERS['claude-code'].answer({ kind: 'deny', reason: `mcp-guard: denied: unknown --agent "${agent}"` }));
  }
  return answerEvent(adapter, args).finally(() => heartbeatAfterHook(args));
}
