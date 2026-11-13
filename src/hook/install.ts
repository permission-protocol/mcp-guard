import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join, posix, win32 } from 'node:path';
import { DEFAULT_HOOK_WAIT_SECONDS, HOOK_TIMEOUT_MARGIN_SECONDS } from './decide.js';

/**
 * `mcp-guard hook install | uninstall` for Claude Code: one PreToolUse entry in the
 * project's `.claude/settings.json`, in the format documented at
 * https://code.claude.com/docs/en/hooks (verified 2026-11-12, see docs/hooks.md).
 *
 * Idempotent, and it keeps every other key and hook. It refuses to touch a file that is
 * not valid JSON, or whose `hooks` is not the documented shape, rather than overwrite it.
 */

/** Claude Code's built-in tools that change things. MCP tools go through the proxy. */
export const DEFAULT_MATCHER = 'Bash|PowerShell|Write|Edit|NotebookEdit';
export const DEFAULT_LAUNCHER = 'npx --no-install mcp-guard';
/** What Claude Code shows when the launcher could not run the guard at all. Fixed text, no input. */
export const LAUNCH_FAILED_REASON = 'mcp-guard: the guard did not run (missing package, crash or bad exit); call blocked. Fix: npm install --save-dev @permission-protocol/mcp-guard';

/**
 * Shell-form hooks run under `sh -c` on macOS and Linux and Git Bash on Windows
 * (https://code.claude.com/docs/en/hooks). Claude Code counts any exit other than 0 or 2
 * as a non-blocking failure, so the installed command maps every other exit (127 for a
 * missing launcher, 1 for a crash, 128+n for a signal) to 2 with a fixed reason. 0 and 2
 * pass through, and stdout is the guard's own. POSIX sh only: under PowerShell (Windows
 * without Git Bash) the wrapper does not parse, and `onFailure: "block"` is the layer
 * that blocks.
 */
export function failClosed(command: string): string {
  return `${command}; c=$?; case $c in 0|2) exit $c;; esac; echo '${LAUNCH_FAILED_REASON}' >&2; exit 2`;
}

export class SettingsError extends Error {
  constructor(readonly code: 'SETTINGS_INVALID_JSON' | 'SETTINGS_UNEXPECTED_SHAPE', message: string) {
    super(message);
    this.name = 'SettingsError';
  }
}

export interface InstallOptions {
  projectDir: string;
  /** Policy path, relative to the project root. */
  configPath?: string;
  waitSeconds?: number;
  matcher?: string;
  /** How Claude Code starts the guard. Default: the locally installed package via npx, no download. */
  launcher?: string;
  /** Check and report what would change without writing (init's pre-flight). Throws SettingsError just as a real install would. */
  dryRun?: boolean;
  /** Whose path rules decide whether `configPath` is absolute (default: this process's platform; tests). */
  platform?: NodeJS.Platform;
}

export interface HookHandler {
  type: 'command';
  command: string;
  timeout: number;
  onFailure: 'block';
  statusMessage: string;
}

export function settingsPath(projectDir: string): string {
  return join(projectDir, '.claude', 'settings.json');
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

const shellQuote = (s: string): string => (/^[A-Za-z0-9_./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);

/**
 * Is `config` an absolute path for the platform the guard runs on? On Windows that is a
 * drive-letter path (`C:\x`, `C:/x`) or a UNC path (`\\server\share`), which the guard
 * (Node on Windows) reads as given even when Git Bash runs the command. A drive-relative
 * path (`C:x`) names no fixed place, so it is refused rather than guessed.
 */
export function isAbsoluteConfigPath(config: string, platform: NodeJS.Platform = process.platform): boolean {
  if (platform !== 'win32') return posix.isAbsolute(config);
  if (/^[A-Za-z]:(?![\\/])/.test(config)) {
    throw new SettingsError('SETTINGS_UNEXPECTED_SHAPE', `--config ${config} is relative to the current directory of drive ${config[0]}:; give an absolute path or one relative to the project root`);
  }
  return win32.isAbsolute(config);
}

export function hookHandler(opts: InstallOptions): HookHandler {
  const wait = opts.waitSeconds ?? DEFAULT_HOOK_WAIT_SECONDS;
  const launcher = (opts.launcher ?? DEFAULT_LAUNCHER).trim();
  if (!launcher.includes('mcp-guard')) throw new SettingsError('SETTINGS_UNEXPECTED_SHAPE', 'the launcher must run mcp-guard (its command must contain "mcp-guard")');
  const config = opts.configPath ?? 'pp.config.yaml';
  // ${CLAUDE_PROJECT_DIR} is the project root; quoted so a path with spaces stays one argument.
  // An absolute path (for the platform: drive-letter and UNC paths on Windows) is used as
  // given; only a relative one is joined to the project root.
  const configArg = isAbsoluteConfigPath(config, opts.platform) ? shellQuote(config) : `"\${CLAUDE_PROJECT_DIR}"/${shellQuote(config)}`;
  return {
    type: 'command',
    command: failClosed(`${launcher} hook --config ${configArg} --wait ${wait}`),
    // Longer than the wait, so the guard always answers before Claude Code gives up on it.
    timeout: wait + HOOK_TIMEOUT_MARGIN_SECONDS,
    // A crash, a missing binary or a timeout blocks the call instead of letting it through.
    onFailure: 'block',
    statusMessage: 'mcp-guard: checking policy (a held call waits for a Permission Protocol signature)',
  };
}

function readSettings(path: string): Record<string, unknown> {
  if (!existsSync(path)) return {};
  const text = readFileSync(path, 'utf8');
  if (!text.trim()) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err: any) {
    throw new SettingsError('SETTINGS_INVALID_JSON', `${path} is not valid JSON (${err.message}); fix it first, nothing was written`);
  }
  if (!isRecord(parsed)) throw new SettingsError('SETTINGS_UNEXPECTED_SHAPE', `${path} is not a JSON object; nothing was written`);
  return parsed;
}

function preToolUse(settings: Record<string, unknown>, path: string, create: boolean): unknown[] | null {
  if (settings.hooks === undefined) {
    if (!create) return null;
    settings.hooks = {};
  }
  if (!isRecord(settings.hooks)) throw new SettingsError('SETTINGS_UNEXPECTED_SHAPE', `"hooks" in ${path} is not an object; nothing was written`);
  const hooks = settings.hooks;
  if (hooks.PreToolUse === undefined) {
    if (!create) return null;
    hooks.PreToolUse = [];
  }
  if (!Array.isArray(hooks.PreToolUse)) throw new SettingsError('SETTINGS_UNEXPECTED_SHAPE', `"hooks.PreToolUse" in ${path} is not a list; nothing was written`);
  return hooks.PreToolUse;
}

/** A handler this command wrote: it runs mcp-guard's hook subcommand. Uninstall removes only those. */
const isOurs = (h: unknown): boolean => isRecord(h) && typeof h.command === 'string' && h.command.includes('mcp-guard') && / hook --config /.test(h.command);

function write(path: string, settings: Record<string, unknown>): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(settings, null, 2) + '\n');
  renameSync(tmp, path);
}

export interface SettingsChange {
  path: string;
  changed: boolean;
  message: string;
}

export function installHook(opts: InstallOptions): SettingsChange {
  const path = settingsPath(opts.projectDir);
  const settings = readSettings(path);
  const groups = preToolUse(settings, path, true)!;
  const matcher = opts.matcher ?? DEFAULT_MATCHER;
  const handler = hookHandler(opts);

  // Already installed exactly like this: nothing to do.
  const same = groups.some((g) => isRecord(g) && g.matcher === matcher && Array.isArray(g.hooks) && g.hooks.length === 1 && JSON.stringify(g.hooks[0]) === JSON.stringify(handler));
  const ours = groups.filter((g) => isRecord(g) && Array.isArray(g.hooks) && g.hooks.some(isOurs)).length;
  if (same && ours === 1) return { path, changed: false, message: `${path}: the mcp-guard PreToolUse hook is already installed (matcher "${matcher}"); nothing changed` };

  // Replace any earlier mcp-guard handler, leaving every other handler where it was.
  let replaced = false;
  for (let i = groups.length - 1; i >= 0; i--) {
    const g = groups[i];
    if (!isRecord(g) || !Array.isArray(g.hooks) || !g.hooks.some(isOurs)) continue;
    g.hooks = g.hooks.filter((h) => !isOurs(h));
    replaced = true;
    if ((g.hooks as unknown[]).length === 0) groups.splice(i, 1);
  }
  groups.push({ matcher, hooks: [handler] });
  if (!opts.dryRun) write(path, settings);
  return {
    path,
    changed: true,
    message: `${path}: ${replaced ? 'replaced' : 'added'} the PreToolUse hook for "${matcher}": ${handler.command} (timeout ${handler.timeout}s, onFailure block)`,
  };
}

export function uninstallHook(projectDir: string): SettingsChange {
  const path = settingsPath(projectDir);
  if (!existsSync(path)) return { path, changed: false, message: `${path} does not exist; nothing changed` };
  const settings = readSettings(path);
  const groups = preToolUse(settings, path, false);
  if (!groups) return { path, changed: false, message: `${path}: no mcp-guard hook installed; nothing changed` };
  let removed = 0;
  for (let i = groups.length - 1; i >= 0; i--) {
    const g = groups[i];
    if (!isRecord(g) || !Array.isArray(g.hooks)) continue;
    const before = g.hooks.length;
    g.hooks = g.hooks.filter((h) => !isOurs(h));
    removed += before - (g.hooks as unknown[]).length;
    if (before > 0 && (g.hooks as unknown[]).length === 0) groups.splice(i, 1);
  }
  if (removed === 0) return { path, changed: false, message: `${path}: no mcp-guard hook installed; nothing changed` };
  const hooks = settings.hooks as Record<string, unknown>;
  if (groups.length === 0) delete hooks.PreToolUse;
  if (Object.keys(hooks).length === 0) delete settings.hooks;
  write(path, settings);
  return { path, changed: true, message: `${path}: removed ${removed} mcp-guard PreToolUse hook${removed === 1 ? '' : 's'}` };
}
