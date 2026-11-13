import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

/**
 * Finding and wrapping MCP servers in the config files of Claude Code and Cursor.
 *
 * Both keep stdio servers as `{ "command": ..., "args": [...], "env": {...} }` under an
 * `mcpServers` object. Wrapping one replaces its command with mcp-guard and moves the
 * original command after `--`, so every call to that server goes through the guard.
 * Nothing else in the file changes, and the file is copied aside first.
 *
 * Remote servers (a `url`, no `command`) are not stdio and cannot be wrapped.
 */

export type McpClient = 'claude-code' | 'cursor';
export const MCP_CLIENTS: McpClient[] = ['claude-code', 'cursor'];
export const GUARD_PACKAGE = '@permission-protocol/mcp-guard';

export interface FoundServer {
  client: McpClient;
  /** The config file that holds it. */
  file: string;
  /** Keys from the file root to the `mcpServers` object. */
  path: string[];
  name: string;
  command: string;
  args: string[];
  wrapped: boolean;
}

export interface SkippedConfig {
  file: string;
  reason: string;
}

interface ConfigLocation {
  client: McpClient;
  file: string;
  /** For ~/.claude.json: also look under projects[<cwd>].mcpServers. */
  projectScoped?: boolean;
}

export function configLocations(home: string = homedir(), cwd: string = process.cwd()): ConfigLocation[] {
  return [
    { client: 'claude-code', file: join(cwd, '.mcp.json') },
    { client: 'claude-code', file: join(home, '.claude.json'), projectScoped: true },
    { client: 'cursor', file: join(cwd, '.cursor', 'mcp.json') },
    { client: 'cursor', file: join(home, '.cursor', 'mcp.json') },
  ];
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

const GUARD_BIN = /(^|[\\/])mcp-guard(\.cmd)?$/;

export function isWrapped(command: string, args: string[]): boolean {
  if (GUARD_BIN.test(command)) return true;
  // `npx -y @permission-protocol/mcp-guard@<v> ... --`, or a --wrap-launcher such as `node <dir>/bin/mcp-guard ... --`.
  return args.some((arg) => arg === GUARD_PACKAGE || arg.startsWith(`${GUARD_PACKAGE}@`) || GUARD_BIN.test(arg)) && args.includes('--');
}

function serversIn(root: unknown, path: string[]): Array<{ name: string; command: string; args: string[] }> {
  let node: unknown = root;
  for (const key of path) node = isRecord(node) ? node[key] : undefined;
  if (!isRecord(node)) return [];
  const found: Array<{ name: string; command: string; args: string[] }> = [];
  for (const [name, entry] of Object.entries(node)) {
    if (!isRecord(entry) || typeof entry.command !== 'string' || !entry.command) continue;
    const args = Array.isArray(entry.args) ? entry.args.filter((a): a is string => typeof a === 'string') : [];
    found.push({ name, command: entry.command, args });
  }
  return found;
}

/** Every stdio server in the known config files, plus the files that could not be read. */
export function findServers(
  options: { home?: string; cwd?: string; client?: McpClient; file?: string } = {},
): { servers: FoundServer[]; skipped: SkippedConfig[] } {
  const cwd = options.cwd ?? process.cwd();
  const locations = options.file
    ? [{ client: options.client ?? 'claude-code', file: resolve(options.file), projectScoped: true } as ConfigLocation]
    : configLocations(options.home, cwd).filter((l) => !options.client || l.client === options.client);
  const servers: FoundServer[] = [];
  const skipped: SkippedConfig[] = [];
  for (const location of locations) {
    if (!existsSync(location.file)) continue;
    let root: unknown;
    try {
      root = JSON.parse(readFileSync(location.file, 'utf-8'));
    } catch {
      skipped.push({ file: location.file, reason: 'not valid JSON' });
      continue;
    }
    const paths: string[][] = [['mcpServers']];
    if (location.projectScoped && isRecord(root) && isRecord(root.projects)) {
      for (const project of Object.keys(root.projects)) {
        if (resolve(project) === resolve(cwd)) paths.push(['projects', project, 'mcpServers']);
      }
    }
    for (const path of paths) {
      for (const server of serversIn(root, path)) {
        servers.push({ client: location.client, file: location.file, path, ...server, wrapped: isWrapped(server.command, server.args) });
      }
    }
  }
  return { servers, skipped };
}

export interface WrapOptions {
  /** The policy file the guard reads for this server. */
  policyPath: string;
  agentId: string;
  /** Pinned so the client always starts the guard version that was set up. */
  version: string;
  /** `--wrap-launcher`, split into words: replaces `npx -y @permission-protocol/mcp-guard@<version>`. */
  launcher?: string[];
  now?: Date;
}

/**
 * How the client starts the guard: `npx -y @permission-protocol/mcp-guard@<version>`, or
 * the `--wrap-launcher` words. On Windows an MCP client cannot start `npx` directly (it
 * is npx.cmd), so an npx launcher goes through `cmd /c`.
 */
export function wrapLauncher(version: string, launcher?: string[], platform: NodeJS.Platform = process.platform): string[] {
  const words = launcher && launcher.length > 0 ? launcher : ['npx', '-y', `${GUARD_PACKAGE}@${version}`];
  return platform === 'win32' && /^npx(\.cmd)?$/i.test(words[0]) ? ['cmd', '/c', ...words] : words;
}

/**
 * Split a `--wrap-launcher` value into words: whitespace separates, double quotes group
 * (for paths with spaces). No other shell syntax: the client runs it without a shell.
 */
export function splitLauncher(value: string): string[] {
  const words: string[] = [];
  const re = /"([^"]*)"|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(value)) !== null) {
    const word = m[1] ?? m[2];
    if (m[2] !== undefined && m[2].includes('"')) throw new Error('--wrap-launcher: put each quoted word in its own pair of double quotes');
    words.push(word);
  }
  if (words.length === 0 || words[0] === '') throw new Error('--wrap-launcher needs a command');
  return words;
}

/**
 * Does this launcher start this package at this version? Runs `<launcher> --version`
 * without a shell, with a timeout and without PP_* variables, the way the client will run
 * it (from `cwd`). Returns null when it printed exactly `version`, else what went wrong.
 */
export function probeWrapLauncher(launcher: string[], version: string, options: { cwd?: string; timeoutMs?: number } = {}): string | null {
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('PP_')));
  const shown = launcher.map((w) => (/\s/.test(w) ? `"${w}"` : w)).join(' ');
  const run = spawnSync(launcher[0], [...launcher.slice(1), '--version'], {
    cwd: options.cwd, env, encoding: 'utf8', timeout: options.timeoutMs ?? 60_000, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, shell: false,
  });
  if (run.error) return `"${shown}" could not be run (${(run.error as NodeJS.ErrnoException).code ?? run.error.name})`;
  const printed = (run.stdout ?? '').trim().split(/\r?\n/).pop() ?? '';
  if (run.status === 0 && printed === version) return null;
  if (run.status === 0) return `"${shown}" started, but reported version "${printed.replace(/[^\x20-\x7e]/g, '').slice(0, 40)}", not ${version}`;
  return `"${shown}" did not start mcp-guard ${version} (exit ${run.status ?? run.signal})`;
}

export interface WrapResult {
  backup: string;
  command: string;
  args: string[];
}

/**
 * The guard command line that replaces a server's own (see wrapLauncher).
 */
export function wrappedCommand(
  server: Pick<FoundServer, 'command' | 'args'>,
  options: WrapOptions,
  platform: NodeJS.Platform = process.platform,
): { command: string; args: string[] } {
  const launcher = wrapLauncher(options.version, options.launcher, platform);
  return { command: launcher[0], args: [...launcher.slice(1), '--config', options.policyPath, '--agent-id', options.agentId, '--', server.command, ...server.args] };
}

/**
 * Rewrite one server entry in place. The file is copied to `<file>.mcp-guard-backup-<time>`
 * first; every other key of the entry (env, cwd, ...) and of the file is kept.
 */
export function wrapServer(server: FoundServer, options: WrapOptions): WrapResult {
  if (server.wrapped) throw new Error(`"${server.name}" is already wrapped by mcp-guard`);
  const text = readFileSync(server.file, 'utf-8');
  const root: unknown = JSON.parse(text);
  let node: unknown = root;
  for (const key of server.path) node = isRecord(node) ? node[key] : undefined;
  const entry = isRecord(node) ? node[server.name] : undefined;
  if (!isRecord(entry) || entry.command !== server.command) {
    throw new Error(`"${server.name}" in ${server.file} changed since it was read; nothing was written`);
  }
  const stamp = (options.now ?? new Date()).toISOString().replace(/[:.]/g, '-');
  const backup = `${server.file}.mcp-guard-backup-${stamp}`;
  copyFileSync(server.file, backup);
  const next = wrappedCommand(server, options);
  entry.command = next.command;
  entry.args = next.args;
  const indent = /^\{\r?\n(\s+)"/.exec(text)?.[1] ?? '  ';
  writeFileSync(server.file, JSON.stringify(root, null, indent) + (text.endsWith('\n') ? '\n' : ''));
  return { backup, ...next };
}
