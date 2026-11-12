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

export function isWrapped(command: string, args: string[]): boolean {
  if (/(^|[\\/])mcp-guard(\.cmd)?$/.test(command)) return true;
  return args.some((arg) => arg === GUARD_PACKAGE || arg.startsWith(`${GUARD_PACKAGE}@`)) && args.includes('--');
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
  now?: Date;
}

export interface WrapResult {
  backup: string;
  command: string;
  args: string[];
}

/**
 * The guard command line that replaces a server's own. On Windows an MCP client cannot
 * start `npx` directly (it is npx.cmd), so it goes through `cmd /c`.
 */
export function wrappedCommand(
  server: Pick<FoundServer, 'command' | 'args'>,
  options: WrapOptions,
  platform: NodeJS.Platform = process.platform,
): { command: string; args: string[] } {
  const guard = ['-y', `${GUARD_PACKAGE}@${options.version}`, '--config', options.policyPath, '--agent-id', options.agentId, '--', server.command, ...server.args];
  return platform === 'win32' ? { command: 'cmd', args: ['/c', 'npx', ...guard] } : { command: 'npx', args: guard };
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
