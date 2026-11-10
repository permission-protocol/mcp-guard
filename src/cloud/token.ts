import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { keysDir } from '../keystore.js';

/**
 * The install token that authenticates this guard to Permission Protocol: a workspace
 * API key whose only scope is `mcp:guard`. It can open, read and redeem this install's
 * own requests. It cannot approve anything.
 *
 * Read from, in order:
 *   1. PP_INSTALL_TOKEN (the wrapped server never sees PP_* variables);
 *   2. the OS keychain, where `mcp-guard init` puts it (macOS Keychain, or the Secret
 *      Service on Linux when `secret-tool` is installed);
 *   3. the token file beside the key directory, owner-readable only. `init` writes it
 *      there, mode 0600, when no keychain is available (always on Windows).
 *
 * A missing, malformed or exposed token is a typed error: cloud approvals then refuse
 * to start in enforce mode. There is no anonymous fallback.
 */

export const TOKEN_FILE = 'install-token';
export const KEYCHAIN_SERVICE = 'permission-protocol-mcp-guard';
export const KEYCHAIN_ACCOUNT = 'install-token';
const TOKEN_PATTERN = /^pp_(?:live|test)_[A-Za-z0-9_-]{8,120}$/;

export class InstallTokenError extends Error {
  constructor(readonly code: 'INSTALL_TOKEN_MISSING' | 'INSTALL_TOKEN_INVALID' | 'INSTALL_TOKEN_EXPOSED', message: string) {
    super(message);
    this.name = 'InstallTokenError';
  }
}

export function installTokenPath(): string {
  return join(dirname(keysDir()), TOKEN_FILE);
}

function checked(token: string, source: string): string {
  const trimmed = token.trim();
  if (!TOKEN_PATTERN.test(trimmed)) {
    throw new InstallTokenError('INSTALL_TOKEN_INVALID', `the install token in ${source} is not a Permission Protocol key (pp_live_… or pp_test_…)`);
  }
  return trimmed;
}

/** Runs a keychain helper. `input` goes to stdin, so a secret is never on a command line. */
export type KeychainRunner = (command: string, args: string[], input?: string) => { status: number | null; stdout: string };

const defaultRunner: KeychainRunner = (command, args, input) => {
  const result = spawnSync(command, args, { input, encoding: 'utf8', timeout: 10_000, stdio: ['pipe', 'pipe', 'ignore'] });
  return { status: result.error ? null : result.status, stdout: result.stdout ?? '' };
};

export interface KeychainOptions {
  platform?: NodeJS.Platform;
  run?: KeychainRunner;
  env?: NodeJS.ProcessEnv;
}

/** `MCP_GUARD_TOKEN_STORE=file` keeps the token out of the keychain (headless machines, tests). It changes where the token lives, nothing else. */
function keychainAllowed(env: NodeJS.ProcessEnv): boolean {
  return env.MCP_GUARD_TOKEN_STORE !== 'file';
}

export function readKeychainToken(options: KeychainOptions = {}): string | null {
  const platform = options.platform ?? process.platform;
  const run = options.run ?? defaultRunner;
  if (!keychainAllowed(options.env ?? process.env)) return null;
  let result: { status: number | null; stdout: string } | null = null;
  if (platform === 'darwin') result = run('security', ['find-generic-password', '-a', KEYCHAIN_ACCOUNT, '-s', KEYCHAIN_SERVICE, '-w']);
  else if (platform === 'linux') result = run('secret-tool', ['lookup', 'service', KEYCHAIN_SERVICE, 'account', KEYCHAIN_ACCOUNT]);
  if (!result || result.status !== 0) return null;
  const value = result.stdout.trim();
  return TOKEN_PATTERN.test(value) ? value : null;
}

/** Store the token in the OS keychain. False when this platform has none the guard can use. */
export function writeKeychainToken(token: string, options: KeychainOptions = {}): boolean {
  const platform = options.platform ?? process.platform;
  const run = options.run ?? defaultRunner;
  if (!keychainAllowed(options.env ?? process.env)) return false;
  if (platform === 'darwin') {
    // `security -i` reads the command from stdin, so the token is not an argument.
    const command = `add-generic-password -U -a ${KEYCHAIN_ACCOUNT} -s ${KEYCHAIN_SERVICE} -l "Permission Protocol MCP Guard" -w ${token}\n`;
    return run('security', ['-i'], command).status === 0 && readKeychainToken(options) === token;
  }
  if (platform === 'linux') {
    const stored = run('secret-tool', ['store', '--label=Permission Protocol MCP Guard', 'service', KEYCHAIN_SERVICE, 'account', KEYCHAIN_ACCOUNT], token);
    return stored.status === 0 && readKeychainToken(options) === token;
  }
  return false;
}

export type TokenLocation = { kind: 'keychain' } | { kind: 'file'; path: string };

/** Where `init` puts a new token: the OS keychain, else a 0600 file. */
export function saveInstallToken(token: string, options: KeychainOptions & { path?: string } = {}): TokenLocation {
  const value = checked(token, 'the login');
  if (writeKeychainToken(value, options)) return { kind: 'keychain' };
  const path = options.path ?? installTokenPath();
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, `${value}\n`, { mode: 0o600 });
  try { chmodSync(path, 0o600); } catch { /* best effort on platforms without chmod */ }
  return { kind: 'file', path };
}

export function loadInstallToken(env: NodeJS.ProcessEnv = process.env, path: string = installTokenPath(), keychain: KeychainOptions = {}): string {
  if (env.PP_INSTALL_TOKEN) return checked(env.PP_INSTALL_TOKEN, 'PP_INSTALL_TOKEN');
  const fromKeychain = readKeychainToken({ ...keychain, env });
  if (fromKeychain) return fromKeychain;
  if (!existsSync(path)) {
    throw new InstallTokenError(
      'INSTALL_TOKEN_MISSING',
      `no install token: run \`mcp-guard init\`, or set PP_INSTALL_TOKEN, or write the token to ${path} (owner-only). A token is a Permission Protocol API key with the single scope mcp:guard.`,
    );
  }
  if (process.platform !== 'win32' && (statSync(path).mode & 0o077) !== 0) {
    throw new InstallTokenError('INSTALL_TOKEN_EXPOSED', `${path} is readable by other users; run: chmod 600 ${path}`);
  }
  return checked(readFileSync(path, 'utf8'), path);
}
