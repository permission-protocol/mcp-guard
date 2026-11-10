import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { keysDir } from '../keystore.js';

/**
 * The install token that authenticates this guard to Permission Protocol: a workspace
 * API key whose only scope is `mcp:guard`. It can open, read and redeem this install's
 * own requests. It cannot approve anything.
 *
 * Read from, in order:
 *   1. PP_INSTALL_TOKEN (the wrapped server never sees PP_* variables);
 *   2. the token file beside the key directory, owner-readable only.
 *
 * A missing or exposed token is a typed error: cloud approvals then refuse to start
 * in enforce mode. There is no anonymous fallback.
 */

export const TOKEN_FILE = 'install-token';
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

export function loadInstallToken(env: NodeJS.ProcessEnv = process.env, path: string = installTokenPath()): string {
  if (env.PP_INSTALL_TOKEN) return checked(env.PP_INSTALL_TOKEN, 'PP_INSTALL_TOKEN');
  if (!existsSync(path)) {
    throw new InstallTokenError(
      'INSTALL_TOKEN_MISSING',
      `no install token: set PP_INSTALL_TOKEN or write the token to ${path} (owner-only). Create one in Permission Protocol under Settings > Developer access with the scope mcp:guard.`,
    );
  }
  if (process.platform !== 'win32' && (statSync(path).mode & 0o077) !== 0) {
    throw new InstallTokenError('INSTALL_TOKEN_EXPOSED', `${path} is readable by other users; run: chmod 600 ${path}`);
  }
  return checked(readFileSync(path, 'utf8'), path);
}
