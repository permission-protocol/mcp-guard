import { spawnSync } from 'node:child_process';
import { userInfo } from 'node:os';

/**
 * Windows has no POSIX file modes: `chmod 0600` does nothing there and the guard's
 * exposure checks are skipped. So on win32, after writing a secret file (the install
 * token, a private signing key), the guard tries to restrict it to the current user
 * with `icacls`: inherited entries removed, the current user granted full control.
 *
 * The path is passed as its own argument to `icacls` (exec form, no shell), with a
 * timeout. A missing or failing `icacls` never fails the caller: the result says the
 * file is protected only by the permissions of the user's profile folder.
 */

export type WindowsProtection = 'restricted' | 'profile-only';

/** Runs a program with an argument array, never through a shell. */
export type ExecFile = (file: string, args: string[], options: { timeout: number }) => { status: number | null };

const defaultExec: ExecFile = (file, args, options) => {
  const r = spawnSync(file, args, { timeout: options.timeout, shell: false, windowsHide: true, stdio: 'ignore' });
  return { status: r.error ? null : r.status };
};

export interface ProtectOptions {
  platform?: NodeJS.Platform;
  exec?: ExecFile;
  /** The account to grant, as icacls expects it (default: DOMAIN\user from the environment, else the OS user name). */
  user?: string;
  env?: NodeJS.ProcessEnv;
}

export const ICACLS_TIMEOUT_MS = 10_000;

function currentUser(env: NodeJS.ProcessEnv): string | null {
  const name = env.USERNAME || (() => { try { return userInfo().username; } catch { return ''; } })();
  if (!name) return null;
  return env.USERDOMAIN ? `${env.USERDOMAIN}\\${name}` : name;
}

/**
 * On win32: restrict `path` to the current user and say whether that worked. On any
 * other platform: null (POSIX modes apply; nothing is run).
 */
export function restrictToCurrentUser(path: string, options: ProtectOptions = {}): WindowsProtection | null {
  if ((options.platform ?? process.platform) !== 'win32') return null;
  const user = options.user ?? currentUser(options.env ?? process.env);
  if (!user) return 'profile-only';
  try {
    const r = (options.exec ?? defaultExec)('icacls', [path, '/inheritance:r', '/grant:r', `${user}:F`], { timeout: ICACLS_TIMEOUT_MS });
    return r.status === 0 ? 'restricted' : 'profile-only';
  } catch {
    return 'profile-only';
  }
}

/** What to tell the person about a secret file on Windows. */
export function windowsProtectionNote(protection: WindowsProtection): string {
  return protection === 'restricted'
    ? 'restricted to the current user (icacls)'
    : 'not restricted (icacls failed or is missing); protected only by the permissions of your user profile folder';
}
