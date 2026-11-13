import { spawn, type ChildProcess, type SpawnOptions } from 'node:child_process';
import { win32 } from 'node:path';
import { neutralCwd } from '../child-cwd.js';

/**
 * Open a Permission Protocol signing page in the developer's own browser while a held
 * call waits for a signature.
 *
 * It changes nothing the guard decides. It runs after the approval request exists,
 * returns at once, never throws, and every failure is ignored: the poll goes on and the
 * link is still printed and returned with a denial.
 *
 * The URL came from an API response, so it is opened only when it is `https:`, has no
 * credentials, and its origin is the origin of the cloud API the policy names. The
 * opener gets it as one argument, never through a shell: `/usr/bin/open` on macOS,
 * `rundll32 url.dll,FileProtocolHandler` on Windows (no `cmd.exe`, so `&` and `^` in a
 * URL are not parsed), `xdg-open` elsewhere.
 *
 * Off when CI is set, in an SSH session, on Linux without a display, with
 * MCP_GUARD_OPEN_BROWSER=off (or 0 / false / no), or with `cloud.open_browser: false`.
 */

export type Spawner = (command: string, args: string[], options: SpawnOptions) => ChildProcess;

export interface OpenBrowserDeps {
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  spawn?: Spawner;
  cwd?: string;
}

export function openBrowserEnvOff(env: NodeJS.ProcessEnv): boolean {
  const flag = (env.MCP_GUARD_OPEN_BROWSER ?? '').trim().toLowerCase();
  return flag === 'off' || flag === '0' || flag === 'false' || flag === 'no';
}

const isSet = (v: string | undefined): boolean => v !== undefined && v !== '';

/** Why no browser is opened on this machine, or null when one may be. */
export function browserDisabledReason(policyOpenBrowser: boolean | undefined, env: NodeJS.ProcessEnv = process.env, platform: NodeJS.Platform = process.platform): string | null {
  if (openBrowserEnvOff(env)) return 'MCP_GUARD_OPEN_BROWSER is off';
  if (policyOpenBrowser === false) return 'the policy sets cloud.open_browser: false';
  if (isSet(env.CI)) return 'CI is set';
  if (isSet(env.SSH_CONNECTION) || isSet(env.SSH_CLIENT) || isSet(env.SSH_TTY)) return 'this is an SSH session';
  if (platform !== 'darwin' && platform !== 'win32' && !isSet(env.DISPLAY) && !isSet(env.WAYLAND_DISPLAY)) return 'there is no display';
  return null;
}

/**
 * The URL to open, normalized, or null when it is not a page of the trusted API:
 * `https:`, no user name or password, and the same origin as `trustedOrigin`.
 */
export function trustedSigningUrl(url: string | null | undefined, trustedOrigin: string): string | null {
  if (typeof url !== 'string' || !url || url.length > 2048) return null;
  let parsed: URL;
  let trusted: URL;
  try {
    parsed = new URL(url);
    trusted = new URL(trustedOrigin);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:' || trusted.protocol !== 'https:') return null;
  if (parsed.username || parsed.password) return null;
  if (parsed.origin !== trusted.origin) return null;
  return parsed.href;
}

/** The opener and its arguments for a URL that already passed `trustedSigningUrl`. */
export function openerFor(url: string, platform: NodeJS.Platform = process.platform, env: NodeJS.ProcessEnv = process.env): [string, string[]] {
  if (platform === 'darwin') return ['/usr/bin/open', [url]];
  if (platform === 'win32') {
    const root = env.SystemRoot || env.SYSTEMROOT || env.windir || 'C:\\Windows';
    return [win32.join(root, 'System32', 'rundll32.exe'), ['url.dll,FileProtocolHandler', url]];
  }
  return ['xdg-open', [url]];
}

/** Start the opener detached, with no shell and no stdio. True when it was started. Never throws. */
export function launchOpener(url: string, deps: OpenBrowserDeps = {}): boolean {
  try {
    const platform = deps.platform ?? process.platform;
    const env = deps.env ?? process.env;
    const [command, args] = openerFor(url, platform, env);
    const child = (deps.spawn ?? spawn)(command, args, {
      detached: true,
      stdio: 'ignore',
      shell: false,
      windowsHide: true,
      cwd: deps.cwd ?? neutralCwd(),
      env,
    });
    child.on('error', () => undefined);
    child.unref();
    return true;
  } catch {
    return false;
  }
}

/** Request ids this process has opened a page for. */
const opened = new Set<string>();

export interface SigningPageInput {
  requestId: string;
  approvalUrl: string | null;
  /** The cloud API origin the policy names (`cloud.api_url`). */
  apiUrl: string;
  /** `cloud.open_browser` from the policy. */
  policyOpenBrowser?: boolean;
  /** The request was opened by an earlier run, which already had its chance to open the page. */
  resumed?: boolean;
}

export type SigningPageResult = { opened: true; url: string } | { opened: false; why: string };

/**
 * Open the signing page for a held request, at most once per request id. Never throws
 * and never waits.
 */
export function openSigningPage(input: SigningPageInput, deps: OpenBrowserDeps = {}): SigningPageResult {
  try {
    if (input.resumed) return { opened: false, why: 'the request was resumed' };
    if (opened.has(input.requestId)) return { opened: false, why: 'already opened for this request' };
    const off = browserDisabledReason(input.policyOpenBrowser, deps.env ?? process.env, deps.platform ?? process.platform);
    if (off) return { opened: false, why: off };
    const url = trustedSigningUrl(input.approvalUrl, input.apiUrl);
    if (!url) return { opened: false, why: input.approvalUrl ? 'the signing link is not on the configured Permission Protocol origin over https' : 'no signing link was returned' };
    opened.add(input.requestId);
    return launchOpener(url, deps) ? { opened: true, url } : { opened: false, why: 'the browser could not be started' };
  } catch {
    return { opened: false, why: 'the browser could not be started' };
  }
}
