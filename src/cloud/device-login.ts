/**
 * Device login for `mcp-guard init` (app: POST /api/mcp/device/start and /token).
 *
 * The guard asks for a login, shows the person a short code and a link, and polls
 * until a signed-in owner or admin connects it in the browser. It then receives an
 * install token once. The device code never leaves this process and is not printed.
 */

export interface StartedLogin {
  deviceCode: string;
  userCode: string;
  verificationUrl: string;
  verificationUrlComplete: string;
  expiresInSec: number;
  intervalSec: number;
}

export interface CompletedLogin {
  token: string;
  tokenId: string | null;
  workspace: { name: string; slug: string };
}

export class DeviceLoginError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = 'DeviceLoginError';
  }
}

export interface DeviceLoginDeps {
  fetchImpl?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

const REQUEST_TIMEOUT_MS = 10_000;
const str = (v: unknown): string | null => (typeof v === 'string' && v ? v : null);

async function post(apiUrl: string, path: string, body: unknown, fetchImpl: typeof fetch): Promise<{ status: number; body: Record<string, unknown> }> {
  let response: Response;
  try {
    response = await fetchImpl(`${apiUrl.replace(/\/+$/, '')}${path}`, {
      method: 'POST',
      redirect: 'error',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body),
    });
  } catch (err) {
    throw new DeviceLoginError('UNREACHABLE', `Permission Protocol is unreachable: ${err instanceof Error ? err.message : String(err)}`);
  }
  let parsed: unknown = null;
  try { parsed = JSON.parse(await response.text()); } catch { /* handled below */ }
  const object = typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
  return { status: response.status, body: object };
}

function apiError(status: number, body: Record<string, unknown>): DeviceLoginError {
  const error = body.error as { code?: unknown; message?: unknown } | undefined;
  const code = str(error?.code) ?? `HTTP_${status}`;
  return new DeviceLoginError(code, str(error?.message) ?? `Permission Protocol answered ${status}`);
}

export async function startLogin(apiUrl: string, clientLabel: string | null, deps: DeviceLoginDeps = {}): Promise<StartedLogin> {
  const { status, body } = await post(apiUrl, '/api/mcp/device/start', clientLabel ? { clientLabel } : {}, deps.fetchImpl ?? fetch);
  if (status !== 201 && status !== 200) throw apiError(status, body);
  const deviceCode = str(body.deviceCode);
  const userCode = str(body.userCode);
  const verificationUrl = str(body.verificationUrl);
  if (!deviceCode || !userCode || !verificationUrl) throw new DeviceLoginError('BAD_RESPONSE', 'Permission Protocol did not return a login.');
  // The link must be on the API's own origin: the guard never sends a person elsewhere.
  const origin = new URL(apiUrl).origin;
  const complete = str(body.verificationUrlComplete) ?? verificationUrl;
  if (new URL(verificationUrl).origin !== origin || new URL(complete).origin !== origin) {
    throw new DeviceLoginError('BAD_RESPONSE', 'Permission Protocol returned a sign-in link on another site.');
  }
  return {
    deviceCode,
    userCode,
    verificationUrl,
    verificationUrlComplete: complete,
    expiresInSec: typeof body.expiresInSec === 'number' ? body.expiresInSec : 600,
    intervalSec: typeof body.intervalSec === 'number' ? Math.max(1, body.intervalSec) : 3,
  };
}

/** Poll until the login is connected, cancelled or expired. */
export async function awaitLogin(apiUrl: string, login: StartedLogin, deps: DeviceLoginDeps = {}): Promise<CompletedLogin> {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const now = deps.now ?? (() => Date.now());
  const deadline = now() + login.expiresInSec * 1000;
  let intervalMs = login.intervalSec * 1000;

  for (;;) {
    if (now() >= deadline) throw new DeviceLoginError('DEVICE_CODE_EXPIRED', 'The login expired before it was completed. Run the command again.');
    await sleep(Math.min(intervalMs, Math.max(0, deadline - now())));
    let answer: { status: number; body: Record<string, unknown> };
    try {
      answer = await post(apiUrl, '/api/mcp/device/token', { deviceCode: login.deviceCode }, fetchImpl);
    } catch (err) {
      // A dropped connection while a person is signing in: keep waiting until the deadline.
      if (err instanceof DeviceLoginError && err.code === 'UNREACHABLE') continue;
      throw err;
    }
    if (answer.status === 429 || answer.status >= 500) { intervalMs = Math.min(intervalMs * 2, 15_000); continue; }
    if (answer.status !== 200) throw apiError(answer.status, answer.body);
    if (answer.body.status === 'pending') continue;
    const token = str(answer.body.token);
    const workspace = answer.body.workspace as { name?: unknown; slug?: unknown } | undefined;
    if (answer.body.status !== 'connected' || !token) throw new DeviceLoginError('BAD_RESPONSE', 'Permission Protocol did not return a token.');
    return { token, tokenId: str(answer.body.tokenId), workspace: { name: str(workspace?.name) ?? 'unknown workspace', slug: str(workspace?.slug) ?? '' } };
  }
}
