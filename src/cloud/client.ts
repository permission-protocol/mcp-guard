/**
 * HTTP client for Permission Protocol's MCP approval routes
 * (POST /api/mcp/approval-requests, GET …/{id}, POST …/{id}/redeem).
 *
 * It carries the install token and returns parsed JSON or a typed CloudApiError. It
 * decides nothing: every answer is checked by the caller, and a receipt is believed
 * only after cloud/verify.ts verified its signed bytes. Redirects are refused so the
 * token is never sent to another origin.
 */

export type CloudApiErrorKind = 'UNREACHABLE' | 'HTTP' | 'BAD_RESPONSE';

export class CloudApiError extends Error {
  constructor(
    readonly kind: CloudApiErrorKind,
    message: string,
    /** HTTP status, for kind HTTP. */
    readonly status?: number,
    /** The API's own error code, when it sent one. */
    readonly apiCode?: string,
  ) {
    super(message);
    this.name = 'CloudApiError';
  }

  /** Worth asking again later: the API was unreachable, overloaded or failing. */
  get transient(): boolean {
    return this.kind === 'UNREACHABLE' || (this.kind === 'HTTP' && (this.status === 429 || (this.status ?? 0) >= 500));
  }
}

export interface CreateRequestBody {
  tool: string;
  server: string;
  argsHash: string;
  /** Masked and capped by the guard (cloud/preview.ts); omitted with `cloud.args_preview: false`. */
  argsPreview?: string;
  agentId: string;
  env: string;
  timeoutSec: number;
}

export interface CloudClient {
  create(body: CreateRequestBody): Promise<Record<string, unknown>>;
  read(requestId: string): Promise<Record<string, unknown>>;
  redeem(requestId: string): Promise<Record<string, unknown>>;
}

export interface CloudClientOptions {
  apiUrl: string;
  token: string;
  requestTimeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
const REQUEST_ID = /^[A-Za-z0-9_-]{1,80}$/;

export function createCloudClient(options: CloudClientOptions): CloudClient {
  const base = options.apiUrl.replace(/\/+$/, '');
  const doFetch = options.fetchImpl ?? fetch;
  const timeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;

  async function call(method: 'GET' | 'POST', path: string, body?: unknown): Promise<Record<string, unknown>> {
    let response: Response;
    try {
      response = await doFetch(`${base}${path}`, {
        method,
        redirect: 'error',
        signal: AbortSignal.timeout(timeoutMs),
        headers: {
          Authorization: `Bearer ${options.token}`,
          Accept: 'application/json',
          ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      });
    } catch (err) {
      const reason = err instanceof Error ? err.name === 'TimeoutError' ? `no answer in ${timeoutMs} ms` : err.message : String(err);
      throw new CloudApiError('UNREACHABLE', `Permission Protocol is unreachable: ${reason}`);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(await response.text());
    } catch {
      parsed = null;
    }
    const object = typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null;

    if (!response.ok) {
      const error = object?.error;
      const apiCode = typeof error === 'object' && error !== null && typeof (error as { code?: unknown }).code === 'string'
        ? (error as { code: string }).code
        : undefined;
      const apiMessage = typeof error === 'object' && error !== null && typeof (error as { message?: unknown }).message === 'string'
        ? (error as { message: string }).message
        : '';
      throw new CloudApiError('HTTP', `Permission Protocol answered ${response.status}${apiCode ? ` ${apiCode}` : ''}${apiMessage ? `: ${apiMessage}` : ''}`, response.status, apiCode);
    }
    if (!object) throw new CloudApiError('BAD_RESPONSE', `Permission Protocol answered ${response.status} without a JSON object`);
    return object;
  }

  const idPath = (requestId: string): string => {
    if (!REQUEST_ID.test(requestId)) throw new CloudApiError('BAD_RESPONSE', 'Permission Protocol returned a malformed request id');
    return `/api/mcp/approval-requests/${requestId}`;
  };

  return {
    create: (body) => call('POST', '/api/mcp/approval-requests', body),
    read: (requestId) => call('GET', idPath(requestId)),
    redeem: (requestId) => call('POST', `${idPath(requestId)}/redeem`),
  };
}
