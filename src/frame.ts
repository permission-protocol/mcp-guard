/**
 * Inbound JSON-RPC framing for the stdio proxy.
 *
 * The guard only ever forwards a message it parsed and evaluated, re-serialized from
 * the parsed object, so the server cannot read a line differently than the guard did.
 * Anything that is not a single well-formed JSON-RPC 2.0 object is answered with an
 * error and never forwarded. MCP does not use JSON-RPC batching, so arrays are refused.
 */

export type JsonRpcId = string | number | null;

export interface JsonRpcMessage {
  jsonrpc: '2.0';
  id?: JsonRpcId;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: unknown;
}

export type Frame =
  | { kind: 'request'; msg: JsonRpcMessage & { method: string; id: JsonRpcId } }
  | { kind: 'notification'; msg: JsonRpcMessage & { method: string } }
  | { kind: 'response'; msg: JsonRpcMessage }
  | { kind: 'invalid'; id: JsonRpcId; code: number; message: string };

export const PARSE_ERROR = -32700;
export const INVALID_REQUEST = -32600;
export const METHOD_NOT_FOUND = -32601;
export const INVALID_PARAMS = -32602;
export const BLOCKED = -32001;
export const HELD = -32002;
export const DENIED = -32003;
export const EXPIRED = -32004;
export const RELEASE_FAILED = -32005;
/** The guard could not sign the decision (missing, invalid or revoked key): nothing was forwarded. */
export const SIGNING_FAILED = -32006;

/**
 * Methods that carry no action or data access of their own. Everything else — tools/call,
 * resources/read, prompts/get, resources/subscribe and any method the guard does not
 * know — goes through the policy.
 */
export const PASSTHROUGH_METHODS = new Set([
  'initialize',
  'ping',
  'tools/list',
  'resources/list',
  'resources/templates/list',
  'resources/unsubscribe',
  'prompts/list',
  'logging/setLevel',
  'completion/complete',
]);

export function isPassthrough(method: string): boolean {
  return PASSTHROUGH_METHODS.has(method) || method.startsWith('notifications/');
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function validId(v: unknown): v is JsonRpcId {
  return v === null || typeof v === 'string' || (typeof v === 'number' && Number.isFinite(v));
}

export function parseFrame(line: string): Frame {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return { kind: 'invalid', id: null, code: PARSE_ERROR, message: 'Parse error' };
  }
  if (Array.isArray(parsed)) {
    return { kind: 'invalid', id: null, code: INVALID_REQUEST, message: 'Batch requests are not supported' };
  }
  if (!isPlainObject(parsed)) {
    return { kind: 'invalid', id: null, code: INVALID_REQUEST, message: 'Invalid Request' };
  }
  const id = validId(parsed.id) ? parsed.id : null;
  const invalid = (message: string): Frame => ({ kind: 'invalid', id, code: INVALID_REQUEST, message });

  if (parsed.jsonrpc !== '2.0') return invalid('Invalid Request: jsonrpc must be "2.0"');
  if ('id' in parsed && !validId(parsed.id)) return invalid('Invalid Request: bad id');

  const msg = parsed as unknown as JsonRpcMessage;
  if ('method' in parsed) {
    if (typeof parsed.method !== 'string' || !parsed.method) return invalid('Invalid Request: method must be a string');
    if ('params' in parsed && !isPlainObject(parsed.params) && !Array.isArray(parsed.params)) {
      return invalid('Invalid Request: params must be an object or array');
    }
    if ('id' in parsed) return { kind: 'request', msg: msg as JsonRpcMessage & { method: string; id: JsonRpcId } };
    return { kind: 'notification', msg: msg as JsonRpcMessage & { method: string } };
  }
  if ('id' in parsed && ('result' in parsed || 'error' in parsed)) return { kind: 'response', msg };
  return invalid('Invalid Request');
}

export function errorLine(id: JsonRpcId, code: number, message: string): string {
  return JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } });
}

/**
 * The tools/call target and arguments, validated. Returns an error message when the
 * params are malformed (the call is then refused, never forwarded).
 */
export function toolCallTarget(
  params: unknown,
): { name: string; args: Record<string, unknown> | undefined } | { error: string } {
  if (!isPlainObject(params)) return { error: 'Invalid params: tools/call requires an object' };
  if (typeof params.name !== 'string' || !params.name) return { error: 'Invalid params: tool name must be a string' };
  if (params.arguments !== undefined && !isPlainObject(params.arguments)) {
    return { error: 'Invalid params: arguments must be an object' };
  }
  return { name: params.name, args: params.arguments as Record<string, unknown> | undefined };
}

/** A copy of the message with Permission Deck agent metadata (`_pp`) removed from tool arguments. */
export function stripAgentMetadata(msg: JsonRpcMessage): JsonRpcMessage {
  const params = msg.params;
  if (msg.method !== 'tools/call' || !isPlainObject(params) || !isPlainObject(params.arguments)) return msg;
  if (!('_pp' in params.arguments)) return msg;
  const { _pp, ...rest } = params.arguments;
  return { ...msg, params: { ...params, arguments: rest } };
}
