import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { canonicalJsonText } from '../signing/canonical.js';
import { rawPublicKey, type KeySet } from '../signing/keys.js';
import { pinsFor } from '../cloud/pinned-keys.js';
import type { CloudReceiptArtifact } from '../cloud/verify.js';
import { maskText } from '../cloud/preview.js';

/**
 * Test stand-ins for Permission Protocol: a signing key, receipts in the shapes the app
 * signs (jcs_v3 by default, as production does; jcs_v2 on request), and a small HTTP
 * server that speaks the MCP approval routes. Nothing here is used by the guard itself.
 */

export interface TestIssuer {
  keyId: string;
  privateKey: KeyObject;
  keySet: KeySet;
  trust: ReturnType<typeof pinsFor>;
  publicKeyB64: string;
}

export function testPpIssuer(keyId = 'pp-test-cloud-k1'): TestIssuer {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicKeyB64 = rawPublicKey(publicKey).toString('base64');
  const keySet: KeySet = { issuer: 'https://pp.test', keys: [{ key_id: keyId, alg: 'ed25519', public_key_b64: publicKeyB64 }] };
  return { keyId, privateKey, keySet, trust: pinsFor(keySet), publicKeyB64 };
}

export interface MintOptions {
  fingerprint: string;
  requestId: string;
  status?: 'APPROVED' | 'DENIED';
  canonicalization?: 'jcs_v2' | 'jcs_v3' | 'jcs_v4' | string;
  receiptId?: string;
  expiresAt?: string | null;
  deciderId?: string | null;
  deciderDisplay?: string | null;
  deciderAuthMethod?: string | null;
  scope?: string;
  laneTool?: string;
  /** Extra or overriding signed fields. */
  fields?: Record<string, unknown>;
}

let counter = 0;

/** The signed payload of an app receipt for an MCP Guard call. */
export function receiptPayload(issuer: TestIssuer, o: MintOptions): Record<string, unknown> {
  const canonicalization = o.canonicalization ?? 'jcs_v3';
  const action = { operation: o.fingerprint, tool: o.laneTool ?? 'mcp_guard' };
  const carrier = canonicalization === 'jcs_v2'
    ? {
        companyId: 'company-a',
        idemKey: `mcp_guard:${o.requestId}`,
        inputHash: `sha256:${'0'.repeat(64)}`,
        requestJson: canonicalJsonText({ action: { ...action, parameters: { server: 'filesystem', tool: 'delete_file' } }, actor: { agentId: 'agent', runId: o.requestId } }),
      }
    : {
        requestCommitment: `sha256:${'1'.repeat(64)}`,
        publicProjectionJson: canonicalJsonText({
          action,
          context: { environment: 'production', reversibility: 'IRREVERSIBLE' },
          intent: { category: 'mcp_tool_call', name: 'mcp_tool_call' },
          projection: 'execute/v1',
        }),
      };
  const payload: Record<string, unknown> = {
    id: o.receiptId ?? `rcpt_test_${++counter}`,
    agentId: 'agent',
    runId: o.requestId,
    status: o.status ?? 'APPROVED',
    receiptVersion: canonicalization === 'jcs_v2' ? 2 : canonicalization === 'jcs_v4' ? 4 : 3,
    canonicalization,
    signatureAlg: 'ed25519',
    signatureKeyId: issuer.keyId,
    createdAt: new Date(Date.now() - 5_000).toISOString(),
    attributionConfidence: 'credentialed',
    scope: o.scope ?? 'production',
    ...carrier,
    ...o.fields,
  };
  const expiresAt = o.expiresAt === undefined ? new Date(Date.now() + 10 * 60_000).toISOString() : o.expiresAt;
  if (expiresAt !== null) payload.expiresAt = expiresAt;
  const deciderId = o.deciderId === undefined ? 'user:u_maria' : o.deciderId;
  if (deciderId !== null) payload.deciderId = deciderId;
  const deciderDisplay = o.deciderDisplay === undefined ? 'Maria Signer' : o.deciderDisplay;
  if (deciderDisplay !== null) payload.deciderDisplay = deciderDisplay;
  const authMethod = o.deciderAuthMethod === undefined ? 'session_stepup_webauthn' : o.deciderAuthMethod;
  if (authMethod !== null) payload.deciderAuthMethod = authMethod;
  return payload;
}

/** Sign payload text the way the app does: Ed25519 over the SHA-256 of the bytes. */
export function signBytes(issuer: TestIssuer, text: string, receiptId: string, status: string, canonicalization: string): CloudReceiptArtifact {
  const bytes = Buffer.from(text, 'utf8');
  const digest = createHash('sha256').update(bytes).digest();
  return {
    receipt_id: receiptId,
    status,
    receipt_version: 3,
    canonicalization,
    key_id: issuer.keyId,
    alg: 'ed25519',
    signed_payload_hash: digest.toString('hex'),
    signature_b64: sign(null, digest, issuer.privateKey).toString('base64'),
    payload_bytes_b64: bytes.toString('base64'),
  };
}

export function mintCloudReceipt(issuer: TestIssuer, o: MintOptions): CloudReceiptArtifact {
  const payload = receiptPayload(issuer, o);
  return signBytes(issuer, canonicalJsonText(payload), String(payload.id), String(payload.status), String(payload.canonicalization));
}

// ---------------------------------------------------------------------------
// A fake Permission Protocol API
// ---------------------------------------------------------------------------

/**
 * The create body Permission Protocol accepts from 0.6.0, validated as strictly as the app
 * does: an unknown key, a wrong type or a value outside these shapes is refused with 400,
 * so a drift in what the guard sends fails a test.
 */
export const CREATE_REQUIRED_KEYS = ['agentId', 'argsHash', 'env', 'server', 'timeoutSec', 'tool'] as const;
export const CREATE_OPTIONAL_KEYS = ['argsPreview', 'effect', 'project', 'ruleId'] as const;

/** The exact create-body key sets 0.6.0 sends for a call held by a detector rule, sorted. */
export const BODY_KEYS_FULL = ['agentId', 'argsHash', 'argsPreview', 'effect', 'env', 'project', 'ruleId', 'server', 'timeoutSec', 'tool'];
/** The same with `cloud.args_preview: false`: no preview, no project (and no effect.target). */
export const BODY_KEYS_NO_PREVIEW = ['agentId', 'argsHash', 'effect', 'env', 'ruleId', 'server', 'timeoutSec', 'tool'];

/** What the app refuses in `effect.target`: control and format characters, line and paragraph separators, spaces other than U+0020, Hangul fillers, blank Braille, variation selectors. */
const REFUSED_TARGET_CHAR = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\u115F\u1160\u3164\uFFA0\u2800\uFE00-\uFE0F\u{E0100}-\u{E01EF}]|(?! )\p{Zs}/u;

export function createBodyProblem(body: unknown): string | null {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return 'body is not an object';
  const b = body as Record<string, unknown>;
  const allowed = new Set<string>([...CREATE_REQUIRED_KEYS, ...CREATE_OPTIONAL_KEYS]);
  for (const k of Object.keys(b)) if (!allowed.has(k)) return `Unrecognized key: ${k}`;
  for (const k of CREATE_REQUIRED_KEYS) if (!(k in b)) return `Missing key: ${k}`;
  for (const k of ['agentId', 'argsHash', 'env', 'server', 'tool'] as const) if (typeof b[k] !== 'string' || !b[k]) return `${k} must be a non-empty string`;
  if (!Number.isInteger(b.timeoutSec) || (b.timeoutSec as number) <= 0) return 'timeoutSec must be a positive integer';
  if ('argsPreview' in b && (typeof b.argsPreview !== 'string' || Buffer.byteLength(b.argsPreview, 'utf8') > 2048)) return 'argsPreview must be a string of at most 2048 bytes';
  if ('ruleId' in b && (typeof b.ruleId !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(b.ruleId))) return 'ruleId is malformed';
  if ('ruleId' in b && maskText(b.ruleId as string) !== b.ruleId) return 'ruleId looks like a credential';
  if ('project' in b) {
    const p = b.project;
    if (typeof p !== 'string' || !/^[A-Za-z0-9_.@ -]{1,64}$/.test(p) || p.trim() !== p) return 'project is malformed';
    if (maskText(p) !== p) return 'project looks like a credential';
  }
  if ('effect' in b) {
    const e = b.effect;
    if (typeof e !== 'object' || e === null || Array.isArray(e)) return 'effect must be an object';
    const effect = e as Record<string, unknown>;
    for (const k of Object.keys(effect)) if (!['detector', 'kind', 'target', 'parsed'].includes(k)) return `Unrecognized key: effect.${k}`;
    if (typeof effect.detector !== 'string' || !/^[a-z0-9_]{1,40}$/.test(effect.detector)) return 'effect.detector is malformed';
    if (typeof effect.kind !== 'string' || !/^[a-z0-9_]{1,40}$/.test(effect.kind)) return 'effect.kind is malformed';
    if (typeof effect.parsed !== 'boolean') return 'effect.parsed must be a boolean';
    if ('target' in effect && (typeof effect.target !== 'string' || !effect.target || Array.from(effect.target).length > 120)) return 'effect.target must be 1 to 120 characters';
    if ('target' in effect && REFUSED_TARGET_CHAR.test(effect.target as string)) return 'effect.target has a refused character';
  }
  return null;
}

export type FakeDecision = 'approve' | 'reject' | 'frozen' | 'never' | 'tampered' | 'wrong-fingerprint' | 'unsigned-approve';

export interface FakePp {
  url: string;
  issuer: TestIssuer;
  /** What the next created request resolves to, after `decideAfterReads` status reads. */
  decision: FakeDecision;
  decideAfterReads: number;
  /** Requests received, newest last. */
  calls: Array<{ method: string; path: string; authorization: string | null; body: any }>;
  redeemed: string[];
  /** Origin for the links in answers (approvalUrl, receipt url), when they should not be this server's own. */
  publicUrl: string | null;
  /** Device login: what the person in the browser does, after `pollsBeforeDecision` token polls. */
  device: { decision: 'connect' | 'cancel' | 'never'; pollsBeforeDecision: number; workspace: { name: string; slug: string }; started: number };
  close(): Promise<void>;
}

interface FakeRequest {
  id: string;
  fingerprint: string;
  decision: FakeDecision;
  readsLeft: number;
  redeemed: boolean;
  receiptId: string;
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

const sha256 = (text: string): string => `sha256:${createHash('sha256').update(text, 'utf8').digest('hex')}`;

export async function startFakePp(token: string): Promise<FakePp> {
  const issuer = testPpIssuer();
  const requests = new Map<string, FakeRequest>();
  let n = 0;

  const state: FakePp = {
    url: '', issuer, decision: 'approve', decideAfterReads: 1, calls: [], redeemed: [], publicUrl: null, close: async () => undefined,
    device: { decision: 'connect', pollsBeforeDecision: 1, workspace: { name: 'Acme Eng', slug: 'acme-eng' }, started: 0 },
  };
  const devicePolls = new Map<string, number>();

  const links = (): string => state.publicUrl ?? state.url;
  function view(r: FakeRequest): Record<string, unknown> {
    const base = { requestId: r.id, fingerprint: r.fingerprint };
    const receipt = (status: 'APPROVED' | 'DENIED', artifact: CloudReceiptArtifact, deciderId: string) => ({
      id: r.receiptId, url: `${links()}/r/${r.receiptId}`, decision: status === 'APPROVED' ? 'approve' : 'deny',
      requestId: r.id, fingerprint: r.fingerprint, decider: { id: deciderId, display: 'Maria Signer', authMethod: 'session_stepup_webauthn' }, artifact,
    });
    if (r.decision === 'frozen') {
      const artifact = mintCloudReceipt(issuer, { fingerprint: r.fingerprint, requestId: r.id, receiptId: r.receiptId, status: 'DENIED', deciderId: 'system/pp-engine', deciderDisplay: null, deciderAuthMethod: null });
      return { ...base, status: 'denied', approvalUrl: null, reason: 'Global freeze is active', reasonCodes: ['GLOBAL_FREEZE_ACTIVE'], receipt: receipt('DENIED', artifact, 'system/pp-engine') };
    }
    if (r.readsLeft > 0 || r.decision === 'never') {
      return { ...base, status: 'pending', approvalUrl: `${links()}/sign/${r.id}`, retryAfterSec: 1, receipt: null };
    }
    if (r.decision === 'reject') {
      const artifact = mintCloudReceipt(issuer, { fingerprint: r.fingerprint, requestId: r.id, receiptId: r.receiptId, status: 'DENIED' });
      return { ...base, status: 'denied', approvalUrl: null, reason: 'Approval was denied: not this one', receipt: receipt('DENIED', artifact, 'user:u_maria') };
    }
    if (r.decision === 'unsigned-approve') {
      return { ...base, status: 'approved', approvalUrl: null, receipt: null };
    }
    const fingerprint = r.decision === 'wrong-fingerprint' ? sha256('another call') : r.fingerprint;
    let artifact = mintCloudReceipt(issuer, { fingerprint, requestId: r.id, receiptId: r.receiptId });
    if (r.decision === 'tampered') {
      // The API claims a later expiry than was signed: same signature, edited bytes.
      const payload = JSON.parse(Buffer.from(artifact.payload_bytes_b64, 'base64').toString('utf8'));
      payload.expiresAt = new Date(Date.now() + 24 * 3_600_000).toISOString();
      const bytes = Buffer.from(canonicalJsonText(payload), 'utf8');
      artifact = { ...artifact, payload_bytes_b64: bytes.toString('base64'), signed_payload_hash: createHash('sha256').update(bytes).digest('hex') };
    }
    return { ...base, status: 'approved', approvalUrl: null, receipt: receipt('APPROVED', artifact, 'user:u_maria') };
  }

  const server: Server = createServer(async (req, res) => {
    const path = req.url ?? '';
    const raw = await readBody(req);
    let body: any = null;
    try { body = raw ? JSON.parse(raw) : null; } catch { body = raw; }
    state.calls.push({ method: req.method ?? '', path, authorization: req.headers.authorization ?? null, body });
    const send = (status: number, json: unknown): void => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(json));
    };
    // Device login: the guard has no token yet.
    if (req.method === 'POST' && path === '/api/mcp/device/start') {
      state.device.started += 1;
      const deviceCode = `ppdc_${String(state.device.started).padStart(43, 'd')}`;
      devicePolls.set(deviceCode, 0);
      return send(201, {
        deviceCode, userCode: 'ABCD-EFGH', verificationUrl: `${state.url}/mcp/connect`, verificationUrlComplete: `${state.url}/mcp/connect?code=ABCD-EFGH`, expiresInSec: 600, intervalSec: 1,
      });
    }
    if (req.method === 'POST' && path === '/api/mcp/device/token') {
      const polls = devicePolls.get(body?.deviceCode);
      if (polls === undefined) return send(400, { error: { code: 'DEVICE_CODE_INVALID', message: 'That is not a device code.' } });
      devicePolls.set(body.deviceCode, polls + 1);
      if (state.device.decision === 'never' || polls < state.device.pollsBeforeDecision) return send(200, { status: 'pending', intervalSec: 1 });
      if (state.device.decision === 'cancel') return send(403, { error: { code: 'DEVICE_LOGIN_CANCELLED', message: 'The login was cancelled in the browser.' } });
      devicePolls.delete(body.deviceCode);
      return send(200, { status: 'connected', token, tokenId: 'key_fake_1', workspace: state.device.workspace });
    }
    if (req.headers.authorization !== `Bearer ${token}`) return send(401, { error: { code: 'UNAUTHORIZED', message: 'bad token' } });

    if (req.method === 'POST' && path === '/api/mcp/approval-requests') {
      const problem = createBodyProblem(body);
      if (problem) return send(400, { error: { code: 'VALIDATION_ERROR', message: problem } });
      const fingerprint = sha256(canonicalJsonText({ argsHash: body.argsHash, server: body.server, tool: body.tool }));
      const r: FakeRequest = { id: `mcpreq_${String(++n).padStart(32, '0')}`, fingerprint, decision: state.decision, readsLeft: state.decideAfterReads, redeemed: false, receiptId: `rcpt_fake_${n}` };
      requests.set(r.id, r);
      return send(201, r.decision === 'frozen' ? view(r) : { requestId: r.id, fingerprint, status: 'pending', approvalUrl: `${links()}/sign/${r.id}`, retryAfterSec: 1, receipt: null });
    }
    const match = path.match(/^\/api\/mcp\/approval-requests\/([A-Za-z0-9_]+)(\/redeem)?$/);
    const r = match ? requests.get(match[1]) : undefined;
    if (!match || !r) return send(404, { error: { code: 'NOT_FOUND', message: 'no such request' } });
    if (req.method === 'GET' && !match[2]) {
      const answer = view(r);
      if (r.readsLeft > 0) r.readsLeft -= 1;
      return send(200, answer);
    }
    if (req.method === 'POST' && match[2]) {
      if (r.redeemed) return send(409, { error: { code: 'ALREADY_REDEEMED', message: 'already redeemed' } });
      if (r.decision !== 'approve' && r.decision !== 'tampered' && r.decision !== 'wrong-fingerprint') return send(409, { error: { code: 'NOT_APPROVED', message: 'not approved' } });
      r.redeemed = true;
      state.redeemed.push(r.id);
      return send(200, { requestId: r.id, receiptId: r.receiptId, fingerprint: r.fingerprint, redeemedAt: new Date().toISOString() });
    }
    return send(405, { error: { code: 'METHOD_NOT_ALLOWED', message: 'no' } });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  state.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  state.close = () => new Promise<void>((resolve) => { server.closeAllConnections?.(); server.close(() => resolve()); });
  return state;
}
