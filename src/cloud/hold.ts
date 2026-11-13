import type { KeySet, TrustPins } from '../signing/keys.js';
import type { ReplayCache } from '../verify-core.js';
import { CloudApiError, type CloudClient, type CreateRequestBody } from './client.js';
import { argsHashOf, callFingerprint } from './fingerprint.js';
import { argsPreviewOf, requestContextOf } from './preview.js';
import { verifyCloudReceipt, type CloudReceiptArtifact, type VerifiedCloudReceipt } from './verify.js';

/**
 * One held call, decided by a named human through Permission Protocol.
 *
 *   hash the call locally -> open an approval request -> poll with backoff ->
 *   verify the signed receipt offline against the pinned key -> redeem it once ->
 *   released.
 *
 * FAIL CLOSED. The only path to `released` is a receipt that passed every check in
 * cloud/verify.ts AND a successful redeem. Everything else is one of three refusals,
 * and none of them forwards the call:
 *
 *   denied   a person rejected it, or a freeze, pause or policy refused it
 *   expired  nobody signed before the timeout
 *   blocked  the API could not be reached or answered something the guard cannot
 *            trust: an error, a fingerprint that is not this call's, a receipt that
 *            does not verify, a redeem that did not succeed
 *
 * While waiting, a transient failure of a status read (network, 429, 5xx) is retried
 * until the deadline, because the wait is minutes long and an API restart must not
 * throw away a signature a person is about to give. It can only end in a verified
 * receipt or a refusal. Any other failure blocks at once.
 */

export type CloudOutcome =
  | { kind: 'released'; requestId: string; fingerprint: string; receipt: VerifiedCloudReceipt; receiptUrl: string | null; artifact: CloudReceiptArtifact }
  | { kind: 'denied'; requestId: string; fingerprint: string; reason: string; receipt: VerifiedCloudReceipt | null; receiptUrl: string | null; artifact: CloudReceiptArtifact | null }
  | { kind: 'expired'; requestId: string | null; fingerprint: string; reason: string }
  | { kind: 'blocked'; requestId: string | null; fingerprint: string; code: string; reason: string };

export interface CloudHoldInput {
  client: CloudClient;
  keySet: KeySet;
  trust: TrustPins;
  replayCache: ReplayCache;
  server: string;
  tool: string;
  /**
   * What the server will act on. Hashed here; the hash is sent, and (unless
   * `sendPreview` is false) a preview masked and capped by cloud/preview.ts.
   */
  args: unknown;
  /** `false` (policy `cloud.args_preview: false`): send the hash only, no preview. Default true. */
  sendPreview?: boolean;
  /** The matched rule's id, sent as `ruleId` when it is a plain identifier. Not hashed. */
  ruleId?: string | null;
  /** What the rule's detector found, sent as `effect` (cloud/preview.ts requestContextOf). Not hashed. */
  effect?: { detector: string; kind: string; target?: string; parsed: boolean };
  agentId: string;
  environment: string;
  timeoutSeconds: number;
  /** Called once the request exists, with where a signer decides. */
  onPending?: (info: { requestId: string; approvalUrl: string | null }) => void;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

export { MAX_PREVIEW_BYTES } from './preview.js';
const FIRST_POLL_MS = 1_000;
const MAX_POLL_MS = 5_000;
const POLL_BACKOFF = 1.5;

const str = (v: unknown): string | null => (typeof v === 'string' && v ? v : null);
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const defaultSleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function apiReason(err: unknown): { code: string; reason: string } {
  if (err instanceof CloudApiError) {
    return { code: err.kind === 'HTTP' ? `API_${err.status}${err.apiCode ? `_${err.apiCode}` : ''}` : `API_${err.kind}`, reason: err.message };
  }
  return { code: 'API_ERROR', reason: err instanceof Error ? err.message : String(err) };
}

export async function decideInCloud(input: CloudHoldInput): Promise<CloudOutcome> {
  const now = input.now ?? (() => Date.now());
  const sleep = input.sleep ?? defaultSleep;
  const argsHash = argsHashOf(input.args);
  const fingerprint = callFingerprint({ server: input.server, tool: input.tool, argsHash });
  const blocked = (requestId: string | null, code: string, reason: string): CloudOutcome => ({ kind: 'blocked', requestId, fingerprint, code, reason });
  const deadline = now() + input.timeoutSeconds * 1000;

  const body: CreateRequestBody = {
    tool: input.tool,
    server: input.server,
    argsHash,
    // Masked and capped here, before upload (cloud/preview.ts). Never part of the fingerprint.
    ...(input.sendPreview === false ? {} : { argsPreview: argsPreviewOf(input.args) }),
    agentId: input.agentId,
    env: input.environment,
    timeoutSec: input.timeoutSeconds,
  };
  // Why it was held: rule id and detector finding. Context for the signer, never hashed.
  const context = requestContextOf(input.ruleId, input.effect, input.sendPreview !== false);
  const hasContext = context.ruleId !== undefined || context.effect !== undefined;

  let view: Record<string, unknown>;
  try {
    try {
      view = await input.client.create(hasContext ? { ...body, ...context } : body);
    } catch (err) {
      // A Permission Protocol that validates the body strictly and predates these two
      // fields answers 400: ask once more without them. Any other failure blocks.
      if (!hasContext || !(err instanceof CloudApiError) || err.kind !== 'HTTP' || err.status !== 400) throw err;
      view = await input.client.create(body);
    }
  } catch (err) {
    const { code, reason } = apiReason(err);
    return blocked(null, code, reason);
  }

  const requestId = str(view.requestId);
  if (!requestId) return blocked(null, 'BAD_RESPONSE', 'Permission Protocol returned no request id');
  if (view.fingerprint !== fingerprint) {
    return blocked(requestId, 'FINGERPRINT_MISMATCH', 'Permission Protocol recorded a different fingerprint than this call has');
  }
  input.onPending?.({ requestId, approvalUrl: str(view.approvalUrl) });

  let delay = FIRST_POLL_MS;
  for (;;) {
    const status = view.status;

    if (status === 'approved') {
      const receipt = isRecord(view.receipt) ? view.receipt : null;
      const artifact = receipt && isRecord(receipt.artifact) ? (receipt.artifact as unknown as CloudReceiptArtifact) : null;
      const verified = verifyCloudReceipt(artifact, {
        keySet: input.keySet,
        trust: input.trust,
        fingerprint,
        requestId,
        expect: 'APPROVED',
        now: new Date(now()),
        replayCache: input.replayCache,
      });
      if (!verified.ok) return blocked(requestId, `RECEIPT_${verified.code}`, `The receipt was refused: ${verified.message}`);
      try {
        const redeemed = await input.client.redeem(requestId);
        if (redeemed.receiptId !== verified.receipt.receiptId || redeemed.fingerprint !== fingerprint) {
          return blocked(requestId, 'REDEEM_MISMATCH', 'Permission Protocol redeemed a different receipt than the one verified');
        }
      } catch (err) {
        const { code, reason } = apiReason(err);
        return blocked(requestId, `REDEEM_${code}`, `The receipt could not be redeemed: ${reason}`);
      }
      return { kind: 'released', requestId, fingerprint, receipt: verified.receipt, receiptUrl: str(receipt?.url), artifact: artifact! };
    }

    if (status === 'denied') {
      const receipt = isRecord(view.receipt) ? view.receipt : null;
      const artifact = receipt && isRecord(receipt.artifact) ? (receipt.artifact as unknown as CloudReceiptArtifact) : null;
      // The denial blocks whether or not its receipt verifies; a verified one is recorded as signed.
      const verified = artifact
        ? verifyCloudReceipt(artifact, { keySet: input.keySet, trust: input.trust, fingerprint, requestId, expect: 'DENIED' })
        : null;
      return {
        kind: 'denied',
        requestId,
        fingerprint,
        reason: str(view.reason) ?? 'Denied',
        receipt: verified?.ok ? verified.receipt : null,
        receiptUrl: verified?.ok ? str(receipt?.url) : null,
        artifact: verified?.ok ? artifact : null,
      };
    }

    if (status === 'expired') return { kind: 'expired', requestId, fingerprint, reason: str(view.reason) ?? 'Nobody signed before the request expired' };
    if (status !== 'pending') return blocked(requestId, 'REQUEST_NOT_DECIDABLE', `Permission Protocol reports the request as ${String(status)}`);

    const remaining = deadline - now();
    if (remaining <= 0) {
      return { kind: 'expired', requestId, fingerprint, reason: `Nobody signed within ${input.timeoutSeconds} seconds` };
    }
    await sleep(Math.min(delay, remaining));
    delay = Math.min(Math.round(delay * POLL_BACKOFF), MAX_POLL_MS);

    try {
      view = await input.client.read(requestId);
    } catch (err) {
      if (err instanceof CloudApiError && err.transient) continue; // still pending as far as the guard knows
      const { code, reason } = apiReason(err);
      return blocked(requestId, code, reason);
    }
    if (view.requestId !== requestId || view.fingerprint !== fingerprint) {
      return blocked(requestId, 'FINGERPRINT_MISMATCH', 'Permission Protocol answered for a different request or fingerprint');
    }
  }
}
