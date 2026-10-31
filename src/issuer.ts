import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { Config, Reversibility, SigningMode } from './config.js';
import { JCS_V2, canonicalJsonText } from './signing/canonical.js';
import { buildArtifact, type ReceiptArtifact } from './signing/artifact.js';
import { loadSigningKey, SigningError, keysDir, type SigningKey } from './keystore.js';

/**
 * Issues receipts in the org receipt standard (`jcs_v2`, F-10 design note section 8).
 *
 * Every final decision becomes a record of the frozen signed fields plus the portable
 * artifact a gate verifies. The signed request names the tool, method, server label,
 * rule and scope, and binds the arguments only by `inputHash`
 * (`pp.hashable_payload.v1`): no raw argument is ever signed, logged or published.
 *
 * The decider is bound honestly (section 8.3): policy decisions sign
 * `system/mcp-guard-policy`; console decisions sign `local:<operator>` with
 * `local_console` and `heuristic` confidence, because the operator name is configured, not
 * authenticated. A console approval with no operator is refused in production.
 *
 * The signer reloads its key for every receipt, so a key revoked or removed while the
 * guard runs stops signing at once. It never creates a key.
 */

export type ReceiptStatus = 'APPROVED' | 'DENIED';
export type RiskTier = 'low' | 'medium' | 'high' | 'critical';

/** The fixed reason-code set (F-10 8.1, INV-20). `RULE_MATCHED` carries the rule id. */
export type ReasonCode =
  | `RULE_MATCHED:${string}`
  | 'DEFAULT_ACTION'
  | 'COUNTDOWN_AUTO_RELEASE'
  | 'OPERATOR_APPROVED'
  | 'OPERATOR_DENIED'
  | 'APPROVAL_EXPIRED';

export const POLICY_DECIDER_ID = 'system/mcp-guard-policy';

export type Decider = { kind: 'policy' } | { kind: 'operator'; operator: string | null };

/** What an approval authorizes for code/infra actions: `scope.capability`, `scope.ref`, `scope.commitSha`. */
export interface ScopeBinding {
  scope?: string;
  scope_ref?: string;
  scope_sha?: string;
}

export interface DecisionInput {
  /** The queue item id for a held call; a fresh id otherwise. Becomes the idempotency key. */
  decisionId?: string;
  /** JSON-RPC method (`tools/call`, `resources/read`, ...) or `github/merge` for a webhook PR. */
  method: string;
  /** Tool name for tools/call; null for other methods. */
  tool: string | null;
  /** What the server receives: tool arguments (agent metadata stripped) or the params. */
  input: unknown;
  status: ReceiptStatus;
  ruleId: string | null;
  reasonCodes: ReasonCode[];
  decider: Decider;
  reversibility?: Reversibility;
  scope?: ScopeBinding;
  /** Overrides the server label (the webhook names GitHub, not the MCP server). */
  resource?: string;
  /** Argument names, for the human summary (values are never shown). */
  argKeys?: string[];
  now?: Date;
}

/** The camelCase receipt record: the `jcs_v2` signed fields. */
export type ReceiptRecord = Record<string, unknown> & { id: string; status: ReceiptStatus; createdAt: string; expiresAt: string };

export interface IssuedReceipt {
  record: ReceiptRecord;
  /** Present when signed. A gate verifies this, never the record. */
  artifact?: ReceiptArtifact;
  /** `signing: off`: written unsigned on purpose. */
  unsigned?: true;
  /** Observe mode only: signing failed and the call went through anyway. */
  signingFailed?: string;
}

export interface IssuerOptions {
  config: Pick<Config, 'mode' | 'signing' | 'server_label' | 'policy_sha256' | 'receipt_ttl_seconds' | 'scoped_receipt_ttl_seconds'> & { rules?: Config['rules'] };
  agentId: string;
  /** Random per proxy start unless given. */
  runId?: string;
  keysDir?: string;
}

/** `pp.hashable_payload.v1`: sha256 of the canonical JSON of `{ tool, operation, input, metadata: null }`. */
export function hashablePayloadInputHash(tool: string, operation: string, input: unknown): string {
  const normalized = JSON.parse(JSON.stringify({ tool, operation, input, metadata: null }));
  return `sha256:${createHash('sha256').update(canonicalJsonText(normalized)).digest('hex')}`;
}

export function policyVersionOf(policySha256: string): string {
  return `mcp-guard-config:sha256:${policySha256}`;
}

function classifyRisk(label: string, argKeys: string[]): RiskTier {
  const text = `${label} ${argKeys.join(' ')}`.toLowerCase();
  if (/(delete|destroy|drop|truncate|wipe|remove)/.test(text)) return 'critical';
  if (/(prod|deploy|release|publish|billing|payment|spend|merge|migrat|auth|admin|secret|token|password|key)/.test(text)) return 'high';
  if (/(write|update|create|patch|modify|sync|email|post|notify)/.test(text)) return 'medium';
  return 'low';
}

function deciderFields(decider: Decider, status: ReceiptStatus, scope: 'production' | 'demo'): Record<string, string> {
  if (decider.kind === 'policy') {
    return {
      deciderId: POLICY_DECIDER_ID,
      deciderDisplay: 'mcp-guard policy',
      deciderAuthMethod: 'policy',
      attributionConfidence: 'credentialed',
    };
  }
  const resolutionType = status === 'APPROVED' ? 'allow_once' : 'deny';
  const operator = decider.operator?.trim();
  if (!operator) {
    if (status === 'APPROVED' && scope === 'production') {
      throw new SigningError('UNATTRIBUTED_PRODUCTION_DECIDER', 'a console approval with no operator cannot mint a production receipt; start the guard with --operator <name>');
    }
    return { deciderAuthMethod: 'local_console', attributionConfidence: 'unattributed', resolutionType };
  }
  return {
    deciderId: `local:${operator}`,
    deciderDisplay: operator,
    deciderAuthMethod: 'local_console',
    attributionConfidence: 'heuristic',
    resolutionType,
  };
}

export class Issuer {
  readonly runId: string;
  private readonly opts: IssuerOptions;

  constructor(opts: IssuerOptions) {
    this.opts = opts;
    this.runId = opts.runId ?? `run_${randomBytes(8).toString('hex')}`;
  }

  get signing(): SigningMode {
    return this.opts.config.signing;
  }

  get serverLabel(): string {
    return this.opts.config.server_label;
  }

  /** The current signing key, or a SigningError. */
  key(): SigningKey {
    return loadSigningKey(this.opts.keysDir ?? keysDir());
  }

  /**
   * Build and sign the receipt for a final decision. Throws SigningError when it cannot
   * sign (enforce mode); in observe mode a signing failure returns a record marked
   * `signingFailed` and no signature. Writes nothing: the caller emits it.
   */
  issue(input: DecisionInput): IssuedReceipt {
    const { config } = this.opts;
    let key: SigningKey | null = null;
    if (config.signing === 'required') {
      try {
        key = this.key();
      } catch (err) {
        if (config.mode === 'observe' && err instanceof SigningError) {
          return { record: this.record(input, null), signingFailed: err.code };
        }
        throw err;
      }
    }
    const record = this.record(input, key);
    if (!key) return { record, unsigned: true };
    return { record, artifact: buildArtifact(record, key.privateKey) };
  }

  private record(input: DecisionInput, key: SigningKey | null): ReceiptRecord {
    const { config, agentId } = this.opts;
    const now = input.now ?? new Date();
    const receiptScope: 'production' | 'demo' = key?.demo ? 'demo' : 'production';
    const scoped = !!input.scope?.scope;
    const ruleTtl = input.ruleId ? config.rules?.find((r) => r.id === input.ruleId)?.receipt_ttl_seconds : undefined;
    const ttl = ruleTtl ?? (scoped ? config.scoped_receipt_ttl_seconds : config.receipt_ttl_seconds);
    const policyVersion = policyVersionOf(config.policy_sha256);
    const inputHash = hashablePayloadInputHash(input.tool ?? input.method, input.method, input.input);
    const label = input.tool ?? input.method;
    const decider = deciderFields(input.decider, input.status, receiptScope);

    const request: Record<string, unknown> = {
      action: {
        operation: input.method,
        resource: input.resource ?? config.server_label,
        ...(input.tool ? { tool: input.tool } : {}),
      },
      context: {
        mode: config.mode,
        ...(input.reversibility ? { reversibility: input.reversibility.toUpperCase() } : {}),
        transport: input.resource ? 'webhook' : 'stdio',
      },
      hashes: { inputHash },
      intent: { category: 'mcp_tool_call', name: 'mcp_guard_decision' },
      policy: {
        decision: {
          outcome: input.status === 'APPROVED' ? 'approved' : 'denied',
          ...(input.ruleId ? { ruleId: input.ruleId } : {}),
          ruleVersion: policyVersion,
        },
      },
      ...(scoped
        ? {
            scope: {
              capability: input.scope!.scope,
              ...(input.scope!.scope_ref ? { ref: input.scope!.scope_ref } : {}),
              ...(input.scope!.scope_sha ? { commitSha: input.scope!.scope_sha } : {}),
            },
          }
        : {}),
    };

    const by = decider.deciderDisplay ? ` by ${decider.deciderDisplay}` : '';
    return {
      id: `rcpt_mg_${now.getTime().toString(36)}_${randomBytes(6).toString('hex')}`,
      idemKey: `mcp-guard:${input.decisionId ?? randomUUID()}`,
      agentId,
      runId: this.runId,
      requestJson: canonicalJsonText(request),
      inputHash,
      status: input.status,
      riskTier: classifyRisk(label, input.argKeys ?? []),
      policyVersion,
      reasonCodes: JSON.stringify(input.reasonCodes),
      summary: `MCP Guard ${input.status === 'APPROVED' ? 'approved' : 'denied'} "${label}"${by}`,
      receiptVersion: 2,
      canonicalization: JCS_V2,
      ...(key ? { signatureAlg: 'ed25519', signatureKeyId: key.keyId } : {}),
      expiresAt: new Date(now.getTime() + ttl * 1000).toISOString(),
      createdAt: now.toISOString(),
      ...decider,
      scope: receiptScope,
    };
  }
}

/** The reason code for a policy decision: the rule that matched, or the default action. */
export function ruleReason(ruleId: string | null): ReasonCode {
  return ruleId ? `RULE_MATCHED:${ruleId}` : 'DEFAULT_ACTION';
}
