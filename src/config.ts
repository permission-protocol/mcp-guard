import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';

export type Action = 'allow' | 'block' | 'require_approval';

// Permission Deck Slice 1: reversibility is the primary risk axis.
export type Reversibility = 'reversible' | 'irreversible';

export interface Rule {
  id: string;
  /** JSON-RPC method this rule governs. Defaults to `tools/call`. */
  method?: string;
  /** Tool name; required for `tools/call` rules, forbidden for other methods. */
  tool?: string;
  action: Action;
  // --- Permission Deck classifier axes (all optional) ---
  reversibility?: Reversibility;  // reversible -> countdown auto-release; irreversible -> hard stop
  countdown_seconds?: number;     // reversible holds auto-release after this many seconds
  cap_usd?: number;               // spend cap: under cap may act+verify, at/over cap hard-stops
  amount_arg?: string;            // the tool argument that carries the amount for cap_usd
  verify_threshold?: number;      // 0-100; auto-executed actions below this confidence route to Verify
}

export type Mode = 'enforce' | 'observe';

export interface Config {
  default_action: Action;
  mode: Mode;
  rules: Rule[];
  /** Held requests expire after this many seconds. */
  approval_ttl_seconds: number;
  /** Signed receipts expire this many seconds after issue. */
  receipt_ttl_seconds: number;
  /** sha256 of the policy source, bound into every receipt. */
  policy_sha256: string;
}

export const DEFAULT_APPROVAL_TTL_SECONDS = 900;
export const DEFAULT_RECEIPT_TTL_SECONDS = 900;
export const TOOLS_CALL = 'tools/call';

const VALID_ACTIONS: Action[] = ['allow', 'block', 'require_approval'];
const VALID_MODES: Mode[] = ['enforce', 'observe'];
const VALID_REVERSIBILITY: Reversibility[] = ['reversible', 'irreversible'];
const TOP_LEVEL_KEYS = new Set(['default_action', 'mode', 'rules', 'approval_ttl_seconds', 'receipt_ttl_seconds']);
const RULE_KEYS = new Set([
  'id', 'method', 'tool', 'action', 'reversibility', 'countdown_seconds', 'cap_usd', 'amount_arg', 'verify_threshold',
]);

export function loadConfig(configPath: string): Config {
  let raw: string;
  try {
    raw = readFileSync(configPath, 'utf-8');
  } catch (err: any) {
    throw new Error(`Failed to read config file: ${configPath} (${err.code ?? err.message})`);
  }
  return parseConfig(raw);
}

/** Parse and strictly validate a policy. Anything unrecognized is an error, never ignored. */
export function parseConfig(raw: string): Config {
  const parsed = parse(raw);

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Config must be a YAML object');
  }

  for (const key of Object.keys(parsed)) {
    if (!TOP_LEVEL_KEYS.has(key)) throw new Error(`Unknown config key: "${key}"`);
  }

  if (!VALID_ACTIONS.includes(parsed.default_action)) {
    throw new Error(`Invalid default_action: "${parsed.default_action}". Must be one of: ${VALID_ACTIONS.join(', ')}`);
  }

  const mode: Mode = parsed.mode ?? 'enforce';
  if (!VALID_MODES.includes(mode)) {
    throw new Error(`Invalid mode: "${parsed.mode}". Must be one of: ${VALID_MODES.join(', ')}`);
  }

  const approvalTtl = positiveInt(parsed.approval_ttl_seconds, 'approval_ttl_seconds', DEFAULT_APPROVAL_TTL_SECONDS);
  const receiptTtl = positiveInt(parsed.receipt_ttl_seconds, 'receipt_ttl_seconds', DEFAULT_RECEIPT_TTL_SECONDS);

  if (!Array.isArray(parsed.rules)) {
    throw new Error('Config must include a "rules" array');
  }

  const seenIds = new Set<string>();
  const seenTargets = new Set<string>();
  const rules: Rule[] = parsed.rules.map((r: any, i: number) => {
    if (!r || typeof r !== 'object' || Array.isArray(r)) throw new Error(`Rule ${i} must be an object`);
    for (const key of Object.keys(r)) {
      if (!RULE_KEYS.has(key)) throw new Error(`Rule ${i} has unknown key: "${key}"`);
    }
    if (!r.id || typeof r.id !== 'string') {
      throw new Error(`Rule ${i} missing valid "id"`);
    }
    if (seenIds.has(r.id)) throw new Error(`Rule ${i} duplicates id "${r.id}"`);
    seenIds.add(r.id);

    const method: string = r.method ?? TOOLS_CALL;
    if (typeof method !== 'string' || !method) throw new Error(`Rule ${i} has invalid method`);
    if (method === TOOLS_CALL) {
      if (!r.tool || typeof r.tool !== 'string') throw new Error(`Rule ${i} missing valid "tool"`);
    } else if (r.tool !== undefined) {
      throw new Error(`Rule ${i}: "tool" applies only to ${TOOLS_CALL} rules`);
    }
    const target = `${method}\u0000${r.tool ?? ''}`;
    if (seenTargets.has(target)) {
      throw new Error(`Rule ${i} duplicates another rule for ${r.tool ? `tool "${r.tool}"` : `method "${method}"`}`);
    }
    seenTargets.add(target);

    if (!VALID_ACTIONS.includes(r.action)) {
      throw new Error(`Rule ${i} has invalid action: "${r.action}"`);
    }
    if (r.reversibility !== undefined && !VALID_REVERSIBILITY.includes(r.reversibility)) {
      throw new Error(`Rule ${i} has invalid reversibility: "${r.reversibility}". Must be one of: ${VALID_REVERSIBILITY.join(', ')}`);
    }
    for (const numField of ['countdown_seconds', 'cap_usd', 'verify_threshold'] as const) {
      if (r[numField] !== undefined && (typeof r[numField] !== 'number' || !Number.isFinite(r[numField]) || r[numField] < 0)) {
        throw new Error(`Rule ${i} has invalid ${numField}: must be a non-negative number`);
      }
    }
    if (r.verify_threshold !== undefined && r.verify_threshold > 100) {
      throw new Error(`Rule ${i} has invalid verify_threshold: must be 0-100`);
    }
    if (r.countdown_seconds !== undefined && r.countdown_seconds > 0 && r.reversibility !== 'reversible') {
      throw new Error(`Rule ${i}: countdown_seconds requires reversibility: reversible`);
    }
    if (r.cap_usd !== undefined && (typeof r.amount_arg !== 'string' || !r.amount_arg)) {
      throw new Error(`Rule ${i}: cap_usd requires amount_arg (the tool argument holding the amount)`);
    }
    if (r.amount_arg !== undefined && r.cap_usd === undefined) {
      throw new Error(`Rule ${i}: amount_arg is only valid with cap_usd`);
    }
    if (r.amount_arg !== undefined && r.amount_arg.startsWith('_pp')) {
      throw new Error(`Rule ${i}: amount_arg cannot read agent metadata (_pp)`);
    }

    return {
      id: r.id,
      method,
      ...(r.tool !== undefined ? { tool: r.tool } : {}),
      action: r.action as Action,
      ...(r.reversibility !== undefined ? { reversibility: r.reversibility as Reversibility } : {}),
      ...(r.countdown_seconds !== undefined ? { countdown_seconds: r.countdown_seconds } : {}),
      ...(r.cap_usd !== undefined ? { cap_usd: r.cap_usd, amount_arg: r.amount_arg } : {}),
      ...(r.verify_threshold !== undefined ? { verify_threshold: r.verify_threshold } : {}),
    };
  });

  return {
    default_action: parsed.default_action as Action,
    mode,
    rules,
    approval_ttl_seconds: approvalTtl,
    receipt_ttl_seconds: receiptTtl,
    policy_sha256: createHash('sha256').update(raw).digest('hex'),
  };
}

function positiveInt(v: unknown, name: string, fallback: number): number {
  if (v === undefined) return fallback;
  if (typeof v !== 'number' || !Number.isInteger(v) || v <= 0) {
    throw new Error(`Invalid ${name}: must be a positive integer`);
  }
  return v;
}
