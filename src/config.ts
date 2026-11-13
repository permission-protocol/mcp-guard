import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import { PRODUCTION_API_URL } from './cloud/pinned-keys.js';
import type { KeySetEntry } from './signing/keys.js';
import { DETECTOR_NAMES, isDetectorName, type DetectorName } from './detect/index.js';

export type Action = 'allow' | 'block' | 'require_approval';

/** A condition on one named top-level string argument. Exactly one of equals / contains / pattern. */
export interface MatchCondition {
  equals?: string;
  contains?: string;
  pattern?: string;
  ignore_case?: boolean;
  /** `pattern`, compiled once at load. */
  regex?: RegExp;
}

/** Run a named detector over the listed arguments; the rule matches when it fires on any. */
export interface DetectSpec {
  detector: DetectorName;
  args: string[];
}

/** What counts as production, named in the policy's `targets:` section. Fixed set. */
export const TARGET_KINDS = ['databases', 'cloud_accounts', 'kube_contexts', 'git_branches'] as const;
export type TargetKind = (typeof TARGET_KINDS)[number];
export type Targets = Record<TargetKind, string[]>;
export const MAX_TARGETS_PER_KIND = 64;
export const MAX_TARGET_NAME_LENGTH = 128;
/** Literal names only: no patterns. Letters, digits and . _ - : / @, starting with a letter or digit. */
const TARGET_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/@-]*$/;
const MENTIONS_KEYS = new Set(['in', 'args']);

/** Hold a call whose listed arguments name one of the policy's production targets. */
export interface MentionsTargetSpec {
  /** Target kinds to look for; all kinds when the policy omitted `in`. */
  in: TargetKind[];
  args: string[];
}

/** Matches any tool, for rules narrowed by `match` or `detect`. */
export const ANY_TOOL = '*';
export const MAX_PATTERN_LENGTH = 512;
const MAX_DETECT_ARGS = 16;
const MATCH_KEYS = new Set(['equals', 'contains', 'pattern', 'ignore_case']);
const DETECT_KEYS = new Set(['detector', 'args']);

// Permission Deck Slice 1: reversibility is the primary risk axis.
export type Reversibility = 'reversible' | 'irreversible';

export interface Rule {
  id: string;
  /** JSON-RPC method this rule governs. Defaults to `tools/call`. */
  method?: string;
  /** Tool name; required for `tools/call` rules, forbidden for other methods. */
  tool?: string;
  /** All conditions must hold. Keys are top-level argument names. */
  match?: Record<string, MatchCondition>;
  /** Narrow the rule to calls a detector flags. */
  detect?: DetectSpec;
  /** Narrow the rule to calls whose arguments name a production target. */
  mentions_target?: MentionsTargetSpec;
  action: Action;
  /**
   * Observe this rule only: when it matches, the match is recorded as what the rule would
   * have done, and evaluation goes on to the next rule as if this one were absent.
   */
  observe?: boolean;
  // --- Permission Deck classifier axes (all optional) ---
  reversibility?: Reversibility;  // reversible -> countdown auto-release; irreversible -> hard stop
  countdown_seconds?: number;     // reversible holds auto-release after this many seconds
  cap_usd?: number;               // spend cap: under cap may act+verify, at/over cap hard-stops
  amount_arg?: string;            // the tool argument that carries the amount for cap_usd
  verify_threshold?: number;      // 0-100; auto-executed actions below this confidence route to Verify
  receipt_ttl_seconds?: number;   // overrides the receipt expiry for this rule's receipts
}

export type Mode = 'enforce' | 'observe';
export type SigningMode = 'required' | 'off';

export interface Config {
  default_action: Action;
  mode: Mode;
  rules: Rule[];
  /** Held requests expire after this many seconds. */
  approval_ttl_seconds: number;
  /** Receipts for unscoped actions expire this many seconds after issue. */
  receipt_ttl_seconds: number;
  /** Receipts for scoped actions (merge, migration, deploy) expire this many seconds after issue. */
  scoped_receipt_ttl_seconds: number;
  /** Names the MCP server in receipts (never its command line, which can hold secrets). */
  server_label: string;
  /** `required` (default): every decision is signed or refused. `off`: unsigned records no gate accepts. */
  signing: SigningMode;
  /** sha256 of the policy source, bound into every receipt. */
  policy_sha256: string;
  /** Present: held calls are decided by a named human through Permission Protocol. Absent: local-only. */
  cloud?: CloudConfig;
  /** Present when the policy has a `targets:` section. Names are lower-cased. */
  targets?: Targets;
}

export type CloudEnvironment = 'development' | 'staging' | 'production';

export interface CloudConfig {
  /** The Permission Protocol API. Defaults to production. */
  api_url: string;
  /** A label sent with each request and shown to the signer. It clears nothing. */
  environment: CloudEnvironment;
  /** How long a held call waits for a signature before it is refused. */
  approval_timeout_seconds: number;
  /**
   * The receipt-signing keys to pin, ONLY for a non-production api_url (a staging or
   * local Permission Protocol). For the production API the keys are pinned in the
   * release (cloud/pinned-keys.ts) and naming any here is an error.
   */
  trust_keys?: KeySetEntry[];
  /** `false`: send no usage heartbeat (docs/heartbeat.md). Absent: on. */
  heartbeat?: boolean;
}

export const DEFAULT_APPROVAL_TTL_SECONDS = 900;
export const DEFAULT_RECEIPT_TTL_SECONDS = 3600;
export const DEFAULT_SCOPED_RECEIPT_TTL_SECONDS = 900;
/** No receipt lives longer than a day. */
export const MAX_RECEIPT_TTL_SECONDS = 86_400;
export const DEFAULT_SERVER_LABEL = 'mcp-server';
const SERVER_LABEL_PATTERN = /^[A-Za-z0-9._:/@-]{1,64}$/;
export const TOOLS_CALL = 'tools/call';
export const DEFAULT_CLOUD_APPROVAL_TIMEOUT_SECONDS = 600;
export const MIN_CLOUD_APPROVAL_TIMEOUT_SECONDS = 30;
export const MAX_CLOUD_APPROVAL_TIMEOUT_SECONDS = 3600;
const CLOUD_ENVIRONMENTS: CloudEnvironment[] = ['development', 'staging', 'production'];
const CLOUD_KEYS = new Set(['api_url', 'environment', 'approval_timeout_seconds', 'trust_keys', 'heartbeat']);
const TRUST_KEY_KEYS = new Set(['key_id', 'alg', 'public_key_b64']);

const VALID_ACTIONS: Action[] = ['allow', 'block', 'require_approval'];
const VALID_MODES: Mode[] = ['enforce', 'observe'];
const VALID_REVERSIBILITY: Reversibility[] = ['reversible', 'irreversible'];
const VALID_SIGNING: SigningMode[] = ['required', 'off'];
const TOP_LEVEL_KEYS = new Set([
  'default_action', 'mode', 'rules', 'approval_ttl_seconds', 'receipt_ttl_seconds', 'scoped_receipt_ttl_seconds', 'server_label', 'signing', 'cloud', 'targets',
]);
const RULE_KEYS = new Set([
  'id', 'method', 'tool', 'match', 'detect', 'mentions_target', 'observe', 'action', 'reversibility', 'countdown_seconds', 'cap_usd', 'amount_arg', 'verify_threshold', 'receipt_ttl_seconds',
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
  const receiptTtl = receiptTtlSeconds(parsed.receipt_ttl_seconds, 'receipt_ttl_seconds', DEFAULT_RECEIPT_TTL_SECONDS);
  const scopedReceiptTtl = receiptTtlSeconds(parsed.scoped_receipt_ttl_seconds, 'scoped_receipt_ttl_seconds', DEFAULT_SCOPED_RECEIPT_TTL_SECONDS);

  const serverLabel = parsed.server_label ?? DEFAULT_SERVER_LABEL;
  if (typeof serverLabel !== 'string' || !SERVER_LABEL_PATTERN.test(serverLabel)) {
    throw new Error('Invalid server_label: 1-64 characters of letters, digits and . _ : / @ -');
  }
  const signing: SigningMode = parsed.signing ?? 'required';
  if (!VALID_SIGNING.includes(signing)) {
    throw new Error(`Invalid signing: "${parsed.signing}". Must be one of: ${VALID_SIGNING.join(', ')}`);
  }

  if (!Array.isArray(parsed.rules)) {
    throw new Error('Config must include a "rules" array');
  }

  const targets = parsed.targets === undefined ? undefined : parseTargets(parsed.targets);

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
    if (!VALID_ACTIONS.includes(r.action)) {
      throw new Error(`Rule ${i} has invalid action: "${r.action}"`);
    }

    const conditional = r.match !== undefined || r.detect !== undefined || r.mentions_target !== undefined;
    if (conditional && method !== TOOLS_CALL) {
      throw new Error(`Rule ${i}: "match", "detect" and "mentions_target" apply only to ${TOOLS_CALL} rules`);
    }
    if (r.tool === ANY_TOOL && !conditional) {
      throw new Error(`Rule ${i}: tool "*" requires "match" or "detect" (or "mentions_target"; a bare wildcard would match every call)`);
    }
    const match = r.match === undefined ? undefined : parseMatch(r.match, i);
    const detect = r.detect === undefined ? undefined : parseDetect(r.detect, i);
    if (detect && r.action === 'allow') {
      throw new Error(`Rule ${i}: "detect" finds dangerous calls; it cannot be used with action "allow"`);
    }
    let mentionsTarget: MentionsTargetSpec | undefined;
    if (r.mentions_target !== undefined) {
      if (!targets) throw new Error(`Rule ${i}: "mentions_target" needs a top-level "targets:" section naming what counts as production`);
      if (r.action === 'allow') throw new Error(`Rule ${i}: "mentions_target" finds production calls; it cannot be used with action "allow"`);
      mentionsTarget = parseMentionsTarget(r.mentions_target, i);
    }
    if (r.observe !== undefined && typeof r.observe !== 'boolean') throw new Error(`Rule ${i}: observe must be true or false`);
    const observe = r.observe === true;
    if (observe && r.action === 'allow') throw new Error(`Rule ${i}: observe applies to block and require_approval rules (an allow rule has nothing to observe)`);

    // First match wins. An unconditional rule for a target matches every call to it, so
    // a second unconditional rule, or any later conditional rule, for that target is dead.
    const target = `${method}\u0000${r.tool ?? ''}`;
    if (seenTargets.has(target)) {
      if (!conditional && !observe) throw new Error(`Rule ${i} duplicates another rule for ${r.tool ? `tool "${r.tool}"` : `method "${method}"`}`);
      throw new Error(`Rule ${i} ("${r.id}") can never match: an earlier rule without match/detect already matches every call to tool "${r.tool}"`);
    }
    // An observed rule never ends evaluation, so it cannot shadow a later rule.
    if (!conditional && !observe) seenTargets.add(target);
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
    const ruleReceiptTtl = r.receipt_ttl_seconds === undefined ? undefined : receiptTtlSeconds(r.receipt_ttl_seconds, `rule ${i} receipt_ttl_seconds`, 0);

    return {
      id: r.id,
      method,
      ...(r.tool !== undefined ? { tool: r.tool } : {}),
      ...(match ? { match } : {}),
      ...(detect ? { detect } : {}),
      ...(mentionsTarget ? { mentions_target: mentionsTarget } : {}),
      action: r.action as Action,
      ...(observe ? { observe: true } : {}),
      ...(r.reversibility !== undefined ? { reversibility: r.reversibility as Reversibility } : {}),
      ...(r.countdown_seconds !== undefined ? { countdown_seconds: r.countdown_seconds } : {}),
      ...(r.cap_usd !== undefined ? { cap_usd: r.cap_usd, amount_arg: r.amount_arg } : {}),
      ...(r.verify_threshold !== undefined ? { verify_threshold: r.verify_threshold } : {}),
      ...(ruleReceiptTtl !== undefined ? { receipt_ttl_seconds: ruleReceiptTtl } : {}),
    };
  });

  return {
    default_action: parsed.default_action as Action,
    mode,
    rules,
    approval_ttl_seconds: approvalTtl,
    receipt_ttl_seconds: receiptTtl,
    scoped_receipt_ttl_seconds: scopedReceiptTtl,
    server_label: serverLabel,
    signing,
    policy_sha256: createHash('sha256').update(raw).digest('hex'),
    ...(parsed.cloud !== undefined ? { cloud: parseCloud(parsed.cloud) } : {}),
    ...(targets ? { targets } : {}),
  };
}

/**
 * `targets:` maps each kind to a list of literal names. A kind may be absent or empty
 * (it then names nothing); anything else malformed is an error.
 */
function parseTargets(value: unknown): Targets {
  if (value === null) value = {};
  if (typeof value !== 'object' || Array.isArray(value)) throw new Error(`Invalid targets: must map ${TARGET_KINDS.join(', ')} to lists of names`);
  const out = Object.fromEntries(TARGET_KINDS.map((k) => [k, [] as string[]])) as Targets;
  for (const [key, list] of Object.entries(value as Record<string, unknown>)) {
    if (!(TARGET_KINDS as readonly string[]).includes(key)) throw new Error(`Unknown targets key: "${key}". Must be one of: ${TARGET_KINDS.join(', ')}`);
    if (list === null) continue;
    if (!Array.isArray(list)) throw new Error(`Invalid targets.${key}: must be a list of names`);
    if (list.length > MAX_TARGETS_PER_KIND) throw new Error(`Invalid targets.${key}: at most ${MAX_TARGETS_PER_KIND} names`);
    const seen = new Set<string>();
    for (const name of list) {
      // A bare 012345678901 is a YAML number and loses its leading zero: names must be strings.
      if (typeof name !== 'string') throw new Error(`Invalid targets.${key}: every name must be a quoted string (quote account ids: "012345678901")`);
      const text = name;
      if (text.length < 2 || text.length > MAX_TARGET_NAME_LENGTH || !TARGET_NAME_PATTERN.test(text)) {
        throw new Error(`Invalid targets.${key} name "${text.slice(0, 40)}": 2-${MAX_TARGET_NAME_LENGTH} characters of letters, digits and . _ - : / @, starting with a letter or digit (literal names, not patterns)`);
      }
      const lower = text.toLowerCase();
      if (seen.has(lower)) throw new Error(`Invalid targets.${key}: "${text}" is listed twice`);
      seen.add(lower);
      out[key as TargetKind].push(lower);
    }
  }
  return out;
}

function parseMentionsTarget(value: unknown, i: number): MentionsTargetSpec {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`Rule ${i}: "mentions_target" must be an object with args (and optionally in)`);
  const m = value as Record<string, unknown>;
  for (const key of Object.keys(m)) {
    if (!MENTIONS_KEYS.has(key)) throw new Error(`Rule ${i} mentions_target has unknown key: "${key}"`);
  }
  let kinds: TargetKind[] = [...TARGET_KINDS];
  if (m.in !== undefined) {
    if (!Array.isArray(m.in) || m.in.length === 0) throw new Error(`Rule ${i} mentions_target.in must be a non-empty list of: ${TARGET_KINDS.join(', ')}`);
    for (const k of m.in) {
      if (!(TARGET_KINDS as readonly unknown[]).includes(k)) throw new Error(`Rule ${i} mentions_target.in "${String(k)}" is unknown. Must be one of: ${TARGET_KINDS.join(', ')}`);
    }
    if (new Set(m.in).size !== m.in.length) throw new Error(`Rule ${i} mentions_target.in lists a kind twice`);
    kinds = m.in as TargetKind[];
  }
  if (!Array.isArray(m.args) || m.args.length === 0) throw new Error(`Rule ${i} mentions_target.args must be a non-empty list of argument names`);
  if (m.args.length > MAX_DETECT_ARGS) throw new Error(`Rule ${i} mentions_target.args lists more than ${MAX_DETECT_ARGS} arguments`);
  const args = m.args.map((a) => argName(a, `Rule ${i} mentions_target.args`));
  if (new Set(args).size !== args.length) throw new Error(`Rule ${i} mentions_target.args lists an argument twice`);
  return { in: kinds, args };
}

function argName(v: unknown, where: string): string {
  if (typeof v !== 'string' || !v) throw new Error(`${where}: argument names must be non-empty strings`);
  if (v.startsWith('_pp')) throw new Error(`${where}: cannot read agent metadata (_pp)`);
  return v;
}

function parseMatch(value: unknown, i: number): Record<string, MatchCondition> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`Rule ${i}: "match" must map argument names to conditions`);
  const entries = Object.entries(value as Record<string, unknown>);
  if (!entries.length) throw new Error(`Rule ${i}: "match" must name at least one argument`);
  const out: Record<string, MatchCondition> = {};
  for (const [arg, raw] of entries) {
    const where = `Rule ${i} match.${arg}`;
    argName(arg, `Rule ${i} match`);
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error(`${where} must be an object with one of: equals, contains, pattern`);
    const cond = raw as Record<string, unknown>;
    for (const key of Object.keys(cond)) {
      if (!MATCH_KEYS.has(key)) throw new Error(`${where} has unknown key: "${key}"`);
    }
    const ops = (['equals', 'contains', 'pattern'] as const).filter((k) => cond[k] !== undefined);
    if (ops.length !== 1) throw new Error(`${where} must have exactly one of: equals, contains, pattern`);
    const op = ops[0];
    if (typeof cond[op] !== 'string') throw new Error(`${where}.${op} must be a string`);
    if (cond.ignore_case !== undefined && typeof cond.ignore_case !== 'boolean') throw new Error(`${where}.ignore_case must be true or false`);
    const text = cond[op] as string;
    const ignoreCase = cond.ignore_case === true;
    const parsed: MatchCondition = { [op]: text, ...(ignoreCase ? { ignore_case: true } : {}) };
    if (op === 'contains' && !text) throw new Error(`${where}.contains must not be empty`);
    if (op === 'pattern') {
      if (!text) throw new Error(`${where}.pattern must not be empty`);
      if (text.length > MAX_PATTERN_LENGTH) throw new Error(`${where}.pattern is longer than ${MAX_PATTERN_LENGTH} characters`);
      try {
        parsed.regex = new RegExp(text, ignoreCase ? 'i' : '');
      } catch (err: any) {
        throw new Error(`${where}.pattern is not a valid regular expression (${err.message})`);
      }
    }
    out[arg] = parsed;
  }
  return out;
}

function parseDetect(value: unknown, i: number): DetectSpec {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`Rule ${i}: "detect" must be an object with detector and args`);
  const d = value as Record<string, unknown>;
  for (const key of Object.keys(d)) {
    if (!DETECT_KEYS.has(key)) throw new Error(`Rule ${i} detect has unknown key: "${key}"`);
  }
  if (!isDetectorName(d.detector)) {
    throw new Error(`Rule ${i} detect.detector "${String(d.detector)}" is unknown. Must be one of: ${DETECTOR_NAMES.join(', ')}`);
  }
  if (!Array.isArray(d.args) || d.args.length === 0) throw new Error(`Rule ${i} detect.args must be a non-empty list of argument names`);
  if (d.args.length > MAX_DETECT_ARGS) throw new Error(`Rule ${i} detect.args lists more than ${MAX_DETECT_ARGS} arguments`);
  const args = d.args.map((a) => argName(a, `Rule ${i} detect.args`));
  if (new Set(args).size !== args.length) throw new Error(`Rule ${i} detect.args lists an argument twice`);
  return { detector: d.detector, args };
}

/** The origin of an API URL: https anywhere, http only on loopback. No path, query or credentials. */
function cloudOrigin(value: unknown): string {
  if (typeof value !== 'string') throw new Error('Invalid cloud.api_url: must be a URL');
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('Invalid cloud.api_url: must be a URL');
  }
  const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw new Error('Invalid cloud.api_url: must be https (http is accepted only for localhost)');
  }
  if (url.username || url.password || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) {
    throw new Error('Invalid cloud.api_url: must be an origin, without credentials, path, query or fragment');
  }
  return url.origin;
}

function parseCloud(value: unknown): CloudConfig {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid cloud: must be an object');
  const cloud = value as Record<string, unknown>;
  for (const key of Object.keys(cloud)) {
    if (!CLOUD_KEYS.has(key)) throw new Error(`Unknown cloud key: "${key}"`);
  }
  const apiUrl = cloud.api_url === undefined ? PRODUCTION_API_URL : cloudOrigin(cloud.api_url);
  const environment = (cloud.environment ?? 'production') as CloudEnvironment;
  if (!CLOUD_ENVIRONMENTS.includes(environment)) {
    throw new Error(`Invalid cloud.environment: must be one of: ${CLOUD_ENVIRONMENTS.join(', ')}`);
  }
  const timeout = positiveInt(cloud.approval_timeout_seconds, 'cloud.approval_timeout_seconds', DEFAULT_CLOUD_APPROVAL_TIMEOUT_SECONDS);
  if (timeout < MIN_CLOUD_APPROVAL_TIMEOUT_SECONDS || timeout > MAX_CLOUD_APPROVAL_TIMEOUT_SECONDS) {
    throw new Error(`Invalid cloud.approval_timeout_seconds: ${MIN_CLOUD_APPROVAL_TIMEOUT_SECONDS} to ${MAX_CLOUD_APPROVAL_TIMEOUT_SECONDS}`);
  }

  if (cloud.heartbeat !== undefined && typeof cloud.heartbeat !== 'boolean') throw new Error('Invalid cloud.heartbeat: must be true or false');
  const heartbeat = cloud.heartbeat === false ? { heartbeat: false } : {};

  const production = apiUrl === PRODUCTION_API_URL;
  if (cloud.trust_keys === undefined) {
    if (!production) throw new Error('cloud.trust_keys is required when cloud.api_url is not the production API: name the receipt-signing keys to pin');
    return { api_url: apiUrl, environment, approval_timeout_seconds: timeout, ...heartbeat };
  }
  // The production keys are pinned in the release. A policy file cannot replace them.
  if (production) throw new Error('cloud.trust_keys cannot be set for the production API: its keys are pinned in this release');
  if (!Array.isArray(cloud.trust_keys) || cloud.trust_keys.length === 0) throw new Error('Invalid cloud.trust_keys: must be a non-empty list');
  const seen = new Set<string>();
  const trustKeys = cloud.trust_keys.map((entry: unknown, i: number): KeySetEntry => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw new Error(`cloud.trust_keys[${i}] must be an object`);
    const key = entry as Record<string, unknown>;
    for (const name of Object.keys(key)) {
      if (!TRUST_KEY_KEYS.has(name)) throw new Error(`cloud.trust_keys[${i}] has unknown key: "${name}"`);
    }
    if (typeof key.key_id !== 'string' || !key.key_id) throw new Error(`cloud.trust_keys[${i}] missing key_id`);
    if (seen.has(key.key_id)) throw new Error(`cloud.trust_keys[${i}] duplicates key_id "${key.key_id}"`);
    seen.add(key.key_id);
    if ((key.alg ?? 'ed25519') !== 'ed25519') throw new Error(`cloud.trust_keys[${i}]: alg must be ed25519`);
    if (typeof key.public_key_b64 !== 'string' || Buffer.from(key.public_key_b64, 'base64').length !== 32) {
      throw new Error(`cloud.trust_keys[${i}]: public_key_b64 must be a 32-byte Ed25519 public key in base64`);
    }
    return { key_id: key.key_id, alg: 'ed25519', public_key_b64: key.public_key_b64 };
  });
  return { api_url: apiUrl, environment, approval_timeout_seconds: timeout, trust_keys: trustKeys, ...heartbeat };
}

function receiptTtlSeconds(v: unknown, name: string, fallback: number): number {
  const n = positiveInt(v, name, fallback);
  if (n > MAX_RECEIPT_TTL_SECONDS) throw new Error(`Invalid ${name}: at most ${MAX_RECEIPT_TTL_SECONDS} (one day)`);
  return n;
}

function positiveInt(v: unknown, name: string, fallback: number): number {
  if (v === undefined) return fallback;
  if (typeof v !== 'number' || !Number.isInteger(v) || v <= 0) {
    throw new Error(`Invalid ${name}: must be a positive integer`);
  }
  return v;
}
