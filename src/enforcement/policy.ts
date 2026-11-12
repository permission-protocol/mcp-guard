import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { parse } from 'yaml';

export interface ToolPolicy {
  protected: boolean;
  risk?: string;
  required_authorization?: string;
  allowed_signers?: string[];
  allowed_roles?: string[];
  required_approvals?: number;
  conditions?: Array<{ field: string; equals: any }>;
  max_ttl_seconds?: number;
}

export interface PPConfig {
  tools: Record<string, ToolPolicy>;
  policy_hash?: string;
}

/**
 * A policy that cannot be loaded is an error, never "no tool is protected".
 * Callers treat it as a denial.
 */
export class PolicyError extends Error {
  constructor(readonly code: 'PP_POLICY_MISSING' | 'PP_POLICY_INVALID' | 'PP_POLICY_UNSUPPORTED', message: string) {
    super(message);
  }
}

/**
 * Refuse a tool policy this verifier cannot enforce. A SignedToken carries ONE signature
 * under ONE key_id: the names in `signers` are claims inside it, not separate approvals,
 * so `required_approvals` above 1 could be met by a single key holder. Such a policy is
 * refused outright (checked at load and again at verification), never counted by names.
 */
export function assertEnforceablePolicy(policy: ToolPolicy, toolName = 'tool'): void {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new PolicyError('PP_POLICY_INVALID', `Policy for "${toolName}" is not a map`);
  }
  // A string here would make `.includes` a substring match ("admin" would admit "adm").
  for (const field of ['allowed_signers', 'allowed_roles'] as const) {
    const list = policy[field];
    if (list !== undefined && (!Array.isArray(list) || !list.every((x) => typeof x === 'string'))) {
      throw new PolicyError('PP_POLICY_INVALID', `Policy for "${toolName}": ${field} must be a list of strings`);
    }
  }
  const n = policy.required_approvals;
  if (n === undefined) return;
  if (typeof n !== 'number' || !Number.isInteger(n) || n < 1) {
    throw new PolicyError('PP_POLICY_INVALID', `Policy for "${toolName}": required_approvals must be 1, got ${JSON.stringify(n)}`);
  }
  if (n > 1) {
    throw new PolicyError(
      'PP_POLICY_UNSUPPORTED',
      `Policy for "${toolName}": required_approvals ${n} is not supported. An authorization token has one signature from one key, so it cannot prove ${n} separate approvals.`,
    );
  }
}

let cachedConfig: PPConfig | null = null;

export function loadPolicy(configPathArg?: string): PPConfig {
  if (cachedConfig && !configPathArg) return cachedConfig;

  const configPath = configPathArg || process.env.PP_CONFIG_PATH || path.join(process.cwd(), 'pp.config.yaml');
  if (!fs.existsSync(configPath)) {
    throw new PolicyError('PP_POLICY_MISSING', `Policy file not found: ${configPath}`);
  }

  const fileContents = fs.readFileSync(configPath, 'utf8');
  let parsed: unknown;
  try {
    parsed = parse(fileContents);
  } catch (err) {
    throw new PolicyError('PP_POLICY_INVALID', `Policy file is not valid YAML: ${configPath} (${(err as Error).message})`);
  }
  const tools = (parsed as PPConfig | null)?.tools;
  if (!tools || typeof tools !== 'object' || Array.isArray(tools)) {
    throw new PolicyError('PP_POLICY_INVALID', `Policy file has no "tools" map: ${configPath}`);
  }

  for (const [name, toolPolicy] of Object.entries(tools)) {
    if (toolPolicy === null || toolPolicy === undefined) continue;
    assertEnforceablePolicy(toolPolicy as ToolPolicy, name);
  }

  cachedConfig = {
    tools,
    policy_hash: crypto.createHash('sha256').update(fileContents).digest('hex').substring(0, 12),
  };
  return cachedConfig;
}

/** Test helper: forget the cached policy. */
export function _resetPolicyCache(): void {
  cachedConfig = null;
}

export function getToolPolicy(toolName: string): ToolPolicy | null {
  const config = loadPolicy();
  return config.tools[toolName] || null;
}
