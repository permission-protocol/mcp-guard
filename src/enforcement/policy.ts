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
  constructor(readonly code: 'PP_POLICY_MISSING' | 'PP_POLICY_INVALID', message: string) {
    super(message);
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
