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

let cachedConfig: PPConfig | null = null;

export function loadPolicy(configPathArg?: string): PPConfig {
  if (cachedConfig && !configPathArg) return cachedConfig;
  
  const configPath = configPathArg || process.env.PP_CONFIG_PATH || path.join(process.cwd(), 'pp.config.yaml');
  if (!fs.existsSync(configPath)) {
    return { tools: {} };
  }

  const fileContents = fs.readFileSync(configPath, 'utf8');
  let parsed;
  try {
    parsed = parse(fileContents);
  } catch (err) {
    console.error("Failed to parse pp.config.yaml", err);
    parsed = {};
  }
  
  cachedConfig = (parsed as PPConfig) || { tools: {} };
  
  // Ensure tools object exists
  if (!cachedConfig.tools) {
    cachedConfig.tools = {};
  }
  cachedConfig.policy_hash = crypto.createHash('sha256').update(fileContents).digest('hex').substring(0, 12);
  
  return cachedConfig;
}

export function getToolPolicy(toolName: string): ToolPolicy | null {
  const config = loadPolicy();
  return config.tools[toolName] || null;
}
