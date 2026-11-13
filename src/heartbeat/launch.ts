import { join } from 'node:path';
import type { Config } from '../config.js';

/**
 * Shared by the hook and proxy entry points (heartbeat/hook.ts, heartbeat/proxy.ts).
 * Both hand the work to a separate process, `mcp-guard heartbeat --background`, so
 * reading the log and the network request never run in a process that decides a call.
 */

export const CLI = join(__dirname, '..', 'cli.js');

export function heartbeatEnvOff(env: NodeJS.ProcessEnv = process.env): boolean {
  const flag = (env.MCP_GUARD_HEARTBEAT ?? '').trim().toLowerCase();
  return flag === 'off' || flag === '0' || flag === 'false' || flag === 'no';
}

/** Why no heartbeat is sent, or null when it is on. A missing install token is checked by the sender. */
export function heartbeatDisabledReason(config: Pick<Config, 'cloud'> | null, env: NodeJS.ProcessEnv = process.env): string | null {
  if (heartbeatEnvOff(env)) return 'MCP_GUARD_HEARTBEAT is off';
  if (!config?.cloud) return 'the policy has no cloud: section';
  if (config.cloud.heartbeat === false) return 'the policy sets cloud.heartbeat: false';
  return null;
}

export function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}
