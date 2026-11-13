import { spawn, type ChildProcess, type SpawnOptions } from 'node:child_process';
import { resolve } from 'node:path';
import { loadConfig, type Config } from '../config.js';
import { hookReceiptsPath } from '../hook/decide.js';
import { childEnv, neutralCwd } from '../child-cwd.js';
import { CLI, flag, heartbeatDisabledReason, heartbeatEnvOff } from './launch.js';
import { MIN_INTERVAL_MS } from './send.js';
import { defaultStatePath, isDue, loadState } from './state.js';

export interface HookHeartbeatDeps {
  env?: NodeJS.ProcessEnv;
  now?: () => number;
  spawn?: (command: string, args: string[], options: SpawnOptions) => ChildProcess;
  statePath?: string;
}

/**
 * Called after the hook has decided and answered. When a heartbeat is due, starts the
 * sender detached (no stdio, unref'd) and returns at once; the hook process itself makes
 * no network request and does not wait. Most runs stop after reading one small state
 * file. Never throws.
 */
export function heartbeatAfterHook(args: string[], deps: HookHeartbeatDeps = {}): void {
  try {
    const env = deps.env ?? process.env;
    if (heartbeatEnvOff(env)) return;
    if (!isDue(loadState(deps.statePath ?? defaultStatePath()), (deps.now ?? Date.now)(), MIN_INTERVAL_MS)) return;
    const configPath = resolve(flag(args, '--config') ?? './pp.config.yaml');
    let config: Config;
    try { config = loadConfig(configPath); } catch { return; }
    if (heartbeatDisabledReason(config, env)) return;
    const override = flag(args, '--mode');
    const mode = override === 'enforce' || override === 'observe' ? override : config.mode;
    const receipts = resolve(hookReceiptsPath(configPath, env));
    const child = (deps.spawn ?? spawn)(
      process.execPath,
      [CLI, 'heartbeat', '--background', '--client', 'claude-code', '--config', configPath, '--receipts', receipts, '--mode', mode],
      // Started in the guard's config directory, never the project: on Windows a running
      // process keeps its working directory from being deleted.
      { detached: true, stdio: 'ignore', windowsHide: true, cwd: neutralCwd(), env: childEnv(env) },
    );
    child.on('error', () => undefined);
    child.unref();
  } catch {
    // A heartbeat never affects the hook.
  }
}
