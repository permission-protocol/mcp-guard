import { spawn, type ChildProcess, type SpawnOptions } from 'node:child_process';
import { resolve } from 'node:path';
import type { Config } from '../config.js';
import { CLI, heartbeatDisabledReason } from './launch.js';
import { MIN_INTERVAL_MS } from './send.js';

export const PROXY_FIRST_DELAY_MS = 30_000;
export const PROXY_INTERVAL_MS = MIN_INTERVAL_MS;
/** A sender child still running after this long is stopped. */
const CHILD_DEADLINE_MS = 60_000;
/** The only line copied from the sender: a fixed text and an error code. */
export const FAILURE_LINE = /^\[mcp-guard\] heartbeat not sent \([A-Z0-9_]+\)$/;

export interface ProxyHeartbeatDeps {
  env?: NodeJS.ProcessEnv;
  spawn?: (command: string, args: string[], options: SpawnOptions) => ChildProcess;
  stderr?: (text: string) => void;
  firstDelayMs?: number;
  intervalMs?: number;
}

/**
 * The proxy's heartbeat: a timer (first tick after 30 s, then every 10 minutes) that
 * starts one sender child at a time. The sender throttles itself; the proxy only copies
 * its one failure line, if any, to stderr. Timers are unref'd and nothing here touches
 * the request path. Returns null when the heartbeat is off. Never throws.
 */
export function startProxyHeartbeat(config: Config, receiptsPath: string, deps: ProxyHeartbeatDeps = {}): { tick(): void; stop(): void } | null {
  try {
    const env = deps.env ?? process.env;
    if (heartbeatDisabledReason(config, env) || !config.cloud) return null;
    const write = deps.stderr ?? ((text: string) => { try { process.stderr.write(text); } catch { /* ignore */ } });
    const args = [
      CLI, 'heartbeat', '--background', '--client', 'mcp-proxy', '--api-url', config.cloud.api_url, '--mode', config.mode, '--receipts', resolve(receiptsPath),
    ];
    let running = false;
    const tick = (): void => {
      if (running) return;
      try {
        running = true;
        const child = (deps.spawn ?? spawn)(process.execPath, args, { stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true, env });
        let err = '';
        const deadline = setTimeout(() => { try { child.kill(); } catch { /* gone */ } }, CHILD_DEADLINE_MS);
        deadline.unref?.();
        child.stderr?.on('data', (d: Buffer) => { if (err.length < 1024) err += d.toString('utf8'); });
        child.on('error', () => { running = false; clearTimeout(deadline); write('[mcp-guard] heartbeat not sent (SPAWN_FAILED)\n'); });
        child.on('close', () => {
          running = false;
          clearTimeout(deadline);
          const line = err.split('\n').find((l) => FAILURE_LINE.test(l));
          if (line) write(`${line}\n`);
        });
        child.unref();
        (child.stderr as { unref?: () => void } | null)?.unref?.();
      } catch {
        running = false;
      }
    };
    const first = setTimeout(tick, deps.firstDelayMs ?? PROXY_FIRST_DELAY_MS);
    const every = setInterval(tick, deps.intervalMs ?? PROXY_INTERVAL_MS);
    first.unref?.();
    every.unref?.();
    return { tick, stop: () => { clearTimeout(first); clearInterval(every); } };
  } catch {
    return null;
  }
}
