import { chmodSync, closeSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync, writeSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { keysDir } from '../keystore.js';
import type { LogState } from './aggregate.js';

/**
 * The heartbeat's own state, beside the guard's other state (the key directory's parent,
 * like the install token and hook-requests.json), mode 0600: per receipt log a byte
 * offset and per-day totals, the last attempt time, and a hash of what was last accepted
 * per day. It holds counts and rule ids only. A missing or corrupt file is recounted from
 * the logs. A lock file keeps parallel guard processes from sending twice or writing over
 * each other.
 */

export interface HeartbeatState {
  v: 1;
  logs: LogState[];
  /** Epoch ms of the last send attempt (any outcome). */
  lastAttemptAt: number;
  /** Epoch ms before which nothing is sent (after a 429, 401, 400 or 413). */
  nextAllowedAt: number;
  /** Per day, sha256 of the last body Permission Protocol accepted. */
  sent: Record<string, string>;
}

export const MAX_LOGS = 16;
/** A lock older than this is from a process that died; it is taken over. */
export const STALE_LOCK_MS = 2 * 60 * 1000;

export function defaultStatePath(): string {
  return join(dirname(keysDir()), 'heartbeat-state.json');
}

export function emptyState(): HeartbeatState {
  return { v: 1, logs: [], lastAttemptAt: 0, nextAllowedAt: 0, sent: {} };
}

const num = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) ? v : 0);

export function loadState(path: string): HeartbeatState {
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    if (!parsed || parsed.v !== 1 || !Array.isArray(parsed.logs)) return emptyState();
    const logs = (parsed.logs as unknown[]).filter((l): l is LogState => {
      const x = l as LogState;
      return !!x && typeof x.path === 'string' && typeof x.offset === 'number' && typeof x.days === 'object' && x.days !== null && Array.isArray(x.holds) && typeof x.tail === 'string';
    });
    const sent = parsed.sent && typeof parsed.sent === 'object' && !Array.isArray(parsed.sent) ? parsed.sent : {};
    return { v: 1, logs, lastAttemptAt: num(parsed.lastAttemptAt), nextAllowedAt: num(parsed.nextAllowedAt), sent };
  } catch {
    return emptyState();
  }
}

/** Atomic: written to a temporary file, then renamed over the old one. */
export function saveState(path: string, state: HeartbeatState): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(state) + '\n', { mode: 0o600 });
  try { chmodSync(tmp, 0o600); } catch { /* best effort */ }
  renameSync(tmp, path);
}

/** True when a send may be attempted now. Reads the state file only; no lock. */
export function isDue(state: Pick<HeartbeatState, 'lastAttemptAt' | 'nextAllowedAt'>, now: number, minIntervalMs: number): boolean {
  return now >= state.lastAttemptAt + minIntervalMs && now >= state.nextAllowedAt;
}

/** Take the lock, or null when another process holds it. */
export function acquireLock(statePath: string, now: () => number = Date.now): (() => void) | null {
  const lockPath = `${statePath}.lock`;
  mkdirSync(dirname(lockPath), { recursive: true, mode: 0o700 });
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = openSync(lockPath, 'wx', 0o600);
      try { writeSync(fd, `${process.pid}\n`); } finally { closeSync(fd); }
      let released = false;
      return () => {
        if (released) return;
        released = true;
        try { unlinkSync(lockPath); } catch { /* already gone */ }
      };
    } catch (err: any) {
      if (err?.code !== 'EEXIST') return null;
      try {
        if (now() - statSync(lockPath).mtimeMs <= STALE_LOCK_MS) return null;
        unlinkSync(lockPath);
      } catch {
        // Removed by its owner meanwhile: try once more.
      }
    }
  }
  return null;
}
