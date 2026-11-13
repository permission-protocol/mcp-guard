import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { keysDir } from '../keystore.js';
import type { CloudClient, CreateRequestBody } from '../cloud/client.js';
import { callFingerprint } from '../cloud/fingerprint.js';

/**
 * A hook has a time limit; a signer may take longer. When the hook stops waiting, the
 * approval request stays open in Permission Protocol for the policy's full
 * `cloud.approval_timeout_seconds`, and this file remembers its id under the call's
 * fingerprint. The next identical call (same tool, same arguments) resumes that request
 * instead of opening a new one, so a signature given after the hook gave up still
 * releases the call.
 *
 * The file holds request ids and fingerprints only, never arguments. It grants nothing:
 * a resumed request is checked by decideInCloud exactly like a new one (its fingerprint
 * must be this call's, its receipt must verify offline against the pinned key and must
 * name this request, and the redeem must succeed, which works once). An edited file can
 * at worst point at a request that fails those checks, and the call is then blocked.
 */

export interface PendingEntry {
  requestId: string;
  /** Epoch ms after which Permission Protocol has expired the request. */
  expiresAt: number;
}

const REQUEST_ID = /^[A-Za-z0-9_-]{1,80}$/;
const MAX_ENTRIES = 200;

export function defaultResumePath(): string {
  return process.env.PP_HOOK_STATE_PATH || join(dirname(keysDir()), 'hook-requests.json');
}

export class ResumeStore {
  constructor(readonly path: string = defaultResumePath(), private readonly now: () => number = () => Date.now()) {}

  private load(): Record<string, PendingEntry> {
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(this.path, 'utf8'));
    } catch {
      return {};
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return {};
    const out: Record<string, PendingEntry> = {};
    for (const [fp, v] of Object.entries(parsed as Record<string, unknown>)) {
      const e = v as Partial<PendingEntry> | null;
      if (!e || typeof e.requestId !== 'string' || !REQUEST_ID.test(e.requestId) || typeof e.expiresAt !== 'number') continue;
      if (e.expiresAt <= this.now()) continue;
      out[fp] = { requestId: e.requestId, expiresAt: e.expiresAt };
    }
    return out;
  }

  private save(entries: Record<string, PendingEntry>): void {
    const keys = Object.keys(entries).sort((a, b) => entries[b].expiresAt - entries[a].expiresAt).slice(0, MAX_ENTRIES);
    const kept = Object.fromEntries(keys.map((k) => [k, entries[k]]));
    try {
      mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
      const tmp = `${this.path}.${process.pid}.tmp`;
      writeFileSync(tmp, JSON.stringify(kept) + '\n', { mode: 0o600 });
      try { chmodSync(tmp, 0o600); } catch { /* best effort */ }
      renameSync(tmp, this.path);
    } catch {
      // Best effort: losing an entry only means the next call opens a new request.
    }
  }

  get(fingerprint: string): PendingEntry | null {
    return this.load()[fingerprint] ?? null;
  }

  put(fingerprint: string, entry: PendingEntry): void {
    const all = this.load();
    all[fingerprint] = entry;
    this.save(all);
  }

  remove(fingerprint: string): void {
    const all = this.load();
    if (!(fingerprint in all)) return;
    delete all[fingerprint];
    this.save(all);
  }
}

export interface ResumingClient extends CloudClient {
  /** The status of the last view the API returned, so the caller can tell a local wait limit from a final answer. */
  readonly lastStatus: unknown;
  /** Whether this call resumed a request an earlier hook run opened. */
  readonly resumed: boolean;
}

/**
 * Wrap a client so `create` resumes a remembered open request for the same fingerprint,
 * and opens new requests with the policy's full approval lifetime (`requestLifetimeSeconds`)
 * while decideInCloud waits only the hook's share of it. Reads and redeems pass through.
 */
export function resumingClient(inner: CloudClient, store: ResumeStore, requestLifetimeSeconds: number, now: () => number = () => Date.now()): ResumingClient {
  let lastStatus: unknown = undefined;
  let resumed = false;
  const seen = (view: Record<string, unknown>): Record<string, unknown> => {
    lastStatus = view.status;
    return view;
  };

  return {
    get lastStatus() { return lastStatus; },
    get resumed() { return resumed; },

    async create(body: CreateRequestBody): Promise<Record<string, unknown>> {
      const fingerprint = callFingerprint({ server: body.server, tool: body.tool, argsHash: body.argsHash });
      const entry = store.get(fingerprint);
      if (entry) {
        try {
          const view = await inner.read(entry.requestId);
          if (view.requestId === entry.requestId && view.fingerprint === fingerprint && (view.status === 'pending' || view.status === 'approved')) {
            resumed = true;
            return seen(view);
          }
        } catch {
          // Unknown, gone or unreadable: open a new request below.
        }
        store.remove(fingerprint);
      }
      const view = await inner.create({ ...body, timeoutSec: requestLifetimeSeconds });
      if (typeof view.requestId === 'string' && REQUEST_ID.test(view.requestId) && view.fingerprint === fingerprint && view.status === 'pending') {
        store.put(fingerprint, { requestId: view.requestId, expiresAt: now() + requestLifetimeSeconds * 1000 });
      }
      return seen(view);
    },

    async read(requestId: string): Promise<Record<string, unknown>> {
      return seen(await inner.read(requestId));
    },

    redeem: (requestId: string) => inner.redeem(requestId),
  };
}
