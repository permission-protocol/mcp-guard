/**
 * Permission Deck — completion records (the proof layer).
 *
 * A receipt proves *authorization*, not that the action happened. The real-world
 * proof (a tweet URL, a merged-PR URL, a deploy URL) only exists *after* the action
 * completes, which is after the receipt is signed. Per the locked cockpit
 * architecture, that proof must NEVER be written onto the immutable signed receipt —
 * it lives on a separate, mutable CompletionRecord keyed by `receipt_id`.
 *
 * Data flow: PP mints + signs the receipt on approval (immutable). The executor
 * webhooks `POST /api/completions { receipt_id, status, proof_url }` when the action
 * finishes. The ledger renders `Receipt ⋈ CompletionRecord` — two states, two
 * timestamps: *authorized* (receipt.timestamp) vs *completed* (completion.completed_at).
 *
 * The receipt is the source of truth for authority; the completion record is the
 * source of truth for "did it happen, and here's the link." Neither overwrites the other.
 */

export type CompletionStatus = 'pending' | 'done' | 'stalled' | 'failed' | 'cancelled';
export type ProofType = 'url' | 'audit_ref' | 'none';

export interface CompletionRecord {
  receipt_id: string;
  status: CompletionStatus;
  /** `url` = public link (tweet/PR/deploy); `audit_ref` = internal ref (snapshot id); `none` = no proof surface. */
  proof_type: ProofType;
  proof_url: string | null;
  /** Non-URL proof, e.g. a DB snapshot id or audit-log entry for a migration. */
  proof_ref: string | null;
  /** When the action actually finished. Null while pending/stalled. */
  completed_at: string | null;
  /** Last time this record changed state. */
  updated_at: string;
}

/** receipt_id → CompletionRecord. In-memory; mirrors the receipts ring buffer lifetime. */
const completions = new Map<string, CompletionRecord>();

/** Flip a stale `pending` to `stalled` after this window (ms). Mirrors the pending_merge>10min pattern. */
const STALL_MS = Number(process.env.PP_COMPLETION_STALL_MS ?? 10 * 60 * 1000);

/** Open a completion record in `pending` the moment a receipt is minted. */
export function openCompletion(receiptId: string): CompletionRecord {
  const now = new Date().toISOString();
  const rec: CompletionRecord = {
    receipt_id: receiptId,
    status: 'pending',
    proof_type: 'none',
    proof_url: null,
    proof_ref: null,
    completed_at: null,
    updated_at: now,
  };
  completions.set(receiptId, rec);
  return rec;
}

export interface CompletionInput {
  receipt_id: string;
  status?: CompletionStatus;
  proof_type?: ProofType;
  proof_url?: string | null;
  proof_ref?: string | null;
  completed_at?: string | null;
}

/** Upsert a completion from an executor webhook. PP owns this write; the cockpit never calls it. */
export function recordCompletion(input: CompletionInput): CompletionRecord {
  const now = new Date().toISOString();
  const prev = completions.get(input.receipt_id);
  const status: CompletionStatus = input.status ?? (prev?.status ?? 'pending');
  // Infer proof_type when the caller didn't set it: a URL ⇒ url, a ref ⇒ audit_ref, else none.
  const proof_url = input.proof_url ?? prev?.proof_url ?? null;
  const proof_ref = input.proof_ref ?? prev?.proof_ref ?? null;
  const proof_type: ProofType = input.proof_type
    ?? (proof_url ? 'url' : proof_ref ? 'audit_ref' : (prev?.proof_type ?? 'none'));
  const completed_at = input.completed_at
    ?? (status === 'done' ? (prev?.completed_at ?? now) : prev?.completed_at ?? null);
  const rec: CompletionRecord = {
    receipt_id: input.receipt_id,
    status,
    proof_type,
    proof_url,
    proof_ref,
    completed_at,
    updated_at: now,
  };
  completions.set(input.receipt_id, rec);
  return rec;
}

export function getCompletion(receiptId: string): CompletionRecord | null {
  const rec = completions.get(receiptId);
  if (!rec) return null;
  // Lazily age a long-pending record into `stalled` so the ledger can surface it.
  if (rec.status === 'pending' && rec.completed_at === null) {
    const age = Date.now() - Date.parse(rec.updated_at);
    if (Number.isFinite(age) && age > STALL_MS) {
      return { ...rec, status: 'stalled' };
    }
  }
  return rec;
}
