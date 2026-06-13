import crypto from 'node:crypto';

/**
 * Permission Deck Slice 2.5 — GitHub webhook ingestion (the no-agent adoption path).
 *
 * A customer points their repo's webhook at the deck. When a PR is opened/labeled
 * with the trigger label, the deck enqueues it as a Decide card. Approving it mints
 * the scoped receipt the deploy-gate verifies — so a human authorizes the merge in
 * the deck without any agent ever calling a tool.
 *
 * Pure functions. No I/O. Fully unit-testable.
 */

export interface ParsedPrEvent {
  action: string;       // opened | reopened | labeled | synchronize | closed | ...
  pr_number: number;
  repo: string;         // "owner/name"
  head_sha: string;
  title: string;
  labels: string[];
  html_url: string | null;
}

export const DEFAULT_TRIGGER_LABEL = 'needs-authority';

/**
 * Verify a GitHub webhook HMAC-SHA256 signature (`X-Hub-Signature-256: sha256=<hex>`).
 * Constant-time compare. Fails closed when the secret or header is missing.
 */
export function verifyGithubSignature(
  secret: string | undefined,
  rawBody: string | Buffer,
  signatureHeader: string | undefined,
): boolean {
  if (!secret || !signatureHeader) return false;
  const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  const a = Buffer.from(signatureHeader);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/** Parse a GitHub `pull_request` webhook payload into the fields we gate on. */
export function parsePrEvent(payload: any): ParsedPrEvent | null {
  if (!payload || typeof payload !== 'object' || !payload.pull_request) return null;
  const pr = payload.pull_request;
  if (pr.number == null) return null;
  return {
    action: String(payload.action ?? ''),
    pr_number: Number(pr.number),
    repo: String(payload.repository?.full_name ?? ''),
    head_sha: String(pr.head?.sha ?? ''),
    title: String(pr.title ?? ''),
    labels: Array.isArray(pr.labels) ? pr.labels.map((l: any) => String(l?.name ?? '')).filter(Boolean) : [],
    html_url: pr.html_url ? String(pr.html_url) : null,
  };
}

/** Should this event open an authority gate? A relevant action carrying the trigger label. */
export function shouldGate(ev: ParsedPrEvent, triggerLabel: string = DEFAULT_TRIGGER_LABEL): boolean {
  const relevant = ['opened', 'reopened', 'labeled', 'synchronize'].includes(ev.action);
  return relevant && ev.labels.includes(triggerLabel);
}

/** The scope binding a merge receipt must carry to satisfy the deploy-gate for this PR. */
export function scopeForPr(ev: ParsedPrEvent): { scope: string; scope_ref: string; scope_sha: string } {
  return {
    scope: 'github:merge',
    scope_ref: `refs/pull/${ev.pr_number}/merge`,
    scope_sha: ev.head_sha,
  };
}
