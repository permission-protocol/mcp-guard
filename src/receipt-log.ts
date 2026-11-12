import { appendFileSync } from 'node:fs';
import type { IssuedReceipt } from './issuer.js';

/**
 * Where receipts go: one JSON line each in the receipts file, the console's recent list,
 * and (optionally) a POST to PP_RECEIPT_ENDPOINT. A signed receipt is written as
 * `{ "artifact": ..., "record": ... }`; the artifact is what a gate verifies. Holds are
 * written as unsigned `{ "hold": ... }` lines. Nothing written here holds raw arguments.
 */

const MAX_RECENT = 50;
const recent: IssuedReceipt[] = [];

export function defaultReceiptsPath(): string {
  return process.env.PP_SHARED_RECEIPTS_PATH || 'pp-receipts.jsonl';
}

export function recentReceipts(): IssuedReceipt[] {
  return recent.slice().reverse();
}

function append(line: string, path: string): void {
  try {
    appendFileSync(path, line + '\n');
  } catch {
    // Best effort: a full disk must not crash the proxy.
  }
}

export function emitReceipt(issued: IssuedReceipt, path: string = defaultReceiptsPath()): void {
  const r = issued.record;
  const note = issued.artifact ? '' : issued.unsigned ? ' UNSIGNED (signing: off)' : ` UNSIGNED (${issued.signingFailed})`;
  process.stderr.write(`[mcp-guard] receipt ${r.id} ${r.status}: ${String(r.summary)}${note}\n`);
  const json = JSON.stringify(issued);
  append(json, path);
  recent.push(issued);
  if (recent.length > MAX_RECENT) recent.shift();

  const endpoint = process.env.PP_RECEIPT_ENDPOINT;
  if (!endpoint) return;
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (process.env.PP_RECEIPT_TOKEN) headers.Authorization = `Bearer ${process.env.PP_RECEIPT_TOKEN}`;
  void fetch(endpoint, { method: 'POST', headers, body: json }).catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`[mcp-guard] receipt publish failed: ${message}\n`);
  });
}

/** A held call: recorded, never signed (a hold is not a decision). */
export function emitHold(hold: { id: string | null; method: string; tool: string | null; agentId: string; ruleId: string | null; inputHash: string; createdAt: string }, path: string = defaultReceiptsPath()): void {
  append(JSON.stringify({ hold }), path);
}

/**
 * One cloud decision on a held call, appended as a `{ "cloud": ... }` line: what was
 * decided, the Permission Protocol receipt id and URL, who signed, and the signed
 * artifact itself so the line verifies offline later. Never the arguments.
 */
export interface CloudDecisionLine {
  decision: 'released' | 'denied' | 'expired' | 'blocked';
  requestId: string | null;
  receiptId: string | null;
  receiptUrl: string | null;
  fingerprint: string;
  method: string;
  tool: string | null;
  server: string;
  agentId: string;
  ruleId: string | null;
  decider: { id: string; display: string | null; authMethod: string | null } | null;
  /** Why it was not released. */
  reason: string | null;
  /** The refusal code of a block. */
  code: string | null;
  at: string;
  artifact: unknown | null;
}

export function emitCloudDecision(line: CloudDecisionLine, path: string = defaultReceiptsPath()): void {
  const who = line.decider ? ` by ${line.decider.display ?? line.decider.id}` : '';
  const receipt = line.receiptId ? ` receipt ${line.receiptId}` : ' no receipt';
  const why = line.decision === 'released' ? '' : ` (${line.code ? `${line.code}: ` : ''}${line.reason ?? 'no reason given'})`;
  process.stderr.write(`[mcp-guard] cloud ${line.decision.toUpperCase()} "${line.tool ?? line.method}"${who}:${receipt}${why}\n`);
  append(JSON.stringify({ cloud: line }), path);
}

/** Test helper. */
export function _resetReceiptLog(): void {
  recent.length = 0;
}
