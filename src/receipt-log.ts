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

/** Test helper. */
export function _resetReceiptLog(): void {
  recent.length = 0;
}
