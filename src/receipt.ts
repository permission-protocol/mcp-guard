import { createHash } from 'node:crypto';
import { appendFileSync } from 'node:fs';
import { v4 as uuidv4 } from 'uuid';
import type { Decision } from './engine.js';

export interface Receipt {
  receipt_id: string;
  timestamp: string;
  agent_id: string;
  tool_name: string;
  decision: Decision['decision'];
  reason: string;
  rule_id: string | null;
  request_payload_hash: string;
  target_server: string;
  mode: 'enforce' | 'observe';
}

export function createReceipt(
  agentId: string,
  toolName: string,
  decision: Decision,
  requestPayload: unknown,
  targetServer: string = 'unknown',
  mode: 'enforce' | 'observe' = 'enforce',
): Receipt {
  const payloadStr = JSON.stringify(requestPayload ?? {});
  const hash = createHash('sha256').update(payloadStr).digest('hex');

  return {
    receipt_id: uuidv4(),
    timestamp: new Date().toISOString(),
    agent_id: agentId,
    tool_name: toolName,
    decision: decision.decision,
    reason: decision.reason,
    rule_id: decision.rule_id,
    request_payload_hash: hash,
    target_server: targetServer,
    mode,
  };
}

export function emitReceipt(receipt: Receipt, receiptsPath: string = 'pp-receipts.jsonl'): void {
  const json = JSON.stringify(receipt);
  process.stderr.write(`[mcp-guard] receipt: ${json}\n`);
  try {
    appendFileSync(receiptsPath, json + '\n');
  } catch {
    // Best effort — don't crash the proxy if file write fails
  }
}
