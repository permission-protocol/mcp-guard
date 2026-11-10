import { existsSync, readFileSync } from 'node:fs';
import { loadConfig } from './config.js';
import { PRODUCTION_API_URL, PRODUCTION_KEY_SET, pinsFor } from './cloud/pinned-keys.js';
import { verifyCloudReceipt } from './cloud/verify.js';
import { defaultReceiptsPath } from './receipt-log.js';
import type { KeySet } from './signing/keys.js';

/**
 * `mcp-guard receipt verify <receipt id>`: re-check a Permission Protocol receipt that
 * the guard logged when it released or refused a held call.
 *
 * It reads the `{"cloud": ...}` line with that receipt id from the receipts file and
 * verifies the signed receipt in it, offline, against the pinned Permission Protocol
 * keys: signature, canonical bytes, decision, request id, that the signed fingerprint
 * is the fingerprint the guard logged for the call, and that a person signed an
 * approval. It does not need the network or an account.
 *
 * A receipt is valid for ten minutes after it is signed and is used once, so a logged
 * receipt is normally past its window; this command checks everything else and prints
 * the window. Exit 0 verified, 1 refused, 2 not found or bad usage.
 *
 *   --receipts-path <file>   the receipts file (default: $PP_SHARED_RECEIPTS_PATH or ./pp-receipts.jsonl)
 *   --config <policy.yaml>   only for a non-production Permission Protocol: the policy
 *                            whose cloud.trust_keys pin its keys
 */
export function runReceipt(argv: string[]): number {
  const [sub, ...rest] = argv;
  if (sub !== 'verify') {
    console.error('usage: mcp-guard receipt verify <receipt id> [--receipts-path <file>] [--config <policy.yaml>]');
    return 2;
  }
  let receiptId: string | undefined;
  let receiptsPath = defaultReceiptsPath();
  let configPath: string | undefined;
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '--receipts-path' && rest[i + 1]) receiptsPath = rest[++i];
    else if (rest[i] === '--config' && rest[i + 1]) configPath = rest[++i];
    else if (!rest[i].startsWith('--') && !receiptId) receiptId = rest[i];
    else { console.error(`unknown argument: ${rest[i]}`); return 2; }
  }
  if (!receiptId) { console.error('usage: mcp-guard receipt verify <receipt id> [--receipts-path <file>] [--config <policy.yaml>]'); return 2; }
  if (!existsSync(receiptsPath)) { console.error(`no receipts file at ${receiptsPath}`); return 2; }

  let keySet: KeySet = PRODUCTION_KEY_SET;
  let issuer = PRODUCTION_API_URL;
  if (configPath) {
    try {
      const cloud = loadConfig(configPath).cloud;
      if (cloud && cloud.api_url !== PRODUCTION_API_URL) {
        keySet = { issuer: cloud.api_url, keys: cloud.trust_keys ?? [] };
        issuer = cloud.api_url;
      }
    } catch (err: any) {
      console.error(`could not read ${configPath}: ${err.message}`);
      return 2;
    }
  }

  let line: any = null;
  for (const text of readFileSync(receiptsPath, 'utf-8').split('\n')) {
    if (!text.trim()) continue;
    try {
      const parsed = JSON.parse(text);
      if (parsed?.cloud?.receiptId === receiptId) line = parsed.cloud;
    } catch { /* not a JSON line */ }
  }
  if (!line || !line.artifact) { console.error(`no logged receipt ${receiptId} in ${receiptsPath}`); return 2; }

  const expect = line.decision === 'denied' ? 'DENIED' : 'APPROVED';
  const result = verifyCloudReceipt(line.artifact, { keySet, trust: pinsFor(keySet), fingerprint: line.fingerprint, requestId: line.requestId, expect, audit: true });
  if (!result.ok) {
    console.error(`REFUSED ${receiptId}: ${result.code}: ${result.message}`);
    return 1;
  }
  const r = result.receipt;
  console.log(`VERIFIED ${r.receiptId}`);
  console.log(`  decision:    ${r.status}`);
  console.log(`  signed by:   ${r.decider.display ?? r.decider.id} (${r.decider.id}, ${r.decider.authMethod ?? 'no session'})`);
  console.log(`  call:        ${line.tool ?? line.method} on ${line.server}, requested by ${line.agentId}`);
  console.log(`  fingerprint: ${r.fingerprint}`);
  console.log(`  request:     ${r.requestId}`);
  console.log(`  issued:      ${r.issuedAt ?? 'unstated'}   valid until: ${r.expiresAt ?? 'unstated'}`);
  console.log(`  signing key: ${r.keyId} (pinned for ${issuer}), format ${r.canonicalization}`);
  if (line.receiptUrl) console.log(`  receipt:     ${line.receiptUrl}`);
  console.log('The signature, the signed fingerprint and the signer were checked offline against the pinned key.');
  return 0;
}
