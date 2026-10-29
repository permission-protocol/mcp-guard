import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Receipt } from './receipt.js';
import { verifyReceipt, type ExpectedScope } from './receipt-verify.js';
import { keyIdForPublicKey } from './signer.js';
import type { PinnedKeys } from './verify-core.js';

/**
 * `mcp-guard verify` — the OFFLINE receipt gate a CI step runs.
 *
 *   mcp-guard verify --receipt-file receipt.json --pubkey pinned.pub.pem \
 *     --scope deploy:production --scope-sha <sha>
 *
 * The public key must be supplied (`--pubkey`, repeatable): the gate trusts only keys it
 * is given and never generates or discovers one. Exit 0 = authorized, 1 = refused,
 * 2 = missing input. "No receipt = No deploy. This is intentional."
 */

const USAGE = 'usage: mcp-guard verify (--receipt-file <path> | --receipt-id <id> [--receipts-path <jsonl>]) --pubkey <pem> [--pubkey <pem> ...] [--scope s] [--scope-ref r] [--scope-sha h] [--allow-policy-approval]';

function ciError(message: string): void {
  console.log(`::error::${message.replace(/\n/g, '%0A')}`);
  console.error(message);
}

function parseArgs(argv: string[]): { flags: Record<string, string>; pubkeys: string[]; bools: Set<string> } {
  const flags: Record<string, string> = {};
  const pubkeys: string[] = [];
  const bools = new Set<string>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    if (key === 'allow-policy-approval' || key === 'help') { bools.add(key); continue; }
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) { flags[key] = ''; continue; }
    if (key === 'pubkey') pubkeys.push(next);
    else flags[key] = next;
    i++;
  }
  return { flags, pubkeys, bools };
}

function loadReceiptById(id: string, path: string): Receipt | string {
  if (!existsSync(path)) return `receipt store not found at ${path}`;
  let found: Receipt | null = null;
  for (const line of readFileSync(path, 'utf-8').split('\n')) {
    if (!line.trim()) continue;
    try {
      const r = JSON.parse(line);
      if (r?.envelope?.receipt_id === id) found = r;
    } catch { /* skip malformed line */ }
  }
  return found ?? `no receipt with id "${id}" in ${path}`;
}

export function runVerify(argv: string[]): number {
  const { flags, pubkeys, bools } = parseArgs(argv);
  const fail = (msg: string): number => { ciError(`No receipt = No deploy. This is intentional. (${msg})`); return 2; };
  if (bools.has('help')) { console.log(USAGE); return 0; }

  let receipt: Receipt;
  if (flags['receipt-file']) {
    const p = resolve(flags['receipt-file']);
    if (!existsSync(p)) return fail(`receipt file not found: ${p}`);
    try { receipt = JSON.parse(readFileSync(p, 'utf-8')); } catch (e: any) { return fail(`receipt file is not valid JSON: ${e.message}`); }
  } else if (flags['receipt-id']) {
    const r = loadReceiptById(flags['receipt-id'], resolve(flags['receipts-path'] || process.env.PP_SHARED_RECEIPTS_PATH || 'pp-receipts.jsonl'));
    if (typeof r === 'string') return fail(r);
    receipt = r;
  } else {
    return fail(USAGE);
  }

  if (pubkeys.length === 0) return fail('--pubkey is required: the gate verifies only against keys you pin');
  const keys: PinnedKeys = {};
  for (const k of pubkeys) {
    const p = resolve(k);
    if (!existsSync(p)) return fail(`public key not found: ${p}`);
    try {
      const pem = readFileSync(p, 'utf-8');
      keys[keyIdForPublicKey(pem)] = pem;
    } catch (e: any) {
      return fail(`public key ${p} is not a valid PEM: ${e.message}`);
    }
  }

  const expected: ExpectedScope = {};
  if (flags.scope) expected.scope = flags.scope;
  if (flags['scope-ref']) expected.scope_ref = flags['scope-ref'];
  if (flags['scope-sha']) expected.scope_sha = flags['scope-sha'];
  const hasExpected = Object.keys(expected).length > 0;

  const result = verifyReceipt(receipt, keys, {
    ...(hasExpected ? { expected } : {}),
    allowPolicyApproval: bools.has('allow-policy-approval'),
  });
  const id = (receipt as any)?.envelope?.receipt_id ?? '(unknown)';
  if (result.valid) {
    const scope = hasExpected ? ` for ${[expected.scope, expected.scope_ref, expected.scope_sha && `@ ${expected.scope_sha}`].filter(Boolean).join(' ')}` : '';
    console.log(`Receipt ${id} VERIFIED${scope}. Gate green.`);
    return 0;
  }
  ciError(`No receipt = No deploy. This is intentional. Receipt ${id} REFUSED:\n  - ${result.reasons.join('\n  - ')}`);
  return 1;
}
