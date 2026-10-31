import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Receipt } from './receipt.js';
import {
  verifyReceipt,
  verifyArtifactReceipt,
  isLegacyMcpGuardReceipt,
  LEGACY_SIGNED_FIELDS_NOTE,
  type ExpectedScope,
  type CallInput,
  type VerifyResult,
} from './receipt-verify.js';
import { keyIdForPublicKey } from './signer.js';
import { parseTrust } from './signing/keys.js';
import type { PinnedKeys } from './verify-core.js';

/**
 * `mcp-guard verify` — the OFFLINE receipt gate a CI step runs.
 *
 * Org receipt standard (`jcs_v2` artifact, `{ "artifact": ... }`):
 *   mcp-guard verify --receipt-file receipt.json --keys keys.json \
 *     --trust KEY_ID=sha256:<fingerprint> --scope deploy:production --scope-sha <sha>
 *
 * Legacy mcp-guard 0.2 receipt (`{ "envelope": ... }`): refused unless the gate opts in,
 * then verified and labelled legacy:
 *   mcp-guard verify --receipt-file receipt.json --accept-legacy --pubkey pinned.pub.pem --scope ...
 *
 * The gate trusts only keys it is given and never generates or discovers one.
 * Exit 0 = authorized, 1 = refused, 2 = missing input. "No receipt = No deploy."
 */

const USAGE = [
  'usage: mcp-guard verify (--receipt-file <path> | --receipt-id <id> [--receipts-path <jsonl>]) --scope s [--scope-ref r] [--scope-sha h] [--allow-policy-approval]',
  '  org standard (jcs_v2) receipts: --keys <keys.json> [--trust KEY_ID=sha256:<hex> ...] [--require-call --call <call.json>] [--allow-demo]',
  '    --call: {"tool", "operation", "input"}; the signed inputHash must recompute from it',
  '    --require-call: refuse scoped verification when --call is not supplied',
  '  legacy mcp-guard 0.2 receipts:  --accept-legacy --pubkey <pem> [--pubkey <pem> ...]',
].join('\n');

function ciError(message: string): void {
  console.log(`::error::${message.replace(/\n/g, '%0A')}`);
  console.error(message);
}

interface Args { flags: Record<string, string>; pubkeys: string[]; trust: string[]; bools: Set<string> }

function parseArgs(argv: string[]): Args {
  const flags: Record<string, string> = {};
  const pubkeys: string[] = [];
  const trust: string[] = [];
  const bools = new Set<string>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    if (['allow-policy-approval', 'accept-legacy', 'allow-demo', 'require-call', 'help'].includes(key)) { bools.add(key); continue; }
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) { flags[key] = ''; continue; }
    if (key === 'pubkey') pubkeys.push(next);
    else if (key === 'trust') trust.push(next);
    else flags[key] = next;
    i++;
  }
  return { flags, pubkeys, trust, bools };
}

function receiptIdOf(r: any): string | undefined {
  return r?.artifact?.receipt_id ?? r?.envelope?.receipt_id;
}

function loadReceiptById(id: string, path: string): unknown | string {
  if (!existsSync(path)) return `receipt store not found at ${path}`;
  let found: unknown = null;
  for (const line of readFileSync(path, 'utf-8').split('\n')) {
    if (!line.trim()) continue;
    try {
      const r = JSON.parse(line);
      if (receiptIdOf(r) === id) found = r;
    } catch { /* skip malformed line */ }
  }
  return found ?? `no receipt with id "${id}" in ${path}`;
}

export function runVerify(argv: string[]): number {
  const { flags, pubkeys, trust, bools } = parseArgs(argv);
  const fail = (msg: string): number => { ciError(`No receipt = No deploy. This is intentional. (${msg})`); return 2; };
  if (bools.has('help')) { console.log(USAGE); return 0; }

  let receipt: unknown;
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

  for (const f of ['scope', 'scope-ref', 'scope-sha']) {
    if (f in flags && !flags[f]) return fail(`--${f} needs a value`);
  }
  if (!flags.scope) return fail('--scope is required: a gate must say which action it authorizes');
  const expected: ExpectedScope = { scope: flags.scope };
  if (flags['scope-ref']) expected.scope_ref = flags['scope-ref'];
  if (flags['scope-sha']) expected.scope_sha = flags['scope-sha'];
  const allowPolicyApproval = bools.has('allow-policy-approval');

  let result: VerifyResult;
  let label: string;
  if (isLegacyMcpGuardReceipt(receipt)) {
    if (!bools.has('accept-legacy')) {
      ciError(`No receipt = No deploy. This is intentional. Receipt ${receiptIdOf(receipt) ?? '(unknown)'} REFUSED:\n  - LEGACY_RECEIPT_REFUSED: this is an mcp-guard 0.2 receipt, not the org receipt standard. Re-approve the action with mcp-guard 0.3, or pass --accept-legacy with --pubkey to accept 0.2 receipts.`);
      return 1;
    }
    if (pubkeys.length === 0) return fail('--pubkey is required for a legacy mcp-guard 0.2 receipt: the gate verifies only against keys you pin');
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
    result = verifyReceipt(receipt as Receipt, keys, { expected, allowPolicyApproval });
    label = `VERIFIED (${LEGACY_SIGNED_FIELDS_NOTE})`;
  } else {
    if (bools.has('require-call') && !flags.call) return fail('--require-call requires --call <call.json>: scoped verification must bind the exact action');
    if (!flags.keys) return fail('--keys <keys.json> is required: the gate verifies only against a key set you supply');
    const p = resolve(flags.keys);
    if (!existsSync(p)) return fail(`key set not found: ${p}`);
    let keySet: unknown;
    try { keySet = JSON.parse(readFileSync(p, 'utf-8')); } catch (e: any) { return fail(`key set ${p} is not valid JSON: ${e.message}`); }
    let pins;
    try { pins = trust.length ? parseTrust(trust) : null; } catch (e: any) { return fail(e.message); }
    let call: CallInput | undefined;
    if (flags.call) {
      const cp = resolve(flags.call);
      if (!existsSync(cp)) return fail(`call file not found: ${cp}`);
      try { call = JSON.parse(readFileSync(cp, 'utf-8')); } catch (e: any) { return fail(`call file is not valid JSON: ${e.message}`); }
      if (typeof call?.tool !== 'string' || typeof call?.operation !== 'string') return fail('call file must be {"tool": "...", "operation": "...", "input": ...}');
    }
    result = verifyArtifactReceipt(receipt, keySet, { expected, allowPolicyApproval, trust: pins, call, allowDemo: bools.has('allow-demo') });
    label = pins ? 'VERIFIED (jcs_v2, key pinned by --trust)' : 'VERIFIED (jcs_v2; key taken from the key set file, not pinned)';
  }

  const id = receiptIdOf(receipt) ?? '(unknown)';
  if (result.valid) {
    const scope = [expected.scope, expected.scope_ref, expected.scope_sha && `@ ${expected.scope_sha}`].filter(Boolean).join(' ');
    console.log(`Receipt ${id} ${label} for ${scope}. Gate green.`);
    return 0;
  }
  ciError(`No receipt = No deploy. This is intentional. Receipt ${id} REFUSED:\n  - ${result.reasons.join('\n  - ')}`);
  return 1;
}
