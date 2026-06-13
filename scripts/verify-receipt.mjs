#!/usr/bin/env node
/**
 * Permission Deck Slice 2 — OFFLINE receipt-gate CLI for CI.
 *
 * This is what a GitHub Actions "receipt-gate" step calls. It verifies a signed receipt
 * against a PUBLISHED Ed25519 public key, with NO network and NO live PP service, then
 * exits 0 if the receipt authorizes the expected scope/ref/sha — or non-zero with a
 * `::error::` annotation if not. "No receipt = No deploy. This is intentional."
 *
 * Resolution:
 *   - the receipt comes from --receipt-id <id> (looked up in pp-receipts.jsonl, last match wins)
 *     OR --receipt-file <path> (a receipt JSON file).
 *   - the public key comes from --pubkey <path>, else the signer's published key
 *     (.keys/pp-dev-1.pub.pem, published on demand).
 *   - --scope / --scope-ref / --scope-sha set the gate's expectations (exact match).
 *
 * Usage:
 *   node scripts/verify-receipt.mjs --receipt-id rcpt_dg_xxx \
 *     --scope github:merge --scope-ref refs/pull/16/merge --scope-sha <merge_sha>
 *
 *   node scripts/verify-receipt.mjs --receipt-file ./receipt.json \
 *     --pubkey .keys/pp-dev-1.pub.pem --scope deploy:staging
 *
 * Build first: `npm run build` (this script imports the compiled dist/).
 */
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');

const { verifyReceiptOffline } = await import(
  join(REPO_ROOT, 'dist', 'src', 'receipt-verify.js')
);
const { publishPublicKey, getPublicKeyPem } = await import(
  join(REPO_ROOT, 'dist', 'src', 'signer.js')
);

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) {
      out[key] = true;
    } else {
      out[key] = next;
      i++;
    }
  }
  return out;
}

function ciError(message) {
  // GitHub Actions error annotation — shows up red in the checks UI.
  console.log(`::error::${message}`);
  console.error(message);
}

function loadReceiptById(id, receiptsPath) {
  if (!existsSync(receiptsPath)) {
    return { error: `Receipt store not found at ${receiptsPath}` };
  }
  const lines = readFileSync(receiptsPath, 'utf-8')
    .split('\n')
    .filter((l) => l.trim());
  let found = null;
  for (const line of lines) {
    try {
      const r = JSON.parse(line);
      if (r.receipt_id === id) found = r; // last match wins
    } catch {
      // skip malformed line
    }
  }
  if (!found) return { error: `No receipt with id "${id}" in ${receiptsPath}` };
  return { receipt: found };
}

function main() {
  const args = parseArgs(process.argv.slice(2));

  const receiptsPath =
    args['receipts-path'] ||
    process.env.PP_SHARED_RECEIPTS_PATH ||
    join(process.cwd(), 'pp-receipts.jsonl');

  // 1. Resolve the receipt.
  let receipt;
  if (args['receipt-file']) {
    const p = resolve(String(args['receipt-file']));
    if (!existsSync(p)) {
      ciError(`No receipt = No deploy. This is intentional. (receipt file not found: ${p})`);
      process.exit(2);
    }
    try {
      receipt = JSON.parse(readFileSync(p, 'utf-8'));
    } catch (e) {
      ciError(`No receipt = No deploy. This is intentional. (receipt file is not valid JSON: ${e.message})`);
      process.exit(2);
    }
  } else if (args['receipt-id']) {
    const { receipt: r, error } = loadReceiptById(String(args['receipt-id']), receiptsPath);
    if (error) {
      ciError(`No receipt = No deploy. This is intentional. (${error})`);
      process.exit(2);
    }
    receipt = r;
  } else {
    ciError('No receipt = No deploy. This is intentional. (pass --receipt-id <id> or --receipt-file <path>)');
    process.exit(2);
  }

  // 2. Resolve the published public key (offline).
  let publicKeyPem;
  if (args['pubkey']) {
    const p = resolve(String(args['pubkey']));
    if (!existsSync(p)) {
      ciError(`No receipt = No deploy. This is intentional. (public key not found: ${p})`);
      process.exit(2);
    }
    publicKeyPem = readFileSync(p, 'utf-8');
  } else {
    // Publish (idempotent) and read the dev key.
    try {
      const path = publishPublicKey();
      publicKeyPem = readFileSync(path, 'utf-8');
    } catch {
      publicKeyPem = getPublicKeyPem();
    }
  }

  // 3. Build expectations from flags.
  const expected = {};
  if (args['scope']) expected.scope = String(args['scope']);
  if (args['scope-ref']) expected.scope_ref = String(args['scope-ref']);
  if (args['scope-sha']) expected.scope_sha = String(args['scope-sha']);
  const hasExpected = Object.keys(expected).length > 0;

  // 4. Verify offline.
  const result = verifyReceiptOffline(
    receipt,
    publicKeyPem,
    hasExpected ? expected : undefined,
  );

  if (result.valid) {
    const scopeDesc = hasExpected
      ? ` for ${expected.scope ?? ''}${expected.scope_ref ? ` ${expected.scope_ref}` : ''}${expected.scope_sha ? ` @ ${expected.scope_sha}` : ''}`
      : '';
    console.log(`Receipt ${receipt.receipt_id} VERIFIED${scopeDesc}. Gate green.`);
    process.exit(0);
  }

  ciError(
    `No receipt = No deploy. This is intentional. Receipt ${receipt.receipt_id ?? '(unknown)'} REFUSED:\n  - ${result.reasons.join('\n  - ')}`,
  );
  process.exit(1);
}

main();
