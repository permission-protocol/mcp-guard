#!/usr/bin/env node
/**
 * OFFLINE receipt gate — thin wrapper over `mcp-guard verify` (src/verify-cli.ts).
 *
 *   node scripts/verify-receipt.mjs --receipt-file ./receipt.json --pubkey pinned.pub.pem \
 *     --scope deploy:staging --scope-sha <sha>
 *
 * --pubkey is required: the gate verifies only against keys you pin.
 * Exit 0 = authorized, 1 = refused, 2 = missing input.
 * Build first: `npm run build` (this script imports the compiled dist/).
 */
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const { runVerify } = await import(join(ROOT, 'dist', 'src', 'verify-cli.js'));
process.exit(runVerify(process.argv.slice(2)));
