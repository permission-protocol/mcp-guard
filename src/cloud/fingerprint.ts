import { createHash } from 'node:crypto';
import { canonicalJsonText } from '../signing/canonical.js';

/**
 * The action fingerprint of one MCP call, as Permission Protocol computes it
 * (app: docs/mcp-approval-contract.md):
 *
 *   argsHash    = "sha256:" + hex(SHA-256(canonical JSON of the arguments))
 *   fingerprint = "sha256:" + hex(SHA-256(canonical JSON of {argsHash, server, tool}))
 *
 * The fingerprint covers argsHash, which is computed from the exact arguments. For a
 * held call the guard sends argsHash and, unless `cloud.args_preview: false`, a preview
 * of the arguments that it masks and caps first (cloud/preview.ts); the preview is
 * never part of the fingerprint. The guard computes the fingerprint from the exact call
 * it will forward and compares it with the one inside the signed receipt, so a receipt
 * releases this call and no other.
 */

const sha256 = (text: string): string => `sha256:${createHash('sha256').update(text, 'utf8').digest('hex')}`;

/** Hash of the arguments the server will act on. Absent arguments hash as `{}`. */
export function argsHashOf(args: unknown): string {
  return sha256(canonicalJsonText(args ?? {}));
}

export interface CallIdentity {
  server: string;
  tool: string;
  argsHash: string;
}

export function callFingerprint(call: CallIdentity): string {
  return sha256(canonicalJsonText({ argsHash: call.argsHash, server: call.server, tool: call.tool }));
}

/** The fingerprint of a call from its parts, hashing the arguments first. */
export function fingerprintOfCall(server: string, tool: string, args: unknown): string {
  return callFingerprint({ server, tool, argsHash: argsHashOf(args) });
}
