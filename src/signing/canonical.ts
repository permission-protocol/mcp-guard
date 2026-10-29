/**
 * The org receipt standard's `jcs_v2` canonicalization (receipt-spec SPEC.md, mirrored
 * from the app's src/lib/permission-protocol-v1/signing/canonicalize.ts and
 * canonical-json.ts).
 *
 * CONTRACT: the bytes are the signing truth. The field list is FROZEN: it must equal the
 * app's SIGNED_FIELDS_V2 exactly, in the same order, and it never changes. A new signed
 * field set is a new canonicalization version, never an edit here. The receipt-spec test
 * vectors (src/tests/fixtures/receipt-spec) pin this byte for byte.
 */

export const JCS_V2 = 'jcs_v2';

/** The app's SIGNED_FIELDS_V2: the v1 set plus the decider binding. FROZEN. */
export const JCS_V2_FIELDS: readonly string[] = Object.freeze([
  'id',
  'companyId',
  'idemKey',
  'agentId',
  'runId',
  'requestJson',
  'inputHash',
  'status',
  'riskTier',
  'policyVersion',
  'reasonCodes',
  'summary',
  'receiptVersion',
  'canonicalization',
  'signatureAlg',
  'signatureKeyId',
  'expiresAt',
  'createdAt',
  'deciderId',
  'deciderDisplay',
  'deciderAuthMethod',
  'resolutionType',
  'attributionConfidence',
  'scope',
]);

/**
 * Recursive key sort: arrays keep their order; objects get their own keys in ascending
 * UTF-16 order. Keys are DEFINED, never assigned, so a `__proto__` key survives as an
 * own key (assigning it would set the prototype and drop it from the output).
 */
export function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value === null || typeof value !== 'object') return value;
  const record = value as Record<string, unknown>;
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(record).sort()) {
    Object.defineProperty(sorted, key, {
      value: sortKeysDeep(record[key]),
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return sorted;
}

/** `JSON.stringify` of the recursively key-sorted value: no whitespace. */
export function canonicalJsonText(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}

/**
 * The canonical `jcs_v2` text of a receipt record: only the frozen fields, null and
 * undefined omitted, Dates as ISO 8601, keys sorted recursively.
 */
export function canonicalizeJcsV2(record: Record<string, unknown>): string {
  const canonical: Record<string, unknown> = {};
  for (const field of JCS_V2_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(record, field)) continue;
    const value = record[field];
    if (value === undefined || value === null) continue;
    canonical[field] = value instanceof Date ? value.toISOString() : value;
  }
  return canonicalJsonText(canonical);
}
