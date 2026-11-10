import { fingerprintOf, type KeySet, type KeySetEntry, type TrustPins } from '../signing/keys.js';

/**
 * Permission Protocol's production receipt-signing keys, pinned in this release.
 *
 * Copied from https://app.permissionprotocol.com/.well-known/permission-protocol/keys.json
 * on 2026-11-10 (both keys active). The guard never fetches keys at decision time: a
 * receipt is accepted only when it verifies against a key in this file. When Permission
 * Protocol rotates its key, a new mcp-guard release carries the new pin; until then a
 * receipt signed by an unknown key is refused (KEY_NOT_FOUND) and the call stays blocked.
 *
 * Nothing in the environment can replace these for the production API. A policy file may
 * name its own keys only together with a non-production `cloud.api_url` (config.ts).
 */
export const PRODUCTION_API_URL = 'https://app.permissionprotocol.com';

export const PRODUCTION_KEY_SET: KeySet = Object.freeze({
  issuer: PRODUCTION_API_URL,
  keys: Object.freeze([
    Object.freeze({ key_id: 'pp_key_default', alg: 'ed25519', public_key_b64: 'wJcxaKl9Mn3jXlE+JhdxmXZkcS6SyMiy7HoVMVLyF7g=' }),
    Object.freeze({ key_id: 'pp_key_348f56d61d0deab4', alg: 'ed25519', public_key_b64: 'DrIEo9bhRbEZQGFxEujYS7xQ+DkG7VhNkWJ6fOZpRQQ=' }),
  ]) as unknown as KeySetEntry[],
}) as KeySet;

/** Fingerprint pins for every key of a set: the set itself is the pin. */
export function pinsFor(keySet: KeySet): TrustPins {
  const pins: TrustPins = new Map();
  for (const key of keySet.keys) {
    pins.set(key.key_id, fingerprintOf(Buffer.from(key.public_key_b64, 'base64')));
  }
  return pins;
}

/** Permission Protocol's demo signing keys never authorize a real call. */
export function isDemoKeyId(keyId: string): boolean {
  return keyId.startsWith('pp-demo-');
}
