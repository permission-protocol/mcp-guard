import { existsSync } from 'node:fs';
import { createKey, keySetPath, keysDir, loadSigningKey, revokeKey } from './keystore.js';

/**
 * `mcp-guard keys`: the only way signing keys are created.
 *
 *   keys init [--demo]     first key (demo keys sign receipts with scope "demo")
 *   keys rotate [--demo]   new key; older keys stay in keys.json so old receipts verify
 *   keys revoke <key id>   every receipt that key signed stops verifying
 *   keys show              key id, fingerprint, the --trust value and the keys.json path
 *
 * The directory is $PP_KEYS_DIR, else ~/.config/mcp-guard/keys. Exit 0 ok, 1 error.
 */

function show(): void {
  const key = loadSigningKey();
  console.log(`key id:      ${key.keyId}${key.demo ? ' (demo: receipts carry scope "demo")' : ''}`);
  console.log(`fingerprint: ${key.fingerprint}`);
  console.log(`key set:     ${keySetPath()}`);
  console.log(`gate flags:  --keys keys.json --trust ${key.keyId}=${key.fingerprint}`);
  console.log('Commit keys.json where your gate runs (for example .pp/keys.json) and store the --trust value in the gate (for example the MCP_GUARD_TRUST repository variable).');
}

export function runKeys(argv: string[]): number {
  const [sub, ...rest] = argv;
  const demo = rest.includes('--demo');
  try {
    switch (sub) {
      case 'init':
      case 'rotate': {
        const key = createKey({ demo, rotate: sub === 'rotate' });
        console.log(`${sub === 'init' ? 'Created' : 'Rotated to'} signing key ${key.keyId} in ${keysDir()} (private key 0600, never leaves this directory).`);
        show();
        return 0;
      }
      case 'revoke': {
        const id = rest.find((a) => !a.startsWith('--'));
        if (!id) { console.error('usage: mcp-guard keys revoke <key id>'); return 1; }
        revokeKey(id);
        console.log(`Revoked ${id}: receipts it signed now fail verification. Republish ${keySetPath()} to your gates, then run \`mcp-guard keys rotate\` to sign again.`);
        return 0;
      }
      case 'show':
        if (!existsSync(keySetPath())) { console.error(`No key set at ${keySetPath()}. Run \`mcp-guard keys init\`.`); return 1; }
        show();
        return 0;
      default:
        console.error('usage: mcp-guard keys init [--demo] | rotate [--demo] | revoke <key id> | show');
        return 1;
    }
  } catch (err: any) {
    console.error(`[mcp-guard] Error: ${err.message}`);
    return 1;
  }
}
