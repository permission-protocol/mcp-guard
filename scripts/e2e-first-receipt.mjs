#!/usr/bin/env node
// Fresh machine to first signed receipt, timed.
//
// Runs the real `mcp-guard init` in an empty config directory with one MCP server
// configured, then runs the verify command it printed. Fails unless init exits 0, the
// receipt verifies, and the whole thing took under ten minutes.
//
//   npm run build && node scripts/e2e-first-receipt.mjs --stand-in
//       no account needed: a local stand-in for Permission Protocol connects the login
//       and signs the self-test call. This is what CI runs.
//
//   node scripts/e2e-first-receipt.mjs [--api-url <origin> --trust-key <id>=<base64>]
//       against a real Permission Protocol (production by default). A person does the
//       two browser steps: Connect, then Sign. The links are printed.
//
// Nothing outside a fresh temp directory is read or written: not your keychain, not
// your MCP client config, not your receipts.
import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const LIMIT_SECONDS = 600;
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(root, 'dist', 'src', 'cli.js');
const echoServer = join(root, 'dist', 'src', 'tests', 'fixtures-echo-server.js');
const args = process.argv.slice(2);
const standIn = args.includes('--stand-in');
const passthrough = args.filter((arg) => arg !== '--stand-in');

const machine = mkdtempSync(join(tmpdir(), 'mcp-guard-first-receipt-'));
const project = join(machine, 'project');
mkdirSync(project, { recursive: true });
const mcpConfig = join(project, '.mcp.json');
writeFileSync(mcpConfig, JSON.stringify({ mcpServers: { filesystem: { command: process.execPath, args: [echoServer] } } }, null, 2) + '\n');

const env = { ...process.env, XDG_CONFIG_HOME: join(machine, 'config'), MCP_GUARD_TOKEN_STORE: 'file', ECHO_LOG: join(machine, 'server.log') };
for (const key of Object.keys(env)) if (key.startsWith('PP_')) delete env[key];

let fake = null;
let initArgs = ['init', '--mcp-config', mcpConfig, '--tool', 'delete_file', '--label', 'e2e-first-receipt', '--yes', '--no-browser', ...passthrough];
if (standIn) {
  const { startFakePp } = await import(pathToFileURL(join(root, 'dist', 'src', 'tests', 'cloud-helpers.js')).href);
  fake = await startFakePp(`pp_test_${'e2e0'.repeat(8)}`);
  initArgs = [...initArgs, '--api-url', fake.url, '--trust-key', `${fake.issuer.keyId}=${fake.issuer.publicKeyB64}`];
}

const fail = async (message) => {
  console.error(`\nFAILED: ${message}`);
  if (fake) await fake.close();
  process.exit(1);
};

console.log(`Fresh machine: ${machine}`);
console.log(standIn ? 'Permission Protocol: local stand-in (signs by itself)\n' : 'Permission Protocol: real. Do the two browser steps when the links appear.\n');

const started = Date.now();
let output = '';
const code = await new Promise((resolve) => {
  const child = spawn(process.execPath, [cli, ...initArgs], { env, cwd: project, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.on('data', (chunk) => { output += chunk; process.stdout.write(chunk); });
  child.stderr.on('data', (chunk) => { process.stderr.write(chunk); });
  const timer = setTimeout(() => { child.kill(); resolve('timeout'); }, (LIMIT_SECONDS + 30) * 1000);
  child.on('exit', (status) => { clearTimeout(timer); resolve(status); });
});
const seconds = (Date.now() - started) / 1000;

if (code !== 0) await fail(`mcp-guard init exited with ${code} after ${seconds.toFixed(0)} s`);
const verify = /Verify it: npx @permission-protocol\/mcp-guard (receipt verify \S+) --receipts-path "([^"]+)"(?: --config "([^"]+)")?/.exec(output);
if (!verify) await fail('init did not print a verify command');
const verifyArgs = [...verify[1].split(' '), '--receipts-path', verify[2], ...(verify[3] ? ['--config', verify[3]] : [])];
const verified = spawnSync(process.execPath, [cli, ...verifyArgs], { env, encoding: 'utf-8' });
process.stdout.write(`\n$ mcp-guard ${verifyArgs.join(' ')}\n${verified.stdout}${verified.stderr}`);
if (verified.status !== 0) await fail('the printed verify command did not verify the receipt');
if (seconds >= LIMIT_SECONDS) await fail(`first signed receipt took ${seconds.toFixed(0)} s, over the ${LIMIT_SECONDS} s goal`);

if (fake) await fake.close();
console.log(`\nPASSED: install to first signed receipt in ${seconds.toFixed(1)} s (goal: under ${LIMIT_SECONDS} s).`);
