import { spawn } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { parseConfig } from '../config.js';
import { awaitLogin, DeviceLoginError, startLogin } from '../cloud/device-login.js';
import { PRODUCTION_API_URL } from '../cloud/pinned-keys.js';
import { saveInstallToken } from '../cloud/token.js';
import { createKey, keysDir, loadSigningKey } from '../keystore.js';
import type { KeySetEntry } from '../signing/keys.js';
import { findServers, wrapServer, MCP_CLIENTS, type FoundServer, type McpClient } from './mcp-clients.js';
import { SELF_TEST_SERVER_LABEL, SELF_TEST_TOOL } from './selftest-server.js';
import { isPresetName, presetPolicyBody, PRESET_NAMES, type PresetName } from '../presets/coding-agent.js';

/**
 * `mcp-guard init`: from nothing to a first signed receipt.
 *
 *   1. find the MCP servers Claude Code and Cursor are configured with; pick one
 *   2. device login: a signed-in owner or admin connects this guard in the browser
 *   3. store the install token (OS keychain, else a 0600 file)
 *   4. create the local signing key if there is none
 *   5. write a policy with one hold rule and cloud approvals on
 *   6. wrap the chosen server in the client's config (the file is copied aside first)
 *   7. self-test: hold a do-nothing call, wait for a signature, verify the receipt
 *   8. print the receipt, how to verify it again, and the time it all took
 *
 * Nothing is wrapped before the login succeeds, and a failed self-test says so: the
 * setup is left in place (calls to the wrapped server's held tool stay blocked until a
 * signature works), with the backup path to undo it.
 */

const TOOL_NAME_PATTERN = /^[A-Za-z0-9_.:/@-]{1,128}$/;
const LABEL_PATTERN = /^[A-Za-z0-9._:/@-]{1,64}$/;
/** Tools worth a signature by default, by name. A guess to preselect; the person chooses. */
const RISKY_TOOL = /(delete|remove|drop|destroy|write|update|create|send|post|publish|deploy|merge|push|pay|transfer|refund|exec|run|shell|sql|migrate)/i;

export interface InitIo {
  out(line: string): void;
  err(line: string): void;
  /** Ask a question; resolves to the trimmed answer. Only called when `interactive`. */
  ask(question: string): Promise<string>;
  openBrowser(url: string): void;
  interactive: boolean;
}

interface InitFlags {
  apiUrl: string;
  trustKeys: KeySetEntry[];
  client?: McpClient;
  server?: string;
  tool?: string;
  preset?: PresetName;
  mcpConfig?: string;
  agentId?: string;
  environment: 'development' | 'staging' | 'production';
  label?: string;
  yes: boolean;
  noBrowser: boolean;
  skipSelfTest: boolean;
  help: boolean;
}

export const INIT_HELP = `
mcp-guard init: connect this machine to Permission Protocol and get a first signed receipt

Usage:
  mcp-guard init [options]

Options:
  --client <claude-code|cursor>   only look at this client's MCP config
  --mcp-config <path>             use this MCP config file instead of the known locations
  --server <name>                 the server to wrap (asked when there is more than one)
  --tool <name>                   the tool to hold for a signature (asked, or suggested)
  --preset <name>                 write a ready policy instead of one hold rule: coding-agent
                                  (destructive commands held, secret reads observed; see docs/presets.md)
  --agent-id <id>                 how receipts name the agent (default: the client)
  --environment <label>           development | staging | production (default production)
  --label <name>                  how this machine is named on the connect page (default: host name)
  --yes                           take the suggested answer to every question
  --no-browser                    print the links instead of opening them
  --skip-self-test                set up without holding a test call
  --api-url <origin>              a non-production Permission Protocol (needs --trust-key)
  --trust-key <key id>=<base64>   its receipt-signing public key; repeatable
`.trim();

class InitError extends Error {}

function parseFlags(argv: string[]): InitFlags {
  const flags: InitFlags = { apiUrl: PRODUCTION_API_URL, trustKeys: [], environment: 'production', yes: false, noBrowser: false, skipSelfTest: false, help: false };
  const value = (i: number, name: string): string => {
    if (argv[i + 1] === undefined || argv[i + 1].startsWith('--')) throw new InitError(`${name} needs a value`);
    return argv[i + 1];
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case '--help': case '-h': flags.help = true; break;
      case '--yes': case '-y': flags.yes = true; break;
      case '--no-browser': flags.noBrowser = true; break;
      case '--skip-self-test': flags.skipSelfTest = true; break;
      case '--api-url': flags.apiUrl = value(i++, arg); break;
      case '--server': flags.server = value(i++, arg); break;
      case '--tool': flags.tool = value(i++, arg); break;
      case '--preset': {
        const preset = value(i++, arg);
        if (!isPresetName(preset)) throw new InitError(`--preset must be one of: ${PRESET_NAMES.join(', ')}`);
        flags.preset = preset;
        break;
      }
      case '--mcp-config': flags.mcpConfig = value(i++, arg); break;
      case '--agent-id': flags.agentId = value(i++, arg); break;
      case '--label': flags.label = value(i++, arg); break;
      case '--client': {
        const client = value(i++, arg) as McpClient;
        if (!MCP_CLIENTS.includes(client)) throw new InitError(`--client must be one of: ${MCP_CLIENTS.join(', ')}`);
        flags.client = client;
        break;
      }
      case '--environment': {
        const environment = value(i++, arg);
        if (environment !== 'development' && environment !== 'staging' && environment !== 'production') throw new InitError('--environment must be development, staging or production');
        flags.environment = environment;
        break;
      }
      case '--trust-key': {
        const pair = value(i++, arg);
        const at = pair.indexOf('=');
        if (at <= 0) throw new InitError('--trust-key must be <key id>=<base64 public key>');
        flags.trustKeys.push({ key_id: pair.slice(0, at), alg: 'ed25519', public_key_b64: pair.slice(at + 1) });
        break;
      }
      default: throw new InitError(`unknown option: ${arg}`);
    }
  }
  if (flags.preset && flags.tool) throw new InitError('--preset and --tool cannot be used together: the preset names what it holds');
  return flags;
}

function yamlString(value: string): string {
  return JSON.stringify(value);
}

/**
 * The policy init writes: everything else allowed, one tool held for a signature; or,
 * with a preset, the preset's rules.
 */
export function policyText(input: { serverLabel: string; tool: string | null; environment: string; apiUrl: string; trustKeys: KeySetEntry[]; preset?: PresetName }): string {
  if (input.preset) {
    return [
      '# Written by `mcp-guard init --preset ' + input.preset + '`. Edit freely: the loader refuses anything it does not recognise.',
      presetPolicyBody(input.preset).trimEnd(),
      '',
      `server_label: ${yamlString(input.serverLabel)}`,
      ...cloudLines(input),
    ].join('\n') + '\n';
  }
  const lines = [
    '# Written by `mcp-guard init`. Edit freely: the loader refuses anything it does not recognise.',
    '# Every call to a tool with a require_approval rule waits for a signature in Permission Protocol.',
    input.tool
      ? 'default_action: allow            # tools without a rule run unchecked. Use require_approval to hold everything else.'
      : 'default_action: require_approval # no tool was chosen, so every call needs a signature',
    `server_label: ${yamlString(input.serverLabel)}`,
    'rules:' + (input.tool ? '' : ' []'),
  ];
  if (input.tool) {
    lines.push(`  - id: ${yamlString(`hold-${input.tool}`.slice(0, 80))}`);
    lines.push(`    tool: ${yamlString(input.tool)}`);
    lines.push('    action: require_approval');
    lines.push('    reversibility: irreversible');
  }
  lines.push(...cloudLines(input));
  return lines.join('\n') + '\n';
}

function cloudLines(input: { environment: string; apiUrl: string; trustKeys: KeySetEntry[] }): string[] {
  const lines = ['cloud:'];
  if (input.apiUrl !== PRODUCTION_API_URL) lines.push(`  api_url: ${yamlString(input.apiUrl)}`);
  lines.push(`  environment: ${input.environment}`);
  lines.push('  approval_timeout_seconds: 600');
  if (input.apiUrl !== PRODUCTION_API_URL) {
    lines.push('  trust_keys:');
    for (const key of input.trustKeys) lines.push(`    - { key_id: ${yamlString(key.key_id)}, public_key_b64: ${yamlString(key.public_key_b64)} }`);
  }
  return lines;
}

function safeLabel(name: string): string {
  const cleaned = name.replace(/[^A-Za-z0-9._:/@-]/g, '-').slice(0, 64);
  return LABEL_PATTERN.test(cleaned) ? cleaned : 'mcp-server';
}

/** Ask a server for its tool names. Best effort: any failure is an empty list. */
export function discoverTools(command: string, args: string[], timeoutMs = 8_000): Promise<string[]> {
  return new Promise((resolve) => {
    let done = false;
    let buffer = '';
    const finish = (tools: string[]): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { child.kill(); } catch { /* already gone */ }
      resolve(tools);
    };
    const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'ignore'], shell: process.platform === 'win32', env: Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('PP_'))) });
    const timer = setTimeout(() => finish([]), timeoutMs);
    child.on('error', () => finish([]));
    child.on('exit', () => finish([]));
    const send = (message: unknown): void => { try { child.stdin!.write(JSON.stringify(message) + '\n'); } catch { /* closed */ } };
    child.stdout!.on('data', (chunk) => {
      buffer += chunk.toString();
      let index: number;
      while ((index = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);
        let message: any;
        try { message = JSON.parse(line); } catch { continue; }
        if (message?.id === 1) {
          send({ jsonrpc: '2.0', method: 'notifications/initialized' });
          send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
        } else if (message?.id === 2) {
          const tools = Array.isArray(message.result?.tools) ? message.result.tools.map((t: any) => t?.name).filter((n: unknown): n is string => typeof n === 'string' && !!n) : [];
          finish(tools);
        }
      }
    });
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'mcp-guard-init', version: '1' } } });
  });
}

export interface SelfTestResult {
  ok: boolean;
  receiptId: string | null;
  receiptUrl: string | null;
  signer: string | null;
  reason: string | null;
  receiptsPath: string;
  policyPath: string;
}

/**
 * Hold one do-nothing call through the real guard and the real approval flow: the same
 * code path every held call takes. Resolves when the call is released or refused.
 */
export function runSelfTest(input: { apiUrl: string; trustKeys: KeySetEntry[]; agentId: string; onLink: (url: string) => void; timeoutSeconds?: number }): Promise<SelfTestResult> {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-guard-self-test-'));
  const policyPath = join(dir, 'pp.config.yaml');
  const receiptsPath = join(dirname(keysDir()), 'self-test-receipts.jsonl');
  const timeoutSeconds = input.timeoutSeconds ?? 600;
  const policy = [
    'default_action: block',
    `server_label: ${SELF_TEST_SERVER_LABEL}`,
    'rules:',
    `  - { id: self-test, tool: ${SELF_TEST_TOOL}, action: require_approval, reversibility: irreversible }`,
    'cloud:',
    ...(input.apiUrl !== PRODUCTION_API_URL ? [`  api_url: ${yamlString(input.apiUrl)}`] : []),
    '  environment: development',
    `  approval_timeout_seconds: ${timeoutSeconds}`,
    ...(input.apiUrl !== PRODUCTION_API_URL ? ['  trust_keys:', ...input.trustKeys.map((k) => `    - { key_id: ${yamlString(k.key_id)}, public_key_b64: ${yamlString(k.public_key_b64)} }`)] : []),
  ].join('\n') + '\n';
  writeFileSync(policyPath, policy);
  mkdirSync(dirname(receiptsPath), { recursive: true });
  const before = existsSync(receiptsPath) ? readFileSync(receiptsPath, 'utf-8').length : 0;

  return new Promise((resolve) => {
    const cli = join(__dirname, '..', 'cli.js');
    const server = join(__dirname, 'selftest-server.js');
    const child = spawn(process.execPath, [cli, '--config', policyPath, '--agent-id', input.agentId, '--', process.execPath, server], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, PP_SHARED_RECEIPTS_PATH: receiptsPath },
    });
    let stderr = '';
    let stdout = '';
    let linked = false;
    let settled = false;
    const finish = (result: Omit<SelfTestResult, 'receiptsPath' | 'policyPath'>): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { child.kill(); } catch { /* already gone */ }
      resolve({ ...result, receiptsPath, policyPath });
    };
    const lastCloudLine = (): any => {
      if (!existsSync(receiptsPath)) return null;
      const lines = readFileSync(receiptsPath, 'utf-8').slice(before).split('\n').filter(Boolean);
      for (let i = lines.length - 1; i >= 0; i--) {
        try { const parsed = JSON.parse(lines[i]); if (parsed.cloud) return parsed.cloud; } catch { /* skip */ }
      }
      return null;
    };
    const timer = setTimeout(() => finish({ ok: false, receiptId: null, receiptUrl: null, signer: null, reason: 'the self-test did not finish in time' }), (timeoutSeconds + 30) * 1000);
    child.stderr!.on('data', (chunk) => {
      stderr += chunk.toString();
      const match = /Sign or reject: (\S+)/.exec(stderr);
      if (match && !linked) { linked = true; input.onLink(match[1]); }
    });
    child.stdout!.on('data', (chunk) => {
      stdout += chunk.toString();
      for (const line of stdout.split('\n')) {
        let message: any;
        try { message = JSON.parse(line); } catch { continue; }
        if (message?.id !== 1) continue;
        const cloud = lastCloudLine();
        if (message.result && cloud?.decision === 'released') {
          finish({ ok: true, receiptId: cloud.receiptId, receiptUrl: cloud.receiptUrl ?? null, signer: cloud.decider?.display ?? cloud.decider?.id ?? null, reason: null });
        } else {
          finish({ ok: false, receiptId: cloud?.receiptId ?? null, receiptUrl: cloud?.receiptUrl ?? null, signer: null, reason: message.error?.message ?? 'the call was not released' });
        }
      }
    });
    child.on('exit', (code) => finish({ ok: false, receiptId: null, receiptUrl: null, signer: null, reason: `the guard exited (${code}): ${stderr.trim().split('\n').slice(-1)[0] ?? 'no output'}` }));
    child.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: SELF_TEST_TOOL, arguments: { note: 'mcp-guard init self-test' } } }) + '\n');
  });
}

function elapsed(ms: number): string {
  const total = Math.round(ms / 1000);
  const minutes = Math.floor(total / 60);
  return minutes > 0 ? `${minutes}m ${total % 60}s` : `${total}s`;
}

function guardVersion(): string {
  return JSON.parse(readFileSync(join(__dirname, '..', '..', '..', 'package.json'), 'utf-8')).version;
}

async function choose<T>(io: InitIo, flags: InitFlags, question: string, options: T[], label: (option: T) => string, suggested: number): Promise<T> {
  if (options.length === 1) return options[0];
  if (flags.yes || !io.interactive) return options[suggested];
  io.out(question);
  options.forEach((option, index) => io.out(`  ${index + 1}. ${label(option)}${index === suggested ? '   (suggested)' : ''}`));
  for (;;) {
    const answer = await io.ask(`Number [${suggested + 1}]: `);
    if (!answer) return options[suggested];
    const index = Number(answer) - 1;
    if (Number.isInteger(index) && index >= 0 && index < options.length) return options[index];
    io.out(`Type a number from 1 to ${options.length}.`);
  }
}

export interface InitDeps {
  fetchImpl?: typeof fetch;
  home?: string;
  cwd?: string;
  discover?: typeof discoverTools;
  selfTest?: typeof runSelfTest;
  now?: () => number;
}

export async function runInit(argv: string[], io: InitIo, deps: InitDeps = {}): Promise<number> {
  const now = deps.now ?? (() => Date.now());
  const startedAt = now();
  let flags: InitFlags;
  try {
    flags = parseFlags(argv);
  } catch (err: any) {
    io.err(`[mcp-guard] ${err.message}`);
    io.err(INIT_HELP);
    return 2;
  }
  if (flags.help) { io.out(INIT_HELP); return 0; }

  try {
    if (flags.apiUrl.replace(/\/+$/, '') !== PRODUCTION_API_URL && flags.trustKeys.length === 0) {
      throw new InitError('--api-url names a non-production Permission Protocol, so it needs at least one --trust-key <key id>=<base64 public key>.');
    }
    // The same rules the policy loader applies: production keys are pinned in the
    // release; any other Permission Protocol must name the keys to pin.
    const cloud = parseConfig(policyText({ serverLabel: 'check', tool: null, environment: flags.environment, apiUrl: flags.apiUrl.replace(/\/+$/, ''), trustKeys: flags.trustKeys })).cloud!;
    if (flags.trustKeys.length > 0 && cloud.api_url === PRODUCTION_API_URL) throw new InitError('--trust-key cannot be used with the production API: its keys are pinned in this release');
    const apiUrl = cloud.api_url;

    // 1. Which server.
    const { servers, skipped } = findServers({ home: deps.home, cwd: deps.cwd, client: flags.client, file: flags.mcpConfig });
    for (const file of skipped) io.err(`[mcp-guard] Skipped ${file.file}: ${file.reason}`);
    const candidates = servers.filter((s) => !s.wrapped && (!flags.server || s.name === flags.server));
    if (candidates.length === 0) {
      const already = servers.filter((s) => s.wrapped && (!flags.server || s.name === flags.server));
      if (already.length > 0) throw new InitError(`${already.map((s) => `"${s.name}"`).join(', ')} ${already.length === 1 ? 'is' : 'are'} already wrapped by mcp-guard. Nothing to do.`);
      throw new InitError(
        flags.server
          ? `No MCP server named "${flags.server}" was found in a Claude Code or Cursor config.`
          : 'No stdio MCP server was found in a Claude Code or Cursor config (.mcp.json, ~/.claude.json, .cursor/mcp.json, ~/.cursor/mcp.json). Add one to your client first, or pass --mcp-config <path>.',
      );
    }
    const server: FoundServer = await choose(io, flags, 'Which MCP server should the guard wrap?', candidates, (s) => `${s.name}  (${s.client}, ${s.file})`, 0);
    io.out(`Server: ${server.name} (${server.client}, ${server.file})`);

    // 2. Device login.
    const label = (flags.label ?? hostname()).replace(/[^A-Za-z0-9_.:@ -]/g, '-').slice(0, 64) || null;
    const login = await startLogin(apiUrl, label, { fetchImpl: deps.fetchImpl });
    io.out('');
    io.out('Connect this guard to your Permission Protocol workspace:');
    io.out(`  1. Open ${login.verificationUrlComplete}`);
    io.out(`  2. Check that the page shows this code: ${login.userCode}`);
    io.out('  3. Choose Connect. You need the owner or admin role.');
    if (!flags.noBrowser) io.openBrowser(login.verificationUrlComplete);
    io.out('Waiting for you to connect...');
    const connected = await awaitLogin(apiUrl, login, { fetchImpl: deps.fetchImpl });
    io.out(`Connected to workspace: ${connected.workspace.name}${connected.workspace.slug ? ` (${connected.workspace.slug})` : ''}`);
    if (io.interactive && !flags.yes) {
      const answer = (await io.ask('Is that the workspace you meant? [Y/n] ')).toLowerCase();
      if (answer === 'n' || answer === 'no') {
        throw new InitError(`Stopped. Nothing on this machine was changed. Revoke the token "MCP Guard${label ? ` (${label})` : ''}" in that workspace under Settings > Developer access.`);
      }
    }

    // 3. Token.
    const stored = saveInstallToken(connected.token);
    io.out(stored.kind === 'keychain' ? 'Install token: stored in the OS keychain.' : `Install token: stored in ${stored.path} (owner-only).`);

    // 4. Local signing key (allow and block decisions are signed on this machine).
    try {
      loadSigningKey();
    } catch (err: any) {
      if (err?.code !== 'SIGNING_KEY_MISSING') throw err;
      const key = createKey();
      io.out(`Local signing key: created ${key.keyId} in ${keysDir()}.`);
    }

    // 5. Which tool to hold (a preset names its own rules).
    let tool = flags.tool ?? null;
    if (flags.preset) {
      io.out(`Policy preset: ${flags.preset}. Destructive commands, SQL, infrastructure and cloud deletes, and changes to the guard itself need a signature; secret reads are recorded, not held. See docs/presets.md.`);
    } else if (!tool) {
      const tools = (await (deps.discover ?? discoverTools)(server.command, server.args)).filter((name) => TOOL_NAME_PATTERN.test(name));
      if (tools.length > 0) {
        const suggested = Math.max(0, tools.findIndex((name) => RISKY_TOOL.test(name)));
        tool = await choose(io, flags, `Which tool of "${server.name}" should need a signature?`, tools, (name) => name, suggested);
      } else {
        io.out(`Could not read the tool list of "${server.name}", so every call to it will need a signature. Edit the policy to narrow that.`);
      }
    } else if (!TOOL_NAME_PATTERN.test(tool)) {
      throw new InitError(`--tool "${tool}" has characters Permission Protocol does not accept in a tool name (letters, digits and _ . : / @ - only).`);
    }
    if (!flags.preset) io.out(tool ? `Hold rule: "${tool}" needs a signature. Every other tool of this server runs as before.` : 'Hold rule: every call needs a signature.');

    // 6. Policy file.
    const serverLabel = safeLabel(server.name);
    const policyPath = join(dirname(keysDir()), 'policies', `${serverLabel.replace(/[/:@]/g, '-')}.yaml`);
    const policy = policyText({ serverLabel, tool, environment: flags.environment, apiUrl, trustKeys: flags.trustKeys, preset: flags.preset });
    parseConfig(policy); // never write a policy the guard would refuse to load
    mkdirSync(dirname(policyPath), { recursive: true });
    if (existsSync(policyPath) && readFileSync(policyPath, 'utf-8') !== policy) {
      const aside = `${policyPath}.backup-${new Date(now()).toISOString().replace(/[:.]/g, '-')}`;
      copyFileSync(policyPath, aside);
      io.out(`Policy: the existing ${policyPath} was copied to ${aside}.`);
    }
    writeFileSync(policyPath, policy);
    io.out(`Policy: ${policyPath}`);

    // 7. Wrap the server.
    const agentId = flags.agentId ?? server.client;
    if (!TOOL_NAME_PATTERN.test(agentId)) throw new InitError('--agent-id may contain letters, digits and _ . : / @ - only.');
    const wrapped = wrapServer(server, { policyPath, agentId, version: guardVersion(), now: new Date(now()) });
    io.out(`Wrapped "${server.name}" in ${server.file}`);
    io.out(`  before: ${[server.command, ...server.args].join(' ')}`);
    io.out(`  now:    ${[wrapped.command, ...wrapped.args].join(' ')}`);
    io.out(`  undo:   copy ${wrapped.backup} back over ${server.file}`);
    io.out(`Restart ${server.client === 'cursor' ? 'Cursor' : 'Claude Code'} so it starts "${server.name}" through the guard.`);

    // 8. Self-test.
    if (flags.skipSelfTest) {
      io.out('');
      io.out(`Set up in ${elapsed(now() - startedAt)}. The self-test was skipped, so no receipt has been signed yet.`);
      return 0;
    }
    io.out('');
    io.out('Self-test: holding a do-nothing call for your signature.');
    const test = await (deps.selfTest ?? runSelfTest)({
      apiUrl,
      trustKeys: flags.trustKeys,
      agentId,
      onLink: (url) => {
        io.out(`  Sign it here: ${url}`);
        if (!flags.noBrowser) io.openBrowser(url);
        io.out('  Waiting for your signature...');
      },
    });
    if (!test.ok) {
      io.err(`[mcp-guard] Self-test did not produce a signed receipt: ${test.reason}`);
      io.err('[mcp-guard] The setup is in place and fails closed: the held tool stays blocked until a signature works. Fix the cause above, then call the tool from your client.');
      return 1;
    }
    const verifyCommand = `npx ${'@permission-protocol/mcp-guard'} receipt verify ${test.receiptId} --receipts-path "${test.receiptsPath}"${apiUrl !== PRODUCTION_API_URL ? ` --config "${policyPath}"` : ''}`;
    io.out('');
    io.out(`Signed receipt: ${test.receiptId}${test.signer ? `, signed by ${test.signer}` : ''}`);
    if (test.receiptUrl) io.out(`  View it:   ${test.receiptUrl}`);
    io.out(`  Verify it: ${verifyCommand}`);
    io.out('');
    io.out(`Time to first signed receipt: ${elapsed(now() - startedAt)}.`);
    return 0;
  } catch (err: any) {
    if (err instanceof InitError || err instanceof DeviceLoginError) io.err(`[mcp-guard] ${err.message}`);
    else io.err(`[mcp-guard] init failed: ${err?.message ?? err}`);
    return 1;
  }
}

/** The terminal: prompts on a TTY, opens the default browser. */
export function terminalIo(): InitIo {
  const interactive = Boolean(process.stdin.isTTY && process.stdout.isTTY);
  return {
    interactive,
    out: (line) => { process.stdout.write(line + '\n'); },
    err: (line) => { process.stderr.write(line + '\n'); },
    ask: async (question) => {
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      try { return (await rl.question(question)).trim(); } finally { rl.close(); }
    },
    openBrowser: (url) => {
      if (!interactive) return;
      try {
        const [command, args] = process.platform === 'darwin' ? ['open', [url]] : process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url]] : ['xdg-open', [url]];
        spawn(command as string, args as string[], { stdio: 'ignore', detached: true }).on('error', () => undefined).unref();
      } catch { /* the link is printed too */ }
    },
  };
}
