import { loadConfig, type Config } from '../config.js';
import { hookReceiptsPath } from '../hook/decide.js';
import { loadInstallToken } from '../cloud/token.js';
import { CLIENT_LABELS, utcDay, validateBody, type ClientLabel, type HeartbeatMode } from './contract.js';
import { flag, heartbeatDisabledReason } from './launch.js';
import { bodyFor, canonicalLogPath, refresh, runHeartbeat } from './send.js';
import { defaultStatePath, loadState } from './state.js';

const HELP = `
mcp-guard heartbeat — the daily usage heartbeat (counts and rule ids only; docs/heartbeat.md)

Usage:
  mcp-guard heartbeat --show [--config <path>] [--receipts <path>] [--client <label>] [--mode enforce|observe]
      Print the exact body that would be sent for today. Sends nothing and changes nothing.
  mcp-guard heartbeat --send [same options]
      Send today's heartbeat once now (and earlier days whose totals changed).

Options:
  --config <path>    Policy file (default: ./pp.config.yaml)
  --receipts <path>  Receipt log to count (default: PP_SHARED_RECEIPTS_PATH, else pp-receipts.jsonl beside the policy)
  --client <label>   ${CLIENT_LABELS.join(' | ')}

Off when MCP_GUARD_HEARTBEAT=off (or 0 / false), when the policy sets cloud.heartbeat: false,
when the policy has no cloud: section, or when there is no install token.
`.trim();

const ORIGIN_HOSTS_HTTP = new Set(['localhost', '127.0.0.1', '[::1]']);

/** The proxy passes the policy's already-validated api_url; checked again here all the same. */
function apiOrigin(value: string | undefined): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (url.origin !== value.replace(/\/+$/, '')) return null;
    if (url.protocol === 'https:' || (url.protocol === 'http:' && ORIGIN_HOSTS_HTTP.has(url.hostname))) return url.origin;
  } catch { /* not a URL */ }
  return null;
}

interface Target { apiUrl: string; mode: HeartbeatMode; receiptsPath: string; client: ClientLabel | null }

function target(args: string[], err: (s: string) => void): Target | null {
  const clientArg = flag(args, '--client');
  if (clientArg !== undefined && !(CLIENT_LABELS as readonly string[]).includes(clientArg)) { err(`--client must be one of: ${CLIENT_LABELS.join(', ')}`); return null; }
  const modeArg = flag(args, '--mode');
  if (modeArg !== undefined && modeArg !== 'enforce' && modeArg !== 'observe') { err('--mode must be enforce or observe'); return null; }
  const client = (clientArg as ClientLabel | undefined) ?? null;
  const apiArg = flag(args, '--api-url');
  const receiptsArg = flag(args, '--receipts');

  if (apiArg !== undefined && args.includes('--background')) {
    // The proxy's sender: the proxy checked the policy before starting it.
    const apiUrl = apiOrigin(apiArg);
    if (!apiUrl || !receiptsArg) { err('bad --api-url or --receipts'); return null; }
    return { apiUrl, mode: (modeArg as HeartbeatMode | undefined) ?? 'enforce', receiptsPath: receiptsArg, client };
  }

  const configPath = flag(args, '--config') ?? './pp.config.yaml';
  let config: Config;
  try {
    config = loadConfig(configPath);
  } catch (e: any) {
    err(`the policy could not be loaded (${e?.message ?? e})`);
    return null;
  }
  const off = heartbeatDisabledReason(config, process.env);
  if (off || !config.cloud) { err(`heartbeat is off: ${off}`); return null; }
  return {
    apiUrl: config.cloud.api_url,
    mode: (modeArg as HeartbeatMode | undefined) ?? config.mode,
    receiptsPath: receiptsArg ?? hookReceiptsPath(configPath),
    client,
  };
}

export async function runHeartbeatCli(args: string[]): Promise<number> {
  if (args.includes('--help') || args.includes('-h') || args.length === 0) {
    console.log(HELP);
    return args.length === 0 ? 1 : 0;
  }
  const background = args.includes('--background');
  const say = (s: string): void => { if (!background) process.stderr.write(`[mcp-guard] ${s}\n`); };
  const t = target(args, say);
  if (!t) return background ? 0 : 1;

  const statePath = defaultStatePath();
  if (args.includes('--show')) {
    const state = loadState(statePath);
    const now = Date.now();
    const existing = state.logs.find((l) => l.path === canonicalLogPath(t.receiptsPath));
    const client = t.client ?? existing?.client ?? 'mcp-guard';
    await refresh(state, t.receiptsPath, client, now);
    const body = bodyFor(state, utcDay(now), t.mode, client);
    const checked = validateBody(body, now);
    let token = 'present';
    try { loadInstallToken(); } catch (e: any) { token = `missing (${e?.code ?? 'INSTALL_TOKEN_ERROR'}): nothing is sent`; }
    process.stderr.write(`[mcp-guard] Would POST to ${t.apiUrl}/api/mcp/heartbeat (install token: ${token}). Counted from ${canonicalLogPath(t.receiptsPath)}${state.logs.length > 1 ? ` and ${state.logs.length - 1} other log(s) this install counted before` : ''}.\n`);
    if (!checked.ok) process.stderr.write(`[mcp-guard] This body fails the contract (${checked.reason}) and would not be sent.\n`);
    console.log(JSON.stringify(body, null, 2));
    return 0;
  }

  if (!background && !args.includes('--send')) {
    console.log(HELP);
    return 1;
  }

  const existing = loadState(statePath).logs.find((l) => l.path === canonicalLogPath(t.receiptsPath));
  const client = t.client ?? existing?.client ?? 'mcp-guard';
  let result;
  try {
    result = await runHeartbeat({ apiUrl: t.apiUrl, mode: t.mode, client, receiptsPath: t.receiptsPath, statePath, force: !background });
  } catch (e: any) {
    result = { status: 'done' as const, sent: [], failed: { day: '', code: e?.code && /^[A-Z0-9_]+$/.test(e.code) ? e.code : 'INTERNAL' } };
  }
  if (result.status === 'skipped') {
    say(`heartbeat not sent: ${result.reason === 'no_token' ? 'no install token' : result.reason === 'locked' ? 'another guard process is sending' : 'sent recently or backing off after a refusal; try again later'}`);
    return background ? 0 : 1;
  }
  if (result.failed) {
    // One line, a fixed text and a code: never the token, a URL with credentials, or argument text.
    process.stderr.write(`[mcp-guard] heartbeat not sent (${result.failed.code})\n`);
    return background ? 0 : 1;
  }
  say(result.sent.length ? `heartbeat sent for ${result.sent.join(', ')}` : 'heartbeat unchanged since the last accepted one; nothing sent');
  return 0;
}
