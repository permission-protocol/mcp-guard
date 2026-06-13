#!/usr/bin/env node
// Infra-MCP — Permission Deck Slice 2
//
// A minimal, dependency-free MCP stdio server exposing exactly three tools that
// represent the "code / infra" action class:
//
//   - merge_pr            { repo, pr_number, title?, scope_ref?, scope_sha?, _pp? }
//   - run_sql_migration   { env, statement, _pp? }
//   - deploy              { env, service, _pp? }
//
// This server is a NORMAL MCP stdio server. It does NOT enforce anything. It is
// meant to run BEHIND `mcp-guard`, which is a stdio JSON-RPC proxy that
// intercepts `tools/call` upstream, classifies (allow / block / hold), and only
// forwards calls it has released. By the time a `tools/call` reaches THIS
// server, the guard has already authorized it — so the tool handler just
// executes the (simulated) side effect.
//
// The tool handlers are STUBS: they append a line to `outbox.log` (next to this
// file) to prove the action executed, then return a normal MCP tool result. The
// `_pp` metadata field (confidence, etc.) is read upstream by mcp-guard's
// classifier; here we accept and ignore it gracefully.
//
// Protocol surface implemented (JSON-RPC 2.0 over newline-delimited stdin/stdout):
//   - initialize
//   - notifications/initialized   (notification, no response)
//   - tools/list
//   - tools/call
//   - ping
// Anything else returns a JSON-RPC -32601 "Method not found".

import { appendFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUTBOX = join(__dirname, 'outbox.log');

const PROTOCOL_VERSION = '2024-11-05';
const SERVER_INFO = { name: 'infra-mcp', version: '0.1.0' };

// ---------------------------------------------------------------------------
// Tool definitions (advertised via tools/list)
// ---------------------------------------------------------------------------

// _pp is an optional metadata envelope the calling agent attaches for the
// upstream guard/classifier (confidence self-report). The Infra-MCP itself does
// not act on it; it is declared here so clients that introspect the schema know
// it is an accepted, additive field.
const PP_META_SCHEMA = {
  type: 'object',
  description:
    'Permission Protocol metadata read by mcp-guard upstream (confidence self-report). Ignored by this server.',
  properties: {
    confidence: {
      type: 'number',
      description: 'Agent self-reported confidence 0-100.',
    },
  },
  additionalProperties: true,
};

const TOOLS = [
  {
    name: 'merge_pr',
    description:
      'Merge a GitHub pull request (reversible — a merge can be reverted; guarded as a Decide with optional countdown upstream). Carries scope_ref/scope_sha so the upstream signer can bind a receipt to this exact merge.',
    inputSchema: {
      type: 'object',
      properties: {
        repo: { type: 'string', description: 'Repository, e.g. "owner/name".' },
        pr_number: { type: 'number', description: 'Pull request number.' },
        title: { type: 'string', description: 'Optional PR title (for the Decide card).' },
        scope_ref: {
          type: 'string',
          description: 'Optional git ref the receipt is scoped to, e.g. "refs/pull/42/merge".',
        },
        scope_sha: {
          type: 'string',
          description: 'Optional merge commit SHA the receipt is scoped to.',
        },
        _pp: PP_META_SCHEMA,
      },
      required: ['repo', 'pr_number'],
      additionalProperties: false,
    },
  },
  {
    name: 'run_sql_migration',
    description:
      'Run a SQL schema migration (irreversible — schema change is a hard stop until approved upstream).',
    inputSchema: {
      type: 'object',
      properties: {
        env: { type: 'string', description: 'Target environment, e.g. "staging" or "production".' },
        statement: { type: 'string', description: 'The SQL migration statement to execute.' },
        _pp: PP_META_SCHEMA,
      },
      required: ['env', 'statement'],
      additionalProperties: false,
    },
  },
  {
    name: 'deploy',
    description:
      'Deploy a service to an environment (reversible — a rollback exists; guarded as a Decide upstream).',
    inputSchema: {
      type: 'object',
      properties: {
        env: { type: 'string', description: 'Target environment, e.g. "staging" or "production".' },
        service: { type: 'string', description: 'The service / app being deployed.' },
        _pp: PP_META_SCHEMA,
      },
      required: ['env', 'service'],
      additionalProperties: false,
    },
  },
];

const TOOL_NAMES = new Set(TOOLS.map((t) => t.name));

// ---------------------------------------------------------------------------
// Side-effect stubs — append to outbox.log to prove execution, return a result
// ---------------------------------------------------------------------------

function logOutbox(line) {
  const stamped = `${new Date().toISOString()} ${line}\n`;
  appendFileSync(OUTBOX, stamped);
  return stamped.trimEnd();
}

function runTool(name, args) {
  const a = args && typeof args === 'object' ? args : {};
  switch (name) {
    case 'merge_pr': {
      const repo = String(a.repo ?? '');
      const pr = Number(a.pr_number ?? 0);
      const title = a.title != null ? String(a.title) : '';
      const scopeSha = a.scope_sha != null ? String(a.scope_sha) : '';
      logOutbox(
        `PR MERGED repo=${repo} pr=${pr}` +
          (title ? ` title=${JSON.stringify(title)}` : '') +
          (scopeSha ? ` scope_sha=${scopeSha}` : '')
      );
      return `Merged PR #${pr} in ${repo}${title ? ` ("${title}")` : ''}.`;
    }
    case 'run_sql_migration': {
      const env = String(a.env ?? '');
      const statement = String(a.statement ?? '');
      logOutbox(`SQL MIGRATED env=${env} stmt=${JSON.stringify(statement)}`);
      return `Ran SQL migration on ${env}: ${statement}`;
    }
    case 'deploy': {
      const env = String(a.env ?? '');
      const service = String(a.service ?? '');
      logOutbox(`DEPLOYED env=${env} service=${service}`);
      return `Deployed ${service} to ${env}.`;
    }
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// ---------------------------------------------------------------------------
// JSON-RPC plumbing
// ---------------------------------------------------------------------------

function send(message) {
  process.stdout.write(JSON.stringify(message) + '\n');
}

function reply(id, result) {
  send({ jsonrpc: '2.0', id, result });
}

function replyError(id, code, message, data) {
  const error = { code, message };
  if (data !== undefined) error.data = data;
  send({ jsonrpc: '2.0', id, error });
}

function handleMessage(msg) {
  if (!msg || typeof msg !== 'object' || msg.jsonrpc !== '2.0') {
    return; // ignore malformed frames
  }

  const { id, method, params } = msg;
  const isNotification = id === undefined || id === null;

  switch (method) {
    case 'initialize': {
      reply(id, {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: SERVER_INFO,
      });
      return;
    }

    case 'notifications/initialized':
    case 'initialized':
      // Client handshake completion notification — no response.
      return;

    case 'ping': {
      if (!isNotification) reply(id, {});
      return;
    }

    case 'tools/list': {
      reply(id, { tools: TOOLS });
      return;
    }

    case 'tools/call': {
      const name = params?.name;
      const args = params?.arguments ?? {};
      if (!TOOL_NAMES.has(name)) {
        replyError(id, -32602, `Unknown tool: ${name}`);
        return;
      }
      try {
        const text = runTool(name, args);
        reply(id, {
          content: [{ type: 'text', text }],
          isError: false,
        });
      } catch (err) {
        // MCP convention: tool execution errors are reported as a result with
        // isError: true, not a protocol-level error.
        reply(id, {
          content: [{ type: 'text', text: `Tool error: ${err.message}` }],
          isError: true,
        });
      }
      return;
    }

    default: {
      if (!isNotification) {
        replyError(id, -32601, `Method not found: ${method}`);
      }
      return;
    }
  }
}

// ---------------------------------------------------------------------------
// stdin reader — newline-delimited JSON frames
// ---------------------------------------------------------------------------

let buffer = '';
process.stdin.setEncoding('utf8');

process.stdin.on('data', (chunk) => {
  buffer += chunk;
  let nl;
  while ((nl = buffer.indexOf('\n')) !== -1) {
    const line = buffer.slice(0, nl).trim();
    buffer = buffer.slice(nl + 1);
    if (!line) continue;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      // Skip unparseable lines rather than crash the transport.
      continue;
    }
    handleMessage(msg);
  }
});

process.stdin.on('end', () => process.exit(0));

// Log startup to stderr (stdout is reserved for JSON-RPC frames).
process.stderr.write('[infra-mcp] ready on stdio\n');
