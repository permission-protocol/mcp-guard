#!/usr/bin/env node
// Actions-MCP — Permission Deck Slice 1
//
// A minimal, dependency-free MCP stdio server exposing exactly three tools that
// represent the "outbound comms + spend" action class:
//
//   - send_email  { to, subject, body, _pp? }
//   - post_x      { text, _pp? }
//   - spend       { payee, amount_usd, memo?, _pp? }
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
const SERVER_INFO = { name: 'actions-mcp', version: '0.1.0' };

// ---------------------------------------------------------------------------
// Tool definitions (advertised via tools/list)
// ---------------------------------------------------------------------------

// _pp is an optional metadata envelope the calling agent attaches for the
// upstream guard/classifier (confidence self-report, declared spend amount).
// The Actions-MCP itself does not act on it; it is declared here so clients
// that introspect the schema know it is an accepted, additive field.
const PP_META_SCHEMA = {
  type: 'object',
  description:
    'Permission Protocol metadata read by mcp-guard upstream (confidence/amount self-report). Ignored by this server.',
  properties: {
    confidence: {
      type: 'number',
      description: 'Agent self-reported confidence 0-100.',
    },
    amount_usd: {
      type: 'number',
      description: 'Declared spend amount (spend only), cross-checked upstream.',
    },
  },
  additionalProperties: true,
};

const TOOLS = [
  {
    name: 'send_email',
    description:
      'Send an outbound email (outbound comms; reversible — guarded with a countdown upstream).',
    inputSchema: {
      type: 'object',
      properties: {
        to: { type: 'string', description: 'Recipient email address.' },
        subject: { type: 'string', description: 'Email subject line.' },
        body: { type: 'string', description: 'Email body text.' },
        _pp: PP_META_SCHEMA,
      },
      required: ['to', 'subject', 'body'],
      additionalProperties: false,
    },
  },
  {
    name: 'post_x',
    description:
      'Post to X / Twitter (public, irreversible — hard-blocked until a signed receipt is issued upstream).',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'The post text.' },
        _pp: PP_META_SCHEMA,
      },
      required: ['text'],
      additionalProperties: false,
    },
  },
  {
    name: 'spend',
    description:
      'Spend money / make a payment (reversible below cap; verified/decided upstream by amount).',
    inputSchema: {
      type: 'object',
      properties: {
        payee: { type: 'string', description: 'Who is being paid.' },
        amount_usd: { type: 'number', description: 'Amount in USD.' },
        memo: { type: 'string', description: 'Optional memo / reason.' },
        _pp: PP_META_SCHEMA,
      },
      required: ['payee', 'amount_usd'],
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
    case 'send_email': {
      const to = String(a.to ?? '');
      const subject = String(a.subject ?? '');
      logOutbox(`EMAIL SENT to=${to} subject=${JSON.stringify(subject)}`);
      return `Email sent to ${to} with subject "${subject}".`;
    }
    case 'post_x': {
      const text = String(a.text ?? '');
      logOutbox(`X POSTED text=${JSON.stringify(text)}`);
      return `Posted to X: "${text}".`;
    }
    case 'spend': {
      const payee = String(a.payee ?? '');
      const amount = Number(a.amount_usd ?? 0);
      const memo = a.memo != null ? String(a.memo) : '';
      logOutbox(
        `SPENT $${amount} to ${payee}${memo ? ` memo=${JSON.stringify(memo)}` : ''}`
      );
      return `Spent $${amount} to ${payee}${memo ? ` (${memo})` : ''}.`;
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
process.stderr.write('[actions-mcp] ready on stdio\n');
