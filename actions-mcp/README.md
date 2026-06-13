# Actions-MCP — Permission Deck Slice 1

A minimal, **dependency-free** MCP stdio server that exposes exactly three tools
representing the **outbound comms + spend** action class:

| Tool | Args | Action class |
|------|------|--------------|
| `send_email` | `{ to, subject, body, _pp? }` | reversible (countdown) |
| `post_x` | `{ text, _pp? }` | irreversible (hard-block) |
| `spend` | `{ payee, amount_usd, memo?, _pp? }` | reversible below cap (verify) |

It is a **normal MCP server**. It does **no enforcement of its own** — it is
meant to run **behind [`mcp-guard`](../README.md)**, the stdio JSON-RPC proxy
that intercepts `tools/call` upstream, classifies the action, and only forwards
calls it has released. By the time a call reaches this server, the guard has
already authorized it, so each tool handler just executes its (simulated) side
effect: it appends a line to `outbox.log` to prove the action ran, then returns
a normal MCP tool result.

The `_pp` metadata field (e.g. `{ confidence }`) is the agent's self-report that
mcp-guard's classifier reads **upstream**. This server accepts and ignores it.

```
Charles (agent) ──tools/call──▶ mcp-guard (proxy) ──▶ actions-mcp (send_email | post_x | spend)
                                     │ intercept + classify + (block | hold | allow)
                                     ▼ outbox.log proves the side effect ran once released
```

## Run it standalone

No install needed — it is plain Node + ESM, zero runtime dependencies.

```bash
node server.mjs
```

It speaks JSON-RPC 2.0 over newline-delimited stdin/stdout. Implemented methods:
`initialize`, `notifications/initialized`, `tools/list`, `tools/call`, `ping`.

## Run it behind mcp-guard

```bash
# from the mcp-guard repo root, or with mcp-guard installed globally:
mcp-guard --config actions-mcp/pp.config.yaml -- node actions-mcp/server.mjs

# from inside this directory, against the sibling mcp-guard build:
node ../bin/mcp-guard --config pp.config.yaml --agent-id charles -- node server.mjs

# dry-run (log decisions + receipts, but still forward) — useful for the demo:
node ../bin/mcp-guard --config pp.config.yaml --mode observe -- node server.mjs

# with the human-approval UI (hold post_x, approve in the browser):
node ../bin/mcp-guard --config pp.config.yaml --approval-port 3100 -- node server.mjs
```

In a Claude Desktop / Cursor MCP config:

```json
{
  "mcpServers": {
    "actions": {
      "command": "mcp-guard",
      "args": ["--config", "actions-mcp/pp.config.yaml", "--agent-id", "charles", "--", "node", "actions-mcp/server.mjs"]
    }
  }
}
```

## Policy (`pp.config.yaml`)

The config is read by **mcp-guard**, not by this server. It carries two parts:

1. `rules:` — the policy surface the shipped mcp-guard enforces today
   (`require_approval` for all three tools; `default_action: block`).
2. `tools:` — the extended Slice-1 classifier schema from the build spec:
   `post_x` → `irreversible` (hard-block until signed receipt), `send_email` →
   `reversible` + `countdown_seconds: 300`, `spend` → `reversible` +
   `cap_usd: 50` + `verify_threshold: 70`.

## Verification transcript

### 1. Standalone — `tools/list` + `tools/call` over stdin

```text
$ printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"rod@example.com","subject":"Hello","body":"Hi there","_pp":{"confidence":42}}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"post_x","arguments":{"text":"shipping slice 1","_pp":{"confidence":91}}}}' \
  '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"spend","arguments":{"payee":"AWS","amount_usd":49,"memo":"hosting","_pp":{"confidence":60,"amount_usd":49}}}}' \
  '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"bogus","arguments":{}}}' \
  | node server.mjs

[actions-mcp] ready on stdio
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"actions-mcp","version":"0.1.0"}}}
{"jsonrpc":"2.0","id":2,"result":{"tools":[ /* send_email, post_x, spend with full inputSchema incl. _pp */ ]}}
{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"Email sent to rod@example.com with subject \"Hello\"."}],"isError":false}}
{"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"Posted to X: \"shipping slice 1\"."}],"isError":false}}
{"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text","text":"Spent $49 to AWS (hosting)."}],"isError":false}}
{"jsonrpc":"2.0","id":6,"error":{"code":-32602,"message":"Unknown tool: bogus"}}
```

Resulting `outbox.log` (proves the side effects executed):

```text
2026-06-13T06:42:48.541Z EMAIL SENT to=rod@example.com subject="Hello"
2026-06-13T06:42:48.542Z X POSTED text="shipping slice 1"
2026-06-13T06:42:48.542Z SPENT $49 to AWS memo="hosting"
```

### 2. Behind mcp-guard, enforce mode — irreversible `post_x` is held before execution

```text
$ printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{...}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"post_x","arguments":{"text":"should be blocked"}}}' \
  | node ../bin/mcp-guard --config pp.config.yaml --agent-id charles -- node server.mjs

{"jsonrpc":"2.0","id":2,"error":{"code":-32002,"message":"Held for approval: Matched rule \"hold-post-x\"; irreversible — hard stop until approved"}}
# outbox.log: No such file or directory  →  the call NEVER reached actions-mcp. No receipt, no execution.
```

### 3. Behind mcp-guard, observe mode — decision logged + receipt emitted, call still forwarded

```text
$ ... | node ../bin/mcp-guard --config pp.config.yaml --mode observe --agent-id charles -- node server.mjs

[mcp-guard] receipt: {"receipt_id":"rcpt_dg_...","status":"AWAITING_APPROVAL","action":"send_email",...}
[mcp-guard] OBSERVE: would hold "send_email" but forwarding (observe mode)
{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"Email sent to rod@example.com with subject \"Behind guard\"."}],"isError":false}}
# outbox.log: EMAIL SENT to=rod@example.com subject="Behind guard"  →  forwarded + executed in observe mode.
```

## Files

- `server.mjs` — the runnable MCP stdio server (no dependencies).
- `pp.config.yaml` — mcp-guard policy (base `rules:` + extended Slice-1 `tools:` schema).
- `package.json` — metadata + `actions-mcp` bin; `npm start` runs the server.
- `outbox.log` — append-only proof-of-execution log (created at runtime).
