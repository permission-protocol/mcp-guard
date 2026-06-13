# Infra-MCP — Permission Deck Slice 2

A minimal, **dependency-free** MCP stdio server that exposes exactly three tools
representing the **code / infra** action class:

| Tool | Args | Action class |
|------|------|--------------|
| `merge_pr` | `{ repo, pr_number, title?, scope_ref?, scope_sha?, _pp? }` | reversible (Decide, optional countdown) |
| `run_sql_migration` | `{ env, statement, _pp? }` | irreversible (hard stop) |
| `deploy` | `{ env, service, _pp? }` | reversible (Decide) |

It is the sibling of [`actions-mcp`](../actions-mcp/README.md) and follows the
exact same shape: a **normal MCP server** that does **no enforcement of its own**.
It is meant to run **behind [`mcp-guard`](../README.md)**, the stdio JSON-RPC
proxy that intercepts `tools/call` upstream, classifies the action (per the
reversibility rules in `pp.config.yaml`), and only forwards calls it has
released. By the time a call reaches this server, the guard has already
authorized it, so each tool handler just executes its (simulated) side effect:
it appends a line to `outbox.log` to prove the action ran, then returns a normal
MCP tool result.

The `_pp` metadata field (e.g. `{ confidence }`) is the agent's self-report that
mcp-guard's classifier reads **upstream**. This server accepts and ignores it.

```
Charles (agent) ──tools/call──▶ mcp-guard (proxy) ──▶ infra-mcp (merge_pr | run_sql_migration | deploy)
                                     │ intercept + classify + (block | hold | allow)
                                     ▼ outbox.log proves the side effect ran once released
```

`merge_pr` carries `scope_ref` / `scope_sha` so the upstream signer can bind a
Slice-2 receipt to that exact merge (`scope: github:merge`), per the slice spec.

## Run it standalone

No install needed — it is plain Node + ESM, zero runtime dependencies.

```bash
node infra-mcp/server.mjs
```

It speaks JSON-RPC 2.0 over newline-delimited stdin/stdout. Implemented methods:
`initialize`, `notifications/initialized`, `tools/list`, `tools/call`, `ping`.
Unknown methods return `-32601`; unknown tools return `-32602`.

## Run it behind mcp-guard

```bash
# from the mcp-guard repo root, with the human-approval UI on port 7700:
mcp-guard --config infra-mcp/pp.config.yaml --approval-port 7700 -- node infra-mcp/server.mjs

# from inside this directory, against the sibling mcp-guard build:
node ../bin/mcp-guard --config pp.config.yaml --agent-id charles -- node server.mjs

# dry-run (log decisions + receipts, but still forward) — useful for the demo:
node ../bin/mcp-guard --config pp.config.yaml --mode observe -- node server.mjs
```

In a Claude Desktop / Cursor MCP config:

```json
{
  "mcpServers": {
    "infra": {
      "command": "mcp-guard",
      "args": ["--config", "infra-mcp/pp.config.yaml", "--approval-port", "7700", "--", "node", "infra-mcp/server.mjs"]
    }
  }
}
```

## Policy (`pp.config.yaml`)

The config is read by **mcp-guard**, not by this server. It uses the Slice-1
**rules-based schema** where reversibility (and any countdown) live **on each
rule** (per slice spec §d):

- `merge_pr` → `require_approval`, `reversibility: reversible` (Decide; `countdown_seconds: 0` hard-hold by default).
- `run_sql_migration` → `require_approval`, `reversibility: irreversible` (HARD STOP, never auto-clears). **Uniform for Slice 2 — not env-conditional.**
- `deploy` → `require_approval`, `reversibility: reversible` (Decide).

`default_action: allow`, `mode: enforce`.

## Verification transcript

### Standalone — full handshake + a `tools/call` for each tool over stdin

```text
$ printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"merge_pr","arguments":{"repo":"pp/mcp-guard","pr_number":42,"title":"Slice 2 infra-mcp","scope_ref":"refs/pull/42/merge","scope_sha":"abc123","_pp":{"confidence":88}}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run_sql_migration","arguments":{"env":"production","statement":"ALTER TABLE receipts ADD COLUMN scope_sha text","_pp":{"confidence":70}}}}' \
  '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"deploy","arguments":{"env":"staging","service":"approval-server","_pp":{"confidence":95}}}}' \
  '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"bogus","arguments":{}}}' \
  '{"jsonrpc":"2.0","id":7,"method":"ping"}' \
  '{"jsonrpc":"2.0","id":8,"method":"frobnicate"}' \
  | node infra-mcp/server.mjs

[infra-mcp] ready on stdio
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"infra-mcp","version":"0.1.0"}}}
{"jsonrpc":"2.0","id":2,"result":{"tools":[ /* merge_pr, run_sql_migration, deploy with full inputSchema incl. _pp */ ]}}
{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"Merged PR #42 in pp/mcp-guard (\"Slice 2 infra-mcp\")."}],"isError":false}}
{"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"Ran SQL migration on production: ALTER TABLE receipts ADD COLUMN scope_sha text"}],"isError":false}}
{"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text","text":"Deployed approval-server to staging."}],"isError":false}}
{"jsonrpc":"2.0","id":6,"error":{"code":-32602,"message":"Unknown tool: bogus"}}
{"jsonrpc":"2.0","id":7,"result":{}}
{"jsonrpc":"2.0","id":8,"error":{"code":-32601,"message":"Method not found: frobnicate"}}
```

Resulting `outbox.log` (proves the three side effects executed):

```text
2026-06-13T07:10:41.271Z PR MERGED repo=pp/mcp-guard pr=42 title="Slice 2 infra-mcp" scope_sha=abc123
2026-06-13T07:10:41.272Z SQL MIGRATED env=production stmt="ALTER TABLE receipts ADD COLUMN scope_sha text"
2026-06-13T07:10:41.272Z DEPLOYED env=staging service=approval-server
```

## Files

- `server.mjs` — the runnable MCP stdio server (no dependencies).
- `pp.config.yaml` — mcp-guard policy (rules-based reversibility schema, Slice 2).
- `README.md` — this file.
- `outbox.log` — append-only proof-of-execution log (created at runtime).
