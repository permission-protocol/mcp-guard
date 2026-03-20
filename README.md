# MCP Guard

**MCP Guard blocks dangerous AI agent actions using a simple YAML config file.**

A lightweight stdio proxy that sits between an MCP client and server, intercepting `tools/call` requests and enforcing policy rules. Every decision is logged as an immutable receipt.

## Quick Start

```bash
# 1. Install
npm install @permissionprotocol/mcp-guard

# 2. Create a policy file (pp.config.yaml)
cat > pp.config.yaml << 'EOF'
default_action: allow
rules:
  - id: block-dangerous-delete
    tool: delete_user_data
    action: block
  - id: hold-production-deploy
    tool: deploy_production
    action: require_approval
EOF

# 3. Run your MCP server through the guard
mcp-guard --config pp.config.yaml -- node my-mcp-server.js

# 4. Point your MCP client at mcp-guard instead of the server directly
# 5. Check pp-receipts.jsonl for audit trail
```

## Architecture

```
┌────────────┐     stdio      ┌─────────────┐     stdio      ┌────────────┐
│  MCP Client│ ──────────────▶│  MCP Guard   │──────────────▶ │ MCP Server │
│  (Claude,  │                │  (proxy)     │                │ (your app) │
│   Cursor)  │ ◀──────────────│              │◀────────────── │            │
└────────────┘   responses    └─────────────┘   responses    └────────────┘
                                    │
                                    ▼
                              pp-receipts.jsonl
                              (audit trail)
```

MCP Guard intercepts JSON-RPC messages on stdin/stdout. When it sees a `tools/call` request:

1. Looks up the tool name in the config rules
2. If **allowed** → forwards to the real server
3. If **blocked** → returns a JSON-RPC error (`-32001`) directly
4. If **held for approval** → returns a JSON-RPC error (`-32002`) directly
5. Emits a receipt for every decision (stderr + jsonl file)

All other JSON-RPC methods pass through transparently.

## Config Reference

```yaml
# pp.config.yaml
default_action: allow  # "allow" or "block" — applies when no rule matches

rules:
  - id: unique-rule-id        # Human-readable identifier
    tool: tool_name            # Exact match on MCP tool name
    action: allow              # allow | block | require_approval
```

### Actions

| Action | Behavior | JSON-RPC Error Code |
|--------|----------|-------------------|
| `allow` | Forward request to server | — |
| `block` | Reject immediately | `-32001` |
| `require_approval` | Reject with hold status | `-32002` |

## Receipts

Every `tools/call` decision generates an immutable receipt:

```json
{
  "receipt_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-03-20T15:30:00.000Z",
  "agent_id": "my-agent",
  "tool_name": "delete_user_data",
  "decision": "blocked",
  "reason": "Matched rule \"block-dangerous-delete\"",
  "rule_id": "block-dangerous-delete",
  "request_payload_hash": "sha256-hex-string"
}
```

Receipts are written to:
- **stderr** — for real-time monitoring
- **pp-receipts.jsonl** — append-only audit file

The `request_payload_hash` is a SHA-256 of the full request params, so you can verify what was sent without storing sensitive arguments.

## CLI

```
mcp-guard [options] -- <server command>

Options:
  --config <path>     Path to config file (default: ./pp.config.yaml)
  --agent-id <id>     Agent identifier for receipts (default: "unknown")
  -h, --help          Show help
```

### Example: Claude Desktop

In your Claude Desktop MCP config, replace:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "node",
      "args": ["my-mcp-server.js"]
    }
  }
}
```

With:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "mcp-guard",
      "args": ["--config", "pp.config.yaml", "--agent-id", "claude-desktop", "--", "node", "my-mcp-server.js"]
    }
  }
}
```

## What This Is NOT

- **Not a dashboard.** It's a proxy. It sits in the data path and enforces rules.
- **Not a scanner.** It doesn't analyze your code or model outputs. It gates tool calls.
- **Not compliance theater.** Every decision has a cryptographic receipt. No hand-waving.
- **Not a replacement for good architecture.** It's one layer in a defense-in-depth strategy.

## Try the Demo

```bash
git clone https://github.com/permission-protocol/mcp-guard
cd mcp-guard
npm install && npm run build
bash example/test.sh
```

See [example/README.md](example/README.md) for details.

## Part of Permission Protocol

MCP Guard is a building block of the [Permission Protocol](https://github.com/permission-protocol) governance framework — explicit authority for autonomous AI systems.

## License

MIT
