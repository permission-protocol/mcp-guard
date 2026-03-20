# MCP Guard Example

Run this demo in 2 minutes.

## Prerequisites

- Node.js 20+
- npm

## Steps

```bash
# 1. Install dependencies
cd /path/to/mcp-guard
npm install

# 2. Build
npm run build

# 3. Run the demo
bash example/test.sh
```

## What happens

The demo sends three `tools/call` requests through `mcp-guard`:

| Tool | Config Rule | Result |
|------|-----------|--------|
| `send_email` | allow | ✅ Forwarded to server, response returned |
| `delete_user_data` | block | 🚫 Blocked, JSON-RPC error returned |
| `deploy_production` | require_approval | ⏸️ Held, JSON-RPC error returned |

Each decision generates a receipt written to stderr and `pp-receipts.jsonl`.

## Config

See `pp.config.yaml` for the policy rules used in this demo.
