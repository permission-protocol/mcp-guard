#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== MCP Guard Demo ==="
echo ""
echo "Building..."
cd "$ROOT_DIR"
npm run build --silent 2>/dev/null

echo "Sending test requests through mcp-guard proxy..."
echo ""

# Create a temp file for responses
RESPONSES=$(mktemp)
RECEIPTS=$(mktemp)

# Send three tool calls through the proxy
{
  # 1. Initialize
  echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}'
  sleep 0.3

  # 2. Allowed: send_email
  echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"user@example.com","body":"Hello!"}}}'
  sleep 0.3

  # 3. Blocked: delete_user_data
  echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_user_data","arguments":{"user_id":"123"}}}'
  sleep 0.3

  # 4. Held: deploy_production
  echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"deploy_production","arguments":{"version":"1.0.0"}}}'
  sleep 0.3
} | node dist/src/cli.js --config example/pp.config.yaml --agent-id demo-agent -- node dist/example/server.js > "$RESPONSES" 2>"$RECEIPTS"

echo "--- Responses (stdout) ---"
cat "$RESPONSES" | while IFS= read -r line; do
  echo "$line" | python3 -m json.tool 2>/dev/null || echo "$line"
done

echo ""
echo "--- Receipts (stderr) ---"
grep "receipt:" "$RECEIPTS" | sed 's/\[mcp-guard\] receipt: //' | while IFS= read -r line; do
  echo "$line" | python3 -m json.tool 2>/dev/null || echo "$line"
done

echo ""
echo "--- Guard Log ---"
grep -v "receipt:" "$RECEIPTS" || true

rm -f "$RESPONSES" "$RECEIPTS"
echo ""
echo "=== Approval Flow ==="
echo ""
echo "To try the approval UI, run:"
echo "  node dist/src/cli.js --config example/pp.config.yaml --approval-port 3100 --agent-id demo-agent -- node dist/example/server.js"
echo ""
echo "Then open http://localhost:3100 and send a require_approval tool call."
echo "The proxy will hold the response until you approve or deny in the UI."
echo ""
echo "Done!"
