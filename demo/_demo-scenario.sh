#!/bin/bash
set -euo pipefail

pause() { sleep "${1:-0.8}"; }

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

clear
echo ""
echo -e "${BOLD}${CYAN}  ┌──────────────────────────────────────────┐${NC}"
echo -e "${BOLD}${CYAN}  │         MCP Guard — Live Demo             │${NC}"
echo -e "${BOLD}${CYAN}  └──────────────────────────────────────────┘${NC}"
echo ""
pause 1.2

# === BEFORE ===
echo -e "${BOLD}${RED}  ▸ WITHOUT MCP Guard${NC}"
echo ""
pause 0.6
echo -e "  ${DIM}Agent calls:${NC} ${BOLD}delete_user_data${NC}${DIM}(user_id: \"usr_12345\")${NC}"
pause 0.4
echo -e "  ${GREEN}✓ Executed${NC} — user data deleted"
echo -e "  ${DIM}No log. No audit. No way to undo.${NC}"
echo ""
pause 1.5

echo -e "${DIM}  ─────────────────────────────────────────${NC}"
echo ""
pause 0.6

# === AFTER ===
echo -e "${BOLD}${GREEN}  ▸ WITH MCP Guard${NC}"
echo ""
pause 0.6

# Show config
echo -e "  ${DIM}$ cat pp.config.yaml${NC}"
pause 0.3
echo -e "  default_action: allow"
echo -e "  rules:"
echo -e "    - tool: send_email        → ${GREEN}allow${NC}"
echo -e "    - tool: delete_user_data  → ${RED}block${NC}"
echo -e "    - tool: deploy_production → ${YELLOW}require_approval${NC}"
echo ""
pause 1.5

# Tool calls
echo -e "  ${DIM}Agent calls:${NC} ${BOLD}send_email${NC}${DIM}(to: team@co.com)${NC}"
pause 0.4
echo -e "  ${GREEN}  ✓ ALLOWED${NC} — forwarded to server"
echo -e "  ${DIM}  → receipt logged${NC}"
echo ""
pause 0.8

echo -e "  ${DIM}Agent calls:${NC} ${BOLD}delete_user_data${NC}${DIM}(user_id: \"usr_12345\")${NC}"
pause 0.4
echo -e "  ${RED}  ✗ BLOCKED${NC} — rejected, user data safe"
echo -e "  ${DIM}  → receipt logged${NC}"
echo ""
pause 0.8

echo -e "  ${DIM}Agent calls:${NC} ${BOLD}deploy_production${NC}${DIM}(v2.1.0)${NC}"
pause 0.4
echo -e "  ${YELLOW}  ⏸ HELD${NC} — waiting for human approval"
echo -e "  ${DIM}  → receipt logged${NC}"
echo ""
pause 1.2

# Receipt
echo -e "  ${DIM}$ cat pp-receipts.jsonl | jq .decision${NC}"
echo -e "  ${GREEN}\"allowed\"${NC}    ${DIM}← send_email${NC}"
echo -e "  ${RED}\"blocked\"${NC}    ${DIM}← delete_user_data${NC}"
echo -e "  ${YELLOW}\"held\"${NC}       ${DIM}← deploy_production${NC}"
echo ""
pause 1.5

# Footer
echo -e "${BOLD}${CYAN}  ─────────────────────────────────────────${NC}"
echo -e "${BOLD}  3 rules. 0 code changes. Every action audited.${NC}"
echo -e "  ${DIM}github.com/permission-protocol/mcp-guard${NC}"
echo -e "${BOLD}${CYAN}  ─────────────────────────────────────────${NC}"
echo ""
pause 3
