#!/bin/bash
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

clear
echo ""
echo -e "  ${DIM}Without MCP Guard                    With MCP Guard${NC}"
echo -e "  ${DIM}─────────────────                    ──────────────${NC}"
echo ""
sleep 1

# LEFT SIDE - Without guard
echo -e "  ${DIM}\$${NC} call ${BOLD}delete_user_data${NC}"
sleep 0.5
echo -e "  ${GREEN}✔ success${NC} — user data deleted"
echo ""
sleep 1.2

# Divider
echo -e "  ${CYAN}▸ Enable MCP Guard...${NC}"
sleep 0.6
echo -e "  ${DIM}\$${NC} mcp-guard --config pp.config.yaml -- node server.js"
echo -e "  ${DIM}[mcp-guard] 3 rules loaded${NC}"
echo ""
sleep 0.8

# RIGHT SIDE - With guard
echo -e "  ${DIM}\$${NC} call ${BOLD}delete_user_data${NC}"
sleep 0.5
echo -e "  ${RED}✖ BLOCKED${NC} — rule: block-delete-user-data"
echo ""
sleep 1.2

# Receipt
echo -e "  ${DIM}\$${NC} tail -1 pp-receipts.jsonl"
echo -e "  ${DIM}{${NC}\"decision\":${RED}\"blocked\"${NC}, \"rule_id\":\"block-delete-user-data\"${DIM}}${NC}"
echo ""
sleep 2
