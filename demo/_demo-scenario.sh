#!/bin/bash
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[1;31m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'
BG_RED='\033[41m'
BG_GREEN='\033[42m'
BLACK='\033[30m'

clear
echo ""

# ── BEFORE (red = danger) ──
echo -e "  ${BG_RED}${BLACK}${BOLD} ✖ WITHOUT MCP GUARD ${NC}"
echo ""
sleep 0.6
echo -e "  ${DIM}\$${NC} call ${BOLD}delete_user_data${NC}"
sleep 0.4
echo -e "  ${GREEN}✔ success${NC} — user data deleted"
echo ""
sleep 1.5

# ── DIVIDER ──
echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
sleep 0.4

# ── AFTER (green = safe) ──
echo -e "  ${BG_GREEN}${BLACK}${BOLD} ✔ WITH MCP GUARD ${NC}"
echo ""
sleep 0.6
echo -e "  ${DIM}\$${NC} call ${BOLD}delete_user_data${NC}"
sleep 0.4
echo -e "  ${RED}${BOLD}✖ BLOCKED${NC}"
echo -e "  ${DIM}rule: block-delete-user-data${NC}"
echo ""
sleep 0.5
echo -e "  ${DIM}{ \"decision\": \"blocked\" }${NC}"
echo ""
sleep 2.5
