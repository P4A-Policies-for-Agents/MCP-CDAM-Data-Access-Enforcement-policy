#!/usr/bin/env bash
# CDAM data access demo: the same tools/call as two IDMC users with different
# Data Marketplace usage contexts. Needs demo/env.local.sh (gitignored).
set -euo pipefail
cd "$(dirname "$0")"; source ./env.local.sh
TOOL="${TOOL:-sales-order-management-api_search_sales_orders}"
DEFAULT_ARGS='{"customer_id":"CUST-9001"}'
ARGS="${ARGS:-$DEFAULT_ARGS}"
token() {  # $1 = Keycloak user, $2 = password
  curl -sS "$KC_URL/realms/$KC_REALM/protocol/openid-connect/token" \
    -d grant_type=password -d client_id="$KC_CLIENT_ID" --data-urlencode client_secret="$KC_CLIENT_SECRET" \
    --data-urlencode username="$1" --data-urlencode password="$2" | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["access_token"])'
}
call() {  # $1 = label, $2 = token or "", $3 = declared usage context or ""
  echo "=== $1"
  local h=(-H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" -H "mcp-session-id: cdam-demo"
           -H "x-dp-clearance: restricted" -H "x-dp-purpose: fraud-detection")  # let the Entitlement Filter pass; CDAM decides
  [ -n "$2" ] && h+=(-H "Authorization: Bearer $2")
  [ -n "$3" ] && h+=(-H "x-usage-context: $3")
  curl -sS -D /tmp/cdam-demo.h -X POST "$CDAM_GW_URL" "${h[@]}" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$TOOL\",\"arguments\":$ARGS}}" | python3 -I "$(pwd)/show.py"
  grep -iE "^(HTTP|x-cdam)" /tmp/cdam-demo.h || true
}
BOB=$(token bob "$KC_BOB_PASSWORD"); GINA=$(token gina "$KC_GINA_PASSWORD")
call "no token" "" ""
call "Bob, Regulatory Reporting" "$BOB" "AK - Regulatory Reporting"
call "Gina, Analytics" "$GINA" "AK - Analytics"
call "Gina declaring Regulatory Reporting (not granted)" "$GINA" "AK - Regulatory Reporting"
