#!/bin/bash
# ZTA State Backup — captures everything that can't be reconstructed from git
# Run before: risky changes, VM snapshots, shutdowns
# Output: ~/zta-backups/TIMESTAMP/

set -euo pipefail
STAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="$HOME/zta-backups/$STAMP"
mkdir -p "$BACKUP_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.env"

echo "=== ZTA Backup: $STAMP ==="
echo "Output: $BACKUP_DIR"

# ── 1. Keycloak realm + users export ─────────────────────────────────────────
echo ""
echo "=== Keycloak export ==="
TOKEN=$(curl -s -X POST "http://127.0.0.1:8081/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${KC_BOOTSTRAP_ADMIN_USERNAME}&password=${KC_BOOTSTRAP_ADMIN_PASSWORD}&grant_type=password&client_id=admin-cli" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -X POST \
  "http://127.0.0.1:8081/admin/realms/zta/partial-export?exportClients=true&exportGroupsAndRoles=true" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  | python3 -m json.tool > "$BACKUP_DIR/keycloak-zta-realm.json"
echo "  ✓ Realm exported ($(wc -l < "$BACKUP_DIR/keycloak-zta-realm.json") lines)"

curl -s "http://127.0.0.1:8081/admin/realms/zta/users?max=200" \
  -H "Authorization: Bearer $TOKEN" \
  | python3 -m json.tool > "$BACKUP_DIR/keycloak-zta-users.json"
echo "  ✓ Users exported ($(python3 -c "import json; print(len(json.load(open('$BACKUP_DIR/keycloak-zta-users.json'))))" ) users)"

curl -s "http://127.0.0.1:8081/admin/realms/zta/groups?max=200" \
  -H "Authorization: Bearer $TOKEN" \
  | python3 -m json.tool > "$BACKUP_DIR/keycloak-zta-groups.json"
echo "  ✓ Groups exported"

# ── 2. Kibana dashboard export ────────────────────────────────────────────────
echo ""
echo "=== Kibana export ==="
NDJSON="$BACKUP_DIR/kibana-dashboards.ndjson"
HTTP_STATUS=$(curl -s -o "$NDJSON" -w "%{http_code}" \
  -u "elastic:${ELASTIC_PASSWORD}" \
  -X POST "http://localhost:5601/kibana/api/saved_objects/_export" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{"type":["dashboard","visualization","index-pattern","lens","search"],"excludeExportDetails":true}' \
  2>/dev/null) || HTTP_STATUS="failed"

if [[ "$HTTP_STATUS" == "200" ]]; then
  echo "  ✓ Kibana objects exported ($(wc -l < "$NDJSON") objects)"
else
  echo "  ⚠ Kibana export failed (status: $HTTP_STATUS) — skipping"
fi

# ── 3. Response actions log ───────────────────────────────────────────────────
echo ""
echo "=== Response log ==="
cp "$SCRIPT_DIR/zta-response-actions.log" "$BACKUP_DIR/" 2>/dev/null \
  && echo "  ✓ zta-response-actions.log copied" \
  || echo "  ⚠ No response log found — skipping"

# ── 4. Sync exports back to oral_arch for git ────────────────────────────────
echo ""
echo "=== Syncing to oral_arch for git ==="
cp "$BACKUP_DIR/keycloak-zta-realm.json"  "$SCRIPT_DIR/keycloak/zta-realm-export.json"
cp "$BACKUP_DIR/keycloak-zta-users.json"  "$SCRIPT_DIR/keycloak/zta-users-export.json"
cp "$BACKUP_DIR/keycloak-zta-groups.json" "$SCRIPT_DIR/keycloak/zta-groups-export.json"
[[ -f "$NDJSON" ]] && cp "$NDJSON" "$SCRIPT_DIR/elk/kibana_backup_${STAMP}.ndjson"
echo "  ✓ Exports copied to oral_arch"

echo ""
echo "=================== BACKUP COMPLETE ==================="
echo "Local backup:  $BACKUP_DIR"
echo "Git-ready:     commit keycloak/ and elk/ in oral_arch"
echo "======================================================="
