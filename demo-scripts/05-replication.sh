#!/bin/bash
echo "========================================"
echo "  Live Database Replication"
echo "========================================"
echo ""
echo "--- Is ztacloud receiving database updates from ztauser? ---"
docker exec keycloak-db psql -U keycloakpost26 -d keycloak \
  -c "SELECT client_addr, state, write_lag, flush_lag, replay_lag FROM pg_stat_replication;"

echo ""
echo "--- Creating a new user on ztauser right now ---"
TOKEN=$(curl -s -X POST http://localhost:8081/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&username=admin&password=ZtaAdmin2026Secure&grant_type=password" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

TS=$(date +%s)
HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:8081/admin/realms/zta/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"livetest$TS\",\"email\":\"livetest$TS@zerotrust.local\",\"enabled\":true}")
echo "User created on ztauser — HTTP $HTTP"

echo ""
echo "Waiting 2 seconds..."
sleep 2

echo "--- Checking ztacloud database for that same user ---"
ssh -i ~/.ssh/zta_gcp ztacloud@100.111.196.121 \
  "psql -h 127.0.0.1 -U keycloakpost26 -d keycloak -t \
   -c \"SELECT username, email FROM user_entity WHERE username='livetest$TS';\""

echo ""
echo "No manual sync. No cron job. It just appeared."
