#!/bin/bash
source ../.env

TOKEN=$(curl -s -X POST http://127.0.0.1:8080/realms/master/protocol/openid-connect/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "username=${KEYCLOAK_ADMIN}" \
  -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
  -d 'grant_type=password' \
  -d 'client_id=admin-cli' | jq -r '.access_token')

echo "Token starts with: ${TOKEN:0:20}"

curl -s -X POST http://127.0.0.1:8080/admin/realms/zta/groups \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"engineers"}'

curl -s -X POST http://127.0.0.1:8080/admin/realms/zta/groups \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"admins"}'

ALICE_ID=$(curl -s "http://127.0.0.1:8080/admin/realms/zta/users?username=alice" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')

BOB_ID=$(curl -s "http://127.0.0.1:8080/admin/realms/zta/users?username=bob" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')

echo "Alice ID: $ALICE_ID"
echo "Bob ID: $BOB_ID"
