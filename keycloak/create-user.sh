#!/bin/bash
source ../.env

TOKEN=$(curl -s -X POST http://127.0.0.1:8080/realms/master/protocol/openid-connect/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "username=${KEYCLOAK_ADMIN}" \
  -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
  -d 'grant_type=password' \
  -d 'client_id=admin-cli' | jq -r '.access_token')

echo 'Got token: '${TOKEN:0:30}'...'

# Create alice
curl -s -X POST http://127.0.0.1:8080/admin/realms/zta/users \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "alice",
    "email": "alice@zerotrust.local",
    "enabled": true,
    "firstName": "Alice",
    "lastName": "Engineer",
    "credentials": [{"type":"password","value":"Alice123!","temporary":false}]
  }'

# Create bob
curl -s -X POST http://127.0.0.1:8080/admin/realms/zta/users \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "bob",
    "email": "bob@zerotrust.local",
    "enabled": true,
    "firstName": "Bob",
    "lastName": "Admin",
    "credentials": [{"type":"password","value":"Bob123!","temporary":false}]
  }'

echo 'Users created.'
