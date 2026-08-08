#!/bin/bash
source ../.env
curl -s ${KEYCLOAK_URL}/realms/zta/.well-known/openid-configuration | python3 -m json.tool
