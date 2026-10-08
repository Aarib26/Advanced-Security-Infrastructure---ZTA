# 14-ansible-exec.sh
#!/bin/bash
echo "========================================"
echo "  DEMO 14: Ansible — Live Automated Response"
echo "========================================"
echo ""

ANSIBLE=/home/aak/oral_arch/python-scripts/ztaenv/bin/ansible-playbook
PLAYBOOK_DIR=~/oral_arch/ansible

echo "--- Available playbooks ---"
ls -1 $PLAYBOOK_DIR/

echo ""
echo "--- LIVE: block_ip_cilium.yml — blocking rogue IP ---"
ROGUE_IP="10.0.0.200"
$ANSIBLE $PLAYBOOK_DIR/block_ip_cilium.yml \
  -e "target_ip=$ROGUE_IP" \
  --connection=local 2>&1 | tail -20

echo ""
echo "--- Verify: Cilium block policy created ---"
kubectl get ciliumnetworkpolicy -A | grep "zta-block"

echo ""
echo "--- Response log entry written ---"
tail -3 ~/oral_arch/zta-response-actions.log

echo ""
echo "--- LIVE: revoke_keycloak_session.yml ---"
$ANSIBLE $PLAYBOOK_DIR/revoke_keycloak_session.yml \
  --connection=local 2>&1 | tail -15

echo ""
echo "--- Verify: revoked session no longer active in Keycloak ---"
TOKEN=$(curl -s -X POST http://localhost:8081/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&username=admin&password=ZtaAdmin2026Secure&grant_type=password" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s "http://localhost:8081/admin/realms/zta/sessions/stats" \
  -H "Authorization: Bearer $TOKEN" \
  | python3 -c "import sys,json; stats=json.load(sys.stdin); print('Active sessions:', stats)" \
  2>/dev/null || echo "  (sessions endpoint — check Keycloak admin UI)"

echo ""
echo "--- End-to-end: detect → alert → Ansible → block ---"
echo "  1. Suricata/ML flags anomalous IP"
echo "  2. zta-threat-hunter reads ELK, calls Ansible API"
echo "  3. block_ip_cilium.yml creates CiliumNetworkPolicy"
echo "  4. Pod-level drop enforced — no firewall rule needed"
echo "  5. Event logged to zta-response-actions.log"
echo ""
echo "--- Proof: full response chain in log ---"
tail -15 ~/oral_arch/zta-response-actions.log

echo ""
echo "========================================"
echo "  Ansible Automated Response: LIVE ✓"
echo "========================================"
