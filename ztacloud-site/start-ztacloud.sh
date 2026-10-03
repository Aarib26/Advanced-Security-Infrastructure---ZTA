#!/usr/bin/env bash
# ZTA Cloud Secondary Site — Startup Script
# Run this after boot to verify all services are up

echo "======================================"
echo " ZTA Cloud Secondary Site — Startup"
echo " $(date)"
echo "======================================"
echo ""

PASS=0; FAIL=0

check() {
    local name="$1"
    local cmd="$2"
    if eval "$cmd" &>/dev/null; then
        echo "  ✅  $name"
        PASS=$((PASS+1))
    else
        echo "  ❌  $name — STARTING..."
        FAIL=$((FAIL+1))
        eval "sudo systemctl start ${3:-}"
    fi
}

echo "[ Services ]"
check "Flask cloud-app (port 8080)" \
    "systemctl is-active --quiet zta-cloud-app" "zta-cloud-app"

check "Filebeat → ztauser ELK" \
    "systemctl is-active --quiet filebeat" "filebeat"

check "Suricata IDS" \
    "systemctl is-active --quiet suricata" "suricata"

check "PostgreSQL replica (WAL streaming)" \
    "systemctl is-active --quiet postgresql" "postgresql"

check "Tailscale mesh" \
    "tailscale status | grep -q ztauser" ""

echo ""
echo "[ Connectivity ]"

# Test Flask responds locally
if curl -sf http://localhost:8080 &>/dev/null; then
    echo "  ✅  Flask app responding on :8080"
else
    echo "  ❌  Flask app not responding"
fi

# Test Tailscale reach to ztauser
if ping -c 1 -W 3 100.96.17.20 &>/dev/null; then
    echo "  ✅  ztauser reachable over Tailscale (100.96.17.20)"
else
    echo "  ❌  ztauser unreachable — check Tailscale"
fi

# Test Logstash port
if nc -zw3 100.96.17.20 5044 &>/dev/null; then
    echo "  ✅  Logstash port 5044 reachable on ztauser"
else
    echo "  ❌  Cannot reach ztauser:5044 — ELK may be down"
fi

# Test PostgreSQL replica
RECOVERY=$(sudo -u postgres psql -h 127.0.0.1 -U keycloakpost26 -d keycloak -t \
    -c "SELECT pg_is_in_recovery();" 2>/dev/null | tr -d ' \n')
if [ "$RECOVERY" = "t" ]; then
    echo "  ✅  PostgreSQL in hot standby mode (WAL streaming active)"
else
    echo "  ❌  PostgreSQL NOT in standby — check replication"
fi

echo ""
echo "[ UFW Status ]"
sudo ufw status | grep -E "Status:|tailscale0" | head -4

echo ""
echo "======================================"
echo " Done: $PASS OK / $FAIL issues"
if [ $FAIL -eq 0 ]; then
    echo " All systems go. Site is ready."
else
    echo " $FAIL service(s) had issues — check above."
fi
echo "======================================"
