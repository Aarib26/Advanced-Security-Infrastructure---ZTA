#!/bin/bash
# ZTA Lab Bootstrap — rebuilds the full stack from a bare Ubuntu host.
# Usage: sudo bash bootstrap.sh [--dry-run] [--skip-packages] [--skip-k3s]
# Requires: SOPS_AGE_KEY_FILE set to your age private key path, OR .env already present
set -euo pipefail

LOG="/tmp/zta-bootstrap-$(date +%s).log"
exec > >(tee -a "$LOG") 2>&1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN=false; SKIP_PACKAGES=false; SKIP_K3S=false
for arg in "$@"; do
  case "$arg" in
    --dry-run)       DRY_RUN=true ;;
    --skip-packages) SKIP_PACKAGES=true ;;
    --skip-k3s)      SKIP_K3S=true ;;
  esac
done

step()  { echo ""; echo "=== [$(date +%T)] $1 ==="; }
ok()    { echo "  ✓ $1"; }
warn()  { echo "  ⚠ $1"; }
die()   { echo "  ✗ $1"; exit 1; }
run()   { $DRY_RUN && echo "  [DRY] $*" || eval "$@"; }

# ── 0. PREFLIGHT ──────────────────────────────────────────────────────────────
step "Preflight"
[[ $EUID -ne 0 ]] && die "Run with sudo"

if [[ ! -f "$SCRIPT_DIR/.env" ]]; then
  [[ -f "$SCRIPT_DIR/secrets.enc.env" ]] || die "No .env or secrets.enc.env found"
  [[ -z "${SOPS_AGE_KEY_FILE:-}" ]] && die "Set SOPS_AGE_KEY_FILE to your age private key path"
  run "age --decrypt --identity $SOPS_AGE_KEY_FILE --output $SCRIPT_DIR/.env $SCRIPT_DIR/secrets.enc.env"
  ok "Secrets decrypted"
fi
source "$SCRIPT_DIR/.env"
DEPLOY_USER="${SUDO_USER:-aak}"
DEPLOY_HOME=$(getent passwd "$DEPLOY_USER" | cut -d: -f6)
ok "Deploy user: $DEPLOY_USER ($DEPLOY_HOME)"
$DRY_RUN && ok "DRY RUN — no changes"

# ── 1. PACKAGES ───────────────────────────────────────────────────────────────
if ! $SKIP_PACKAGES; then
  step "Packages"
  run "apt-get update -qq"
  run "apt-get install -y --no-install-recommends \
    curl wget git jq python3 python3-pip python3-venv \
    suricata freeradius freeradius-rest \
    docker.io docker-compose-plugin \
    nftables iptables net-tools iproute2 age"
  # Filebeat
  if ! command -v filebeat &>/dev/null; then
    run "curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg"
    run "echo 'deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main' > /etc/apt/sources.list.d/elastic-8.x.list"
    run "apt-get update -qq && apt-get install -y filebeat"
  fi
  ok "Packages done"
fi

# ── 2. TAILSCALE ──────────────────────────────────────────────────────────────
step "Tailscale"
if ! command -v tailscale &>/dev/null; then
  run "curl -fsSL https://tailscale.com/install.sh | sh"
fi
TS_IP=$(tailscale ip -4 2>/dev/null || true)
if [[ -z "$TS_IP" ]]; then
  [[ -z "${TAILSCALE_AUTH_KEY:-}" ]] && warn "No TAILSCALE_AUTH_KEY — run: sudo tailscale up --hostname=ztauser" \
    || run "tailscale up --authkey=${TAILSCALE_AUTH_KEY} --hostname=ztauser"
else
  ok "Tailscale: $TS_IP"
fi

# ── 3. K3S ────────────────────────────────────────────────────────────────────
if ! $SKIP_K3S; then
  step "k3s"
  if ! command -v k3s &>/dev/null; then
    [[ -f "$SCRIPT_DIR/install-k3s.sh" ]] && run "bash $SCRIPT_DIR/install-k3s.sh" \
      || run "curl -sfL https://get.k3s.io | sh -"
  fi
  run "kubectl wait --for=condition=Ready node --all --timeout=300s"
  run "kubectl apply -f $SCRIPT_DIR/cilium/zta-cilium-consolidated.yaml"
  run "kubectl apply -f $SCRIPT_DIR/cilium/zta-cilium-demo.yaml"
  run "kubectl wait --for=condition=Ready pod --all -n zta-demo --timeout=180s || true"
  ok "k3s + Cilium done"
fi

# ── 4. OBSERVABILITY CONFIGS (dynamic — renders for this host) ────────────────
step "Observability render"
run "bash $SCRIPT_DIR/observability/detect-env.sh $SCRIPT_DIR/.env"
run "bash $SCRIPT_DIR/observability/render-configs.sh $SCRIPT_DIR/.env"
ok "Suricata + Zeek configs rendered"

# ── 5. DEPLOY CONFIGS TO /etc/ ────────────────────────────────────────────────
step "Deploy configs"
# Filebeat
run "cp $SCRIPT_DIR/filebeat/filebeat.yml /etc/filebeat/filebeat.yml"
# Caddy
run "cp $SCRIPT_DIR/caddy/Caddyfile /etc/caddy/Caddyfile"
# FreeRADIUS
run "cp $SCRIPT_DIR/freeradius/sites-enabled/default /etc/freeradius/3.0/sites-enabled/default"
run "cp $SCRIPT_DIR/freeradius/clients.conf /etc/freeradius/3.0/clients.conf"
# Render keycloak-nac with real secret from .env
run "bash $SCRIPT_DIR/nac/keycloak-federation/render_keycloak_module.sh"
# Zeek
run "cp $SCRIPT_DIR/zeek/node.cfg /opt/zeek/etc/node.cfg"
run "cp $SCRIPT_DIR/zeek/networks.cfg /opt/zeek/etc/networks.cfg"
run "cp $SCRIPT_DIR/zeek/zeekctl.cfg /opt/zeek/etc/zeekctl.cfg"
# Suricata
run "cp $SCRIPT_DIR/suricata/suricata/suricata.yaml /etc/suricata/suricata.yaml"
ok "Configs deployed"

# ── 6. SYSTEMD UNITS ─────────────────────────────────────────────────────────
step "Systemd units"
run "cp $SCRIPT_DIR/systemd/system/*.service /etc/systemd/system/"
run "cp $SCRIPT_DIR/systemd/system/*.timer   /etc/systemd/system/ 2>/dev/null || true"
run "cp -r $SCRIPT_DIR/systemd/service-dropins/suricata.service.d  /etc/systemd/system/"
run "cp -r $SCRIPT_DIR/systemd/service-dropins/freeradius.service.d /etc/systemd/system/"
run "systemctl daemon-reload"
ok "Units deployed"

# ── 7. PYTHON VENV ───────────────────────────────────────────────────────────
step "Python venv"
VENV="$SCRIPT_DIR/python-scripts/ztaenv"
if [[ ! -d "$VENV" ]]; then
  run "python3 -m venv $VENV"
  run "$VENV/bin/pip install --quiet ansible elasticsearch pandas scikit-learn numpy flask pyyaml requests"
fi
ok "Venv ready"

# ── 8. NAC QUARANTINE NETWORK ────────────────────────────────────────────────
step "NAC quarantine network"
run "bash $SCRIPT_DIR/nac/quarantine/setup_quarantine_net.sh"
ok "Quarantine bridge live"

# ── 9. TLS CERTS ─────────────────────────────────────────────────────────────
step "TLS certs"
if [[ ! -f /etc/caddy/certs/keycloak.crt ]]; then
  warn "TLS certs missing — regenerating self-signed for ${DOMAIN_NAME}"
  run "mkdir -p /etc/caddy/certs"
  run "openssl req -x509 -newkey rsa:4096 -days 825 -nodes \
    -keyout /etc/caddy/certs/keycloak.key \
    -out    /etc/caddy/certs/keycloak.crt \
    -subj '/CN=${DOMAIN_NAME:-ztauser}' \
    -addext 'subjectAltName=DNS:${DOMAIN_NAME:-ztauser}'"
  ok "Self-signed cert generated — distribute rootCA manually if needed"
else
  ok "Certs already present"
fi

# ── 10. DOCKER STACK (ordered: Keycloak → Pomerium → ELK) ────────────────────
step "Keycloak"
run "cd $SCRIPT_DIR/keycloak && docker compose --env-file ../.env up -d"
echo "  Waiting for Keycloak (up to 3 min)..."
for i in $(seq 1 36); do
  curl -sf http://127.0.0.1:8081/realms/master >/dev/null 2>&1 && break || sleep 5
done
ok "Keycloak up"

step "Pomerium"
run "cd $SCRIPT_DIR/pomerium && docker compose --env-file ../.env up -d"
ok "Pomerium up"

step "Elasticsearch"
run "cd $SCRIPT_DIR/elk && docker compose --env-file ../.env up -d elasticsearch"
echo "  Waiting for ES (up to 5 min)..."
for i in $(seq 1 60); do
  curl -sf -u "elastic:${ELASTIC_PASSWORD}" http://localhost:9200/_cluster/health >/dev/null 2>&1 && break || sleep 5
done
run "curl -sf -u elastic:${ELASTIC_PASSWORD} -X POST \
  http://localhost:9200/_security/user/kibana_system/_password \
  -H 'Content-Type: application/json' \
  -d '{\"password\":\"${KIBANA_PASSWORD}\"}'  "
ok "ES up + kibana_system password set"

step "Kibana + Logstash"
run "cd $SCRIPT_DIR/elk && docker compose --env-file ../.env up -d kibana"
echo "  Waiting for Kibana (up to 5 min)..."
for i in $(seq 1 60); do
  curl -sf http://localhost:5601/kibana/api/status 2>/dev/null | grep -q '"available"' && break || sleep 5
done
run "cd $SCRIPT_DIR/elk && docker compose --env-file ../.env up -d logstash"
ok "Kibana + Logstash up"

# ── 11. SYSTEMD SERVICES ─────────────────────────────────────────────────────
step "Start services"
run "systemctl restart caddy"
run "systemctl restart freeradius"
run "systemctl restart suricata"
run "systemctl restart filebeat"
run "bash $SCRIPT_DIR/zeek/fix-zeek-interfaces.sh"
run "systemctl restart zeek-frontend zeek-database zeek-attacker"
run "systemctl restart zta-posture-reverify.timer"
run "systemctl restart zta-threat-hunter.service"
ok "All services started"

# ── 12. KIBANA DASHBOARD RESTORE ─────────────────────────────────────────────
step "Kibana dashboard restore"
NDJSON=$(ls $SCRIPT_DIR/elk/kibana_backup_*.ndjson 2>/dev/null | sort | tail -1)
if [[ -n "$NDJSON" ]]; then
  run "curl -sf -u elastic:${ELASTIC_PASSWORD} \
    -X POST 'http://localhost:5601/kibana/api/saved_objects/_import?overwrite=true' \
    -H 'kbn-xsrf: true' \
    --form \"file=@${NDJSON}\""
  ok "Kibana dashboards imported from $(basename $NDJSON)"
else
  warn "No kibana_backup_*.ndjson found — import manually"
fi

# ── FINAL ─────────────────────────────────────────────────────────────────────
TOTAL=$(( $(date +%s) - $(stat -c %Y "$LOG" 2>/dev/null || date +%s) ))
echo ""
echo "==================== BOOTSTRAP COMPLETE ===================="
echo "Kibana:   https://${DOMAIN_NAME:-ztauser.tail65943a.ts.net}/kibana"
echo "Keycloak: https://${DOMAIN_NAME:-ztauser.tail65943a.ts.net}/admin"
echo "ZTA App:  https://${DOMAIN_NAME:-ztauser.tail65943a.ts.net}/zta-app"
echo "Log:      $LOG"
echo ""
echo "Quick validation:"
echo "  radtest alice Alice123! localhost 0 testing123"
echo "  curl -su elastic:\${ELASTIC_PASSWORD} http://localhost:9200/_cluster/health | python3 -m json.tool"
echo "  kubectl get pods -A"
echo "============================================================"
