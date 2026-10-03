#!/bin/bash
# zta_snapshot.sh — full lab context dump for AI tools
# Updated: Oct 2026 — includes hybrid cloud, ztacloud DR site, PostgreSQL replica, failover

SEP() { echo; echo "════════════════════════════════════════════════════════"; echo "  $*"; echo "════════════════════════════════════════════════════════"; }
H() { echo; echo "──── $* ────"; }
CATFILE() { echo; H "$1"; cat "$1" 2>/dev/null || echo "NOT FOUND: $1"; }

SEP "SYSTEM"
echo "Date     : $(date)"
echo "Host     : $(hostname) / $(hostname -I | tr ' ' '\n' | grep -v '^$' | head -5 | tr '\n' ' ')"
echo "OS       : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')"
echo "Kernel   : $(uname -r)"
echo "Uptime   : $(uptime -p)"
echo "User     : $(whoami)"

SEP "TAILSCALE — MESH STATUS"
tailscale status
echo ""
echo "ztauser IP  : $(tailscale ip --4 2>/dev/null || echo 'unknown')"
echo "ztacloud IP : 100.111.196.121 (static)"

SEP "DOCKER CONTAINERS"
docker ps --format "table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.Names}}"

SEP "KUBERNETES — PODS (all namespaces)"
kubectl get po --all-namespaces -o wide

SEP "KUBERNETES — SERVICES (all namespaces)"
kubectl get svc --all-namespaces

SEP "KUBERNETES — DEPLOYMENTS (all namespaces)"
kubectl get deploy --all-namespaces

SEP "KUBERNETES — CONFIGMAPS (zta-demo)"
kubectl get cm -n zta-demo

SEP "KUBERNETES — FULL RESOURCE DUMP (all namespaces)"
kubectl get all --all-namespaces

SEP "CILIUM — NETWORK POLICIES"
kubectl get ciliumnetworkpolicy --all-namespaces

SEP "CILIUM — ENDPOINTS"
kubectl get ciliumendpoints --all-namespaces

SEP "CILIUM — IDENTITY LIST (top 60 lines)"
kubectl exec -n kube-system $(kubectl get pods -n kube-system -l k8s-app=cilium -o jsonpath='{.items[0].metadata.name}') \
  -- cilium-dbg identity list 2>/dev/null | head -60 || echo "(skipped)"

SEP "PROJECT TREE — ~/oral_arch (L6)"
tree -L 6 ~/oral_arch 2>/dev/null || find ~/oral_arch -maxdepth 6 | sort

SEP "STARTUP SCRIPTS"
CATFILE ~/oral_arch/startup.sh
CATFILE ~/oral_arch/startupsequence.sh
CATFILE ~/oral_arch/afk_startup.sh
CATFILE ~/oral_arch/pers_start.sh
CATFILE ~/oral_arch/v2_pers_start.sh
CATFILE ~/oral_arch/updated_startup.sh
CATFILE ~/oral_arch/elkfix_startup.sh
CATFILE ~/oral_arch/no_zeek_startup.sh

SEP "SWEEP / RESPONSE SCRIPTS"
CATFILE ~/oral_arch/attacker_sweep.sh
CATFILE ~/oral_arch/lateral_sweep.sh
CATFILE ~/oral_arch/zta-response-actions.log

SEP "ZTA IDENTITY APP"
CATFILE ~/oral_arch/zta-identity-app/app.py
CATFILE ~/oral_arch/zta-identity-app/Dockerfile

SEP "POMERIUM"
CATFILE ~/oral_arch/pomerium/config.yaml
CATFILE ~/oral_arch/pomerium/docker-compose.yml
CATFILE ~/oral_arch/pomerium/demo-app/html/index.html

SEP "CADDY — CADDYFILE (live)"
cat /etc/caddy/Caddyfile 2>/dev/null || CATFILE ~/oral_arch/caddy/Caddyfile

SEP "ELK"
CATFILE ~/oral_arch/elk/docker-compose.yml
CATFILE ~/oral_arch/elk/logstash/pipeline/zta.conf

SEP "FILEBEAT — ZTAUSER"
CATFILE ~/oral_arch/filebeat/filebeat.yml

SEP "KEYCLOAK"
CATFILE ~/oral_arch/keycloak/docker-compose.yml
CATFILE ~/oral_arch/keycloak/create-groups.sh
CATFILE ~/oral_arch/keycloak/create-user.sh

SEP "FREERADIUS"
CATFILE ~/oral_arch/freeradius/clients.conf
CATFILE ~/oral_arch/freeradius/sites-enabled/default
CATFILE ~/oral_arch/freeradius/mods-available/keycloak-nac

SEP "CILIUM POLICIES"
CATFILE ~/oral_arch/cilium/zta-cilium-consolidated.yaml
CATFILE ~/oral_arch/cilium/zta-cilium-demo.yaml

SEP "SURICATA CONFIG (first 80 lines)"
head -80 ~/oral_arch/suricata/suricata/suricata.yaml 2>/dev/null || echo "NOT FOUND"

SEP "ZEEK"
CATFILE ~/oral_arch/zeek/node.cfg
CATFILE ~/oral_arch/zeek/zeekctl.cfg
CATFILE ~/oral_arch/zeek/networks.cfg
CATFILE ~/oral_arch/zeek/zeek/zeek.conf

SEP "OBSERVABILITY"
CATFILE ~/oral_arch/observability/detect-env.sh
CATFILE ~/oral_arch/observability/render-configs.sh

SEP "NAC"
CATFILE ~/oral_arch/nac/device_onboard.py
CATFILE ~/oral_arch/nac/quarantine/quarantine.env
CATFILE ~/oral_arch/nac/quarantine/reverify_posture.sh
CATFILE ~/oral_arch/nac/quarantine/setup_quarantine_net.sh
CATFILE ~/oral_arch/nac/quarantine/release_from_quarantine.sh
CATFILE ~/oral_arch/nac/quarantine/vlan_assign_hook.sh
CATFILE ~/oral_arch/nac/quarantine/systemd/zta-posture-reverify.service

SEP "ANSIBLE PLAYBOOKS"
ls -lh ~/oral_arch/ansible/
for f in ~/oral_arch/ansible/*.yml; do CATFILE "$f"; done
CATFILE ~/oral_arch/ansible/inventory.ini

SEP "PYTHON SCRIPTS (first 80 lines each)"
H "zeek_anomaly_detector.py"
head -80 ~/oral_arch/python-scripts/ml/zeek_anomaly_detector.py 2>/dev/null || echo "NOT FOUND"
H "threat_hunter.py"
head -80 ~/oral_arch/python-scripts/threat_hunter.py 2>/dev/null || echo "NOT FOUND"

# ─── HYBRID CLOUD / ZTACLOUD SECTION ────────────────────────────────────────

SEP "HYBRID CLOUD — ZTACLOUD DR SITE"
echo "ztacloud Tailscale IP : 100.111.196.121"
echo "Role                  : DR secondary — hot standby, workload site"
echo ""

H "Pomerium /cloud-app route (live config)"
grep -A 10 "cloud-app" ~/oral_arch/pomerium/config.yaml 2>/dev/null || echo "NOT FOUND"

H "Caddyfile /cloud-app entry (live)"
grep -A 8 "cloud-app" /etc/caddy/Caddyfile 2>/dev/null || echo "NOT FOUND"

SEP "HYBRID CLOUD — FAILOVER SCRIPT"
CATFILE ~/oral_arch/scripts/failover-identity.sh

SEP "HYBRID CLOUD — ZTACLOUD SITE FILES (in repo)"
echo ""
find ~/git_oral_arch/Advanced-Security-Infrastructure---ZTA/ztacloud-site \
  -type f 2>/dev/null | sort || echo "ztacloud-site dir not found in repo"

H "Flask cloud-app (ztacloud)"
cat ~/git_oral_arch/Advanced-Security-Infrastructure---ZTA/ztacloud-site/flask/app.py \
  2>/dev/null || echo "NOT FOUND in repo"

H "Filebeat config (ztacloud)"
cat ~/git_oral_arch/Advanced-Security-Infrastructure---ZTA/ztacloud-site/filebeat/filebeat-ztacloud.yml \
  2>/dev/null || echo "NOT FOUND in repo"

H "zta-cloud-app.service"
cat ~/git_oral_arch/Advanced-Security-Infrastructure---ZTA/ztacloud-site/systemd/zta-cloud-app.service \
  2>/dev/null || echo "NOT FOUND in repo"

H "zta-keycloak-standby.service"
cat ~/git_oral_arch/Advanced-Security-Infrastructure---ZTA/ztacloud-site/systemd/zta-keycloak-standby.service \
  2>/dev/null || echo "NOT FOUND in repo"

SEP "POSTGRESQL — REPLICATION STATUS"
H "Primary (ztauser) — pg_stat_replication"
docker exec keycloak-db psql -U keycloakpost26 -d keycloak \
  -c "SELECT client_addr, state, write_lag, flush_lag, replay_lag FROM pg_stat_replication;" \
  2>/dev/null || echo "(keycloak-db not running)"

H "Primary — WAL settings"
docker exec keycloak-db psql -U keycloakpost26 -d keycloak \
  -c "SHOW wal_level; SHOW max_wal_senders;" 2>/dev/null || echo "(not accessible)"

H "pg_hba.conf — replication entry"
docker exec keycloak-db bash -c "grep replicator /var/lib/postgresql/data/pg_hba.conf" \
  2>/dev/null || echo "(not accessible)"

SEP "ELK — INDEX SUMMARY"
H "All ZTA indices"
curl -su elastic:ztaelk26 "http://localhost:9200/_cat/indices?v&s=index" 2>/dev/null \
  | grep zta || echo "(ES not reachable or auth failed)"

H "ztacloud events count"
curl -su elastic:ztaelk26 "http://localhost:9200/zta-logs-*/_count" \
  -H "Content-Type: application/json" \
  -d '{"query":{"term":{"fields.deployment_site":"ztacloud"}}}' 2>/dev/null \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('ztacloud events:', d.get('count','ERR'))" \
  2>/dev/null || echo "(query failed)"

H "Total alert count"
curl -su elastic:ztaelk26 "http://localhost:9200/zta-alerts-*/_count" 2>/dev/null \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('total alerts:', d.get('count','ERR'))" \
  2>/dev/null || echo "(query failed)"

H "ML anomaly count"
curl -su elastic:ztaelk26 "http://localhost:9200/zta-ml-anomalies-*/_count" 2>/dev/null \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('ML anomalies:', d.get('count','ERR'))" \
  2>/dev/null || echo "(query failed)"

SEP "SYSTEMD — ZTA SERVICES (ztauser)"
for svc in zeek-frontend zeek-database zeek-attacker suricata filebeat freeradius \
           zta-threat-hunter zeek_anomaly_detector zta-posture-reverify; do
  H "systemctl status $svc"
  systemctl status "$svc" --no-pager -l 2>/dev/null | head -10 || echo "(not found)"
done

SEP "ZEEK — zeekctl status"
sudo /opt/zeek/bin/zeekctl status 2>/dev/null || echo "(not accessible)"

SEP "ZEEK — log dirs"
for d in /opt/zeek/logs/frontend /opt/zeek/logs/database /opt/zeek/logs/attacker /opt/zeek/logs/current; do
  H "$d"; ls -lht "$d" 2>/dev/null | head -10 || echo "(missing)"
done

SEP "SURICATA — recent alerts (last 20 lines, ztauser)"
sudo tail -20 /var/log/suricata/eve.json 2>/dev/null || echo "NOT FOUND"

SEP "ELASTICSEARCH — cluster health"
curl -su elastic:ztaelk26 http://localhost:9200/_cluster/health?pretty 2>/dev/null \
  || echo "(not reachable)"

SEP "UFW — ztauser firewall"
sudo ufw status verbose 2>/dev/null || echo "(ufw not accessible)"

SEP "NETWORK — interfaces"
ip -brief addr

SEP "NETWORK — routes"
ip route

SEP "NETWORK — listening ports"
ss -tlnp | sort

SEP "NETWORK — Docker networks"
docker network ls

SEP "K8S EVENTS — warnings"
kubectl get events --all-namespaces --field-selector type=Warning \
  --sort-by='.lastTimestamp' 2>/dev/null | tail -30

SEP "GIT — REPO STATUS"
cd ~/git_oral_arch/Advanced-Security-Infrastructure---ZTA 2>/dev/null && \
  git log --oneline -5 && echo "" && git status --short || echo "(git repo not found)"

SEP "END OF SNAPSHOT"
echo "Generated: $(date)"
echo "ztauser snapshot complete. For ztacloud status, run: bash ~/start-ztacloud.sh"
