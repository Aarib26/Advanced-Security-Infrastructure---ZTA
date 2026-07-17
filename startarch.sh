#!/bin/bash
# ~/oral_arch/startarch.sh
# --- Zero Trust Identity & Access Stack (ZTA) ---
cd ~/oral_arch/keycloak
docker compose --env-file ../.env up -d --force-recreate
cd ~/oral_arch/pomerium
docker compose -f docker-compose.yml --env-file ../.env up -d --force-recreate

# --- Cilium Network Segment Hardening (L4-ONLY — confirmed working architecture) ---
# NOTE: L7 HTTP-method enforcement via Envoy is NOT applied at startup.
# Root cause: SYN correctly redirected to Envoy but connection goes silent,
# matches known upstream Cilium 1.18.x bugs. Deck/defense framing uses
# pure L4 CiliumNetworkPolicy as the validated, real architecture.
cd ~/oral_arch/cilium
kubectl apply -f zta-cilium-consolidated.yaml
#kubectl apply -f l7-backend-policy.yaml        # KNOWN BROKEN - do not enable, see notes above
#kubectl apply -f zta-network-policies.yaml
#kubectl apply -f zta-cilium-17-policy.yaml

# --- SOC SIEM Pipeline Layer (ELK) ---
cd ~/oral_arch/elk
docker compose --env-file ../.env up -d --force-recreate
sleep 15
docker compose --env-file ../.env up -d

# --- Network Security Monitoring Core (Zeek Engine) ---
# fix-zeek-interfaces.sh handles interface drift (eBPF/Cilium routing means
# per-pod veth visibility shifts — attacker pod egress iface carries the bulk
# of traffic vs frontend pod's own veth). Self-healing as of July 14 fix.
~/oral_arch/fix-zeek-interfaces.sh

# --- NAC / EAP-TLS Layer (FreeRADIUS) ---
# Real cross-host EAP-TLS (LabUbuntu2 <-> RoadmapLabs) proven July 15, 2026.
# PAP auth (laptop-alice-001, byod-roadmaplabs) still active in parallel.
sudo systemctl restart freeradius
sudo systemctl status freeradius --no-pager | head -5

# --- Active Defensive Hunting Engines ---
# zeek_anomaly_detector.service = Isolation Forest ML engine, reads
#   /opt/zeek/spool/zeek-attacker/conn.log (JSON format, not TSV)
# zta-threat-hunter.service     = queries ES every 5 min, triggers
#   Ansible block_ip_cilium.yml on ML:1 anomalies (5-min lookback window)
sudo systemctl restart zeek_anomaly_detector
sudo systemctl restart zta-threat-hunter

# --- Quick Cluster Inspection Diagnostics ---
echo "=== Current Operational Status Overview ==="
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
sudo /opt/zeek/bin/zeekctl status
systemctl is-active zeek_anomaly_detector zta-threat-hunter freeradius
