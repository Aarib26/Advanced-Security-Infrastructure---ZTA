<div align="center">

# 🛡️ Advanced Security Infrastructure — Zero Trust Architecture

**A self-built Zero Trust lab spanning identity, network microsegmentation, NAC, IDS/NSM, ML-based anomaly detection, and centralized SIEM — deployed and debugged end-to-end on a home lab with a live cloud extension node.**

[![Zero Trust](https://img.shields.io/badge/Architecture-Zero%20Trust-black?style=flat-square)](#)
[![Cilium](https://img.shields.io/badge/eBPF-Cilium%20v1.19.5-orange?style=flat-square)](#)
[![Keycloak](https://img.shields.io/badge/Identity-Keycloak%2026.6.2%20OIDC-blue?style=flat-square)](#)
[![Pomerium](https://img.shields.io/badge/ZTNA-Pomerium%20v0.32.3-green?style=flat-square)](#)
[![ELK](https://img.shields.io/badge/SIEM-ELK%208.11.0-005571?style=flat-square)](#)
[![Ansible](https://img.shields.io/badge/SOAR-Ansible-red?style=flat-square)](#)
[![Suricata](https://img.shields.io/badge/IDS-Suricata%208.0.4-yellow?style=flat-square)](#)

</div>

---

## 📌 What This Is

This repo is the working configuration for a **Zero Trust Architecture lab** built from first principles — not a tutorial clone, not a single `docker-compose up` demo. It's the actual identity, network, NAC, detection, and automation layer built, broken, root-caused, and fixed while learning how a real Zero Trust stack fits together.

Every component here was deployed on a real Ubuntu lab machine (`ztauser`) over Tailscale WireGuard, with actual traffic flowing through it — Keycloak 26.6.2 issuing OIDC tokens, Pomerium v0.32.3 enforcing per-request policy, Cilium v1.19.5 dropping packets at the eBPF layer with 9 active CNPs, Suricata 8.0.4 and Zeek watching four pod-pinned lxc interfaces, and Python scripts scoring device posture and flagging anomalies in real time via a trained Isolation Forest model. A live cloud extension node (`ztacloud-site/`) joins the same Tailscale mesh and ships its own logs into the central ELK stack.

> **Design philosophy:** default-deny everywhere, verify explicitly at every layer, never trust network location as a substitute for identity.

---

## 🗺️ Architecture Diagrams

### System Architecture
![System Architecture](<System_Arch.drawio.png>)

### Network Topology
![Network Topology](<Network Topology Diagram.drawio.png>)

### Data Flow Diagram (DFD — Level 0 + Level 1)
![Data Flow Diagram](<DFD.drawio.png>)

### Security Architecture — Trust Boundaries
![Security Architecture Trust Boundaries](<Security Architecture (Trust Boundaries).drawio.png>)

### Hybrid Cloud Architecture — Provider-Agnostic Design
![Hybrid Cloud Architecture](<Hybrid Cloud Architecture.drawio.png>)

### Process Flow — Automated Threat Response (SOAR)
![SOAR Process Flow](<Process Flow_ Full Threat Response Workflow.drawio.png>)

---

## 🏗️ Architecture Overview

```
                            ┌─────────────────────┐
                            │   Caddy (TLS edge)   │
                            │  reverse proxy + TLS  │
                            └──────────┬───────────┘
                                       │
                 ┌─────────────────────┼─────────────────────┐
                 ▼                     ▼                     ▼
        ┌────────────────┐   ┌─────────────────┐   ┌──────────────────┐
        │  Keycloak 26.6 │   │  Pomerium v0.32 │   │  Kibana / ELK     │
        │  OIDC IdP      │──▶│  ZTNA Proxy     │   │  SIEM Dashboard   │
        │  realm=zta     │   │  :8444          │   │  :5601            │
        └────────────────┘   └────────┬─────────┘   └──────────────────┘
                                       │ allow/deny per-request (JWT TTL=15min)
                                       ▼
                          ┌─────────────────────────────┐
                          │   Cilium v1.19.5 (eBPF)     │
                          │   k3s · zta-demo namespace  │
                          │   9 CNPs · default-deny-all │
                          └────────────┬────────────────┘
                                       │
                 ┌─────────────────────┼─────────────────────┐
                 ▼                     ▼                     ▼
        ┌────────────────┐   ┌─────────────────┐   ┌──────────────────┐
        │  FreeRADIUS    │   │ Suricata 8.0.4  │   │  Zeek (4 sensors)│
        │  802.1X NAC    │   │ 52,151 ET rules │   │  per-pod lxc veth│
        │  VLAN hook     │   │ NF_PACKET mode  │   │  conn/dns/http/  │
        └────────────────┘   └─────────────────┘   │  notice/weird    │
                                                     └──────────────────┘
                                       │
                                       ▼
                    ┌──────────────────────────────────────┐
                    │   Isolation Forest ML                 │
                    │   zeek_anomaly_detector.py            │
                    │   zta_iforest_model.pkl               │
                    │   reads conn.log every 60s            │
                    └──────────────┬───────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────────────┐
                    │   threat_hunter.py (ztaenv)           │
                    │   + lateral_sweep.sh                  │
                    │   queries ES every 30s                │
                    └──────────────┬───────────────────────┘
                                   │ match → Ansible SOAR
                                   ▼
                    ┌──────────────────────────────────────┐
                    │   Ansible Playbooks (4)               │
                    │   block_ip_cilium.yml                 │
                    │   isolate_workload.yml                │
                    │   revoke_keycloak_session.yml         │
                    │   release_ip_cilium.yml               │
                    └──────────────────────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────────────┐
                    │   Logstash 8.11.0 → Elasticsearch    │
                    │   490K+ indexed events                │
                    │   Indexes: zta-logs-* zta-alerts-*   │
                    │   zta-ml-anomalies-* zta-nac-*        │
                    │   zta-hunt-*                          │
                    └──────────────────────────────────────┘
                                   ▲
                    ┌──────────────┘
                    │   ztacloud-site/ (cloud extension node)
                    │   Flask app · Keycloak standby
                    │   filebeat-ztacloud.yml → Logstash:5044
                    │   joined via Tailscale WireGuard mesh
                    └──────────────────────────────────────
```

---

## ⚙️ Workflow

This section traces the end-to-end operational flows across the lab.

### 1. User Authentication Flow

```
User request (HTTPS)
  → Caddy (:443)          — TLS 1.3 termination; routes to Pomerium:8444 or Kibana:5601
  → Pomerium (:8444)      — ZTNA proxy: no session? redirect to Keycloak OIDC
  → Keycloak (:8081)      — Realm=zta: authenticates user, returns JWT (TTL=15min)
  → Pomerium              — Validates JWT claims: groups=admins or groups=engineers
  → Cilium eBPF layer     — CNP enforces L3/L4 allow matrix (frontend→backend→database only)
  → Pod (NodePort:30088)  — Request reaches workload only if both Pomerium + CNP pass
```

Missing Keycloak group membership → denied at Pomerium. CNP violation → dropped at eBPF kernel level before it hits the wire. The demo app at `pomerium/demo-app/html/index.html` is the protected target workload served through this chain.

---

### 2. Device Onboarding / NAC Flow

```
Device connects to network
  → FreeRADIUS              — 802.1X EAP-TLS authentication (certs/ provides CA + CSR)
  → keycloak-nac (rlm_rest) — ROPC call to Keycloak :8081; validates device credentials
  → device_onboard.py       — Posture scoring: LUKS encryption, crypto_managed key,
                              unattended-upgrades, SSH state
  → VLAN decision:
       posture=full/standard → VLAN 10 (Production)
       posture=auth_only     → VLAN 90 (Quarantine, 10.90.0.1/24)
  → vlan_assign_hook.sh     — Post-auth hook: reads zta-nac.log per MAC → VLAN assign
  → setup_quarantine_net.sh — Configures quarantine VLAN network if not already present
  → reverify_posture.sh     — systemd timer (zta-posture-reverify.service) re-probes
                              live devices; CoA-Request:3799 on posture regression
  → release_from_quarantine.sh — Manual operator: promote device out of VLAN 90
```

The `nac/keycloak-federation/` scripts handle the wiring between FreeRADIUS and Keycloak: patching the rlm_rest module, creating the RADIUS client in Keycloak, rendering the module config, and resolving the Keycloak endpoint — all the setup work that has to happen once before NAC is functional.

NAC events log as JSON → Filebeat → Logstash branch 3 → `zta-nac-*` → Kibana NAC Posture & Access dashboard.

---

### 3. Detection Pipeline Flow

```
Live traffic (enp0s3 / lxc veth interfaces)
  │
  ├── Suricata 8.0.4 (NF_PACKET mode, suricata.yaml + threshold.config)
  │     52,151 ET Open rules → match → eve.json
  │     → Filebeat (log_type=suricata) → Logstash branch 1 → zta-alerts-* in ES
  │
  └── Zeek (4 sensors, per-pod lxc veth, zeekctl.cfg / node.cfg)
        fix-zeek-interfaces.sh resolves current lxc veths → rewrites node.cfg + systemd units
        conn / dns / http / notice / weird logs → /opt/zeek/logs/
        → Filebeat (log_type=zeek) → Logstash branch 2 → zta-logs-* in ES
```

Service management for both detectors lives in `systemd/`: Suricata gets a service dropin at `systemd/service-dropins/suricata.service.d/override.conf`; Zeek runs as four independent systemd units (`zeek-frontend.service`, `zeek-database.service`, `zeek-attacker.service`, and `zeek-anomaly-detector.service`) under `systemd/system/`.

---

### 4. ML Anomaly Detection Flow

```
Zeek conn.log (live, /opt/zeek/logs/current/)
  → zeek_anomaly_detector.py (runs as zta-threat-hunter.service, every 60s)
       Features: duration, orig_bytes, pkts_per_sec, proto_enc, state_enc
  → Isolation Forest (zta_iforest_model.pkl — pre-trained on baseline ZTA traffic)
       Score < -0.15 → severity=MEDIUM
       Score < -0.08 → severity=HIGH
  → Indexed to zta-ml-anomalies-* in Elasticsearch
  → Visible in Kibana: ML Automation Triggers dashboard
```

---

### 5. Threat Hunting + SOAR Response Flow

```
threat_hunter.py (runs as zta-threat-hunter.service, polls ES every 30s)
  → Queries zta-ml-anomalies-* for severity=high/medium
  → Deduplication via in-memory set
  → On match: triggers Ansible playbook by event type

lateral_sweep.sh (one-shot or --loop mode)
  → Queries zta-logs-* (Zeek conn records, last N minutes)
  → Compares src:dst:port against active CNP allow matrix
       Allowed:  frontend→backend:80, backend→database:80
       Anything else: violation
  → Attacker pod egress → always severity=high regardless of pair
  → Violations → zta-hunt-* in ES + zta-response-actions.log
  → --auto-respond: calls block_ip_cilium.yml per violating source

attacker_sweep.sh (manual test traffic generator)
  → Resolves backend + database pod IPs dynamically (kubectl, no hardcoded IPs)
  → Executes from inside the attacker pod: BusyBox nc port sweep (ports 1–200)
  → HTTP probes via BusyBox wget against backend and database
  → Used to verify Cilium default-deny-all is actually dropping attacker egress
  → Traffic generated here is what Suricata/Zeek picks up and threat_hunter flags
```

**Ansible SOAR response matrix:**

| Trigger | Playbook | Effect |
|---|---|---|
| Attacker pod egress | `block_ip_cilium.yml` | Dynamic `zta-block-<IP>` CNP at eBPF layer |
| East-west policy violation | `block_ip_cilium.yml` | Same — blocks violating source |
| IOC match | `block_ip_cilium.yml` + `revoke_keycloak_session.yml` | Block at network + revoke identity session |
| Workload anomaly | `isolate_workload.yml` | Namespace-wide block CNP |
| Operator clear | `release_ip_cilium.yml` | Removes `zta-block-*` CNPs (authenticated) |

**MTTR target: < 90 seconds**
`T+0` attack → `T+60s` Zeek conn.log updated → `T+90s` threat_hunter polls → `T+100s` Ansible fires → CNP applied at eBPF kernel level.

---

### 6. Cloud Extension Node Flow

```
ztacloud-site/ (deployed on cloud VM)
  → tailscale up             — Joins on-prem Tailscale mesh (same tag:ztalab)
  → start-ztacloud.sh        — Brings up Flask app + Keycloak standby
  → Flask app (flask/app.py) — Cloud workload protected by same Pomerium/Keycloak realm
  → filebeat-ztacloud.yml    — Ships cloud node logs → on-prem Logstash:5044 (Tailscale IP)
  → zta-keycloak-standby.service — Keycloak replica for identity failover
  → failover-identity.sh     — Promotes standby Keycloak when primary is unreachable
  → zta-cloud-app.service    — Manages Flask app lifecycle on the cloud node
```

The cloud node uses the same Keycloak realm, the same Pomerium config, and the same Cilium CNPs as the on-prem node. Cloud provider security groups are perimeter-only; all application-layer enforcement is Cilium/Pomerium/Keycloak regardless of what the cloud firewall allows.

---

## 🔧 Stack Components

| Layer | Technology | Version | Purpose |
|---|---|---|---|
| **Identity** | Keycloak + PostgreSQL | 26.6.2 / pg:15 | OIDC provider, realm/group/user management, JWT TTL=15min |
| **ZTNA Proxy** | Pomerium | v0.32.3 | Per-request policy enforcement, identity-aware access (groups=admins/engineers) |
| **Edge / TLS** | Caddy | latest | Reverse proxy, TLS 1.3 termination on :443/80 |
| **Microsegmentation** | Cilium (eBPF) on k3s | v1.19.5 | L3/L4 network policy — 9 active CNPs (6 static + 3 dynamic zta-block-\*) |
| **NAC** | FreeRADIUS + `device_onboard.py` | — | 802.1X EAP-TLS device auth, OIDC ROPC posture check, VLAN 10/90 assignment |
| **IDS** | Suricata | 8.0.4 | 52,151 ET Open rules, NF_PACKET mode on enp0s3, eve.json → Filebeat |
| **NSM** | Zeek | — | 4 sensors pinned to per-pod lxc veth interfaces via `fix-zeek-interfaces.sh` |
| **Anomaly Detection** | Python (scikit-learn, Isolation Forest) | — | Unsupervised scoring on Zeek conn.log features; trained model persisted as `.pkl` |
| **Threat Hunting** | `threat_hunter.py` + `lateral_sweep.sh` | — | IOC correlation + east-west policy violation detection against ES |
| **SIEM** | ELK Stack | 8.11.0 | Logstash 3-branch pipeline (suricata/zeek/nac), Elasticsearch :9200, Kibana :5601 |
| **SOAR** | Ansible (4 playbooks) | — | Automated block/isolate/revoke/release triggered by threat_hunter match |
| **Observability** | Hubble UI | — | Real-time Cilium flow visibility, active on k3s |
| **Mesh Networking** | Tailscale (WireGuard) | — | E2E encrypted overlay, 100.96.17.20, tag:ztalab, port 51820/UDP |
| **Cloud Extension** | Flask + Keycloak standby | — | Cloud node in `ztacloud-site/`; same mesh, same realm, own Filebeat |

---

## 📁 Repository Structure

```
.
├── ansible/                         # SOAR playbooks — triggered by threat_hunter.py / lateral_sweep.sh
│   ├── block_ip_cilium.yml          # Adds dynamic zta-block-<IP> CNP; labels pod quarantine
│   ├── isolate_workload.yml         # Namespace-wide block CNP for compromised workloads
│   ├── revoke_keycloak_session.yml  # Admin REST: DELETE /users/{id}/sessions
│   ├── release_ip_cilium.yml        # Removes zta-block-* CNPs (manual, operator-authenticated)
│   └── inventory.ini
│
├── caddy/
│   └── Caddyfile                    # TLS routing: :443/80 → Pomerium:8444, Keycloak:8081, Kibana:5601
│
├── certs/
│   ├── rootCA.crt                   # Self-signed root CA for 802.1X EAP-TLS (FreeRADIUS)
│   └── server.csr                   # Server certificate signing request
│
├── cilium/
│   ├── zta-cilium-consolidated.yaml # 9 CNPs: default-deny-all + explicit allow matrix (Git-tracked)
│   ├── zta-cilium-demo.yaml         # Demo namespace workload definitions (frontend/backend/database/attacker)
│   └── start_hubbleui.sh            # Launches Hubble UI for real-time Cilium flow visualization
│
├── demo-scripts/                    # Numbered oral defense demo scripts — each proves one lab component
│   ├── 00-precheck.sh               # Validates all services are up before demo starts
│   ├── 01-mesh.sh                   # Proves Tailscale WireGuard mesh is live (on-prem ↔ cloud)
│   ├── 02-ufw-proof.sh              # Demonstrates UFW default-forward fix; before/after overlay traffic
│   ├── 03-nac.sh                    # Live 802.1X EAP-TLS auth flow; VLAN assignment output
│   ├── 04-posture-onboard.sh        # Device posture scoring; VLAN 10 vs VLAN 90 decision
│   ├── 05-replication.sh            # Keycloak realm replication to cloud standby node
│   ├── 06-hubble-traffic.sh         # Generates traffic; shows Hubble flow table in real time
│   ├── 07-cilium.sh                 # Shows 9 active CNPs; proves attacker pod is blocked
│   ├── 08-suricata-zeek.sh          # Triggers a Suricata/Zeek alert; shows in eve.json + conn.log
│   ├── 09-ml-model.sh               # Runs zeek_anomaly_detector.py; shows anomaly score output
│   ├── 10-siem.sh                   # Shows Kibana dashboards; confirms 490K+ indexed events
│   ├── 11-ansible-exec.sh           # Fires Ansible SOAR manually; shows CNP applied in < 90s
│   ├── 12-ztacloud-health.sh        # Verifies cloud extension node health + log shipping
│   ├── 13-drp-proof.sh              # Disaster recovery / failover proof: Keycloak standby promotion
│   ├── hubble-quick.sh              # Quick Hubble flow snapshot (used inline during demo)
│   └── traffic-gen.sh               # Generic traffic generator for Suricata/Zeek trigger scenarios
│
├── elk/
│   ├── logstash/
│   │   └── pipeline/
│   │       └── zta.conf             # 3-branch pipeline: suricata→eve, zeek→rename fields, nac→GeoIP
│   ├── docker-compose.yml
│   ├── kibana_backup_20260907.ndjson        # Kibana dashboard export (September snapshot)
│   └── kibana-dashboard-backup-20261003.ndjson  # Kibana dashboard export (October snapshot — current)
│
├── filebeat/
│   └── filebeat.yml                 # Ships Suricata/Zeek/NAC logs from on-prem → Logstash:5044
│
├── freeradius/
│   ├── mods-available/
│   │   └── keycloak-nac             # rlm_rest module: ROPC calls to Keycloak :8081 for NAC auth
│   ├── sites-enabled/
│   │   └── default                  # FreeRADIUS site config: EAP-TLS + post-auth VLAN hook
│   └── clients.conf
│
├── keycloak/
│   ├── docker-compose.yml
│   ├── create-user.sh
│   ├── create-groups.sh
│   ├── verify-keycloack.sh
│   ├── zta-realm-export.json        # Full realm export (realm=zta): clients, flows, scopes
│   ├── zta-groups-export.json       # Groups export: admins, engineers group definitions
│   └── zta-users-export.json        # Users export: lab user accounts and group memberships
│
├── nac/
│   ├── keycloak-federation/         # One-time wiring scripts: FreeRADIUS ↔ Keycloak ROPC setup
│   │   ├── mods-available/
│   │   │   └── keycloak-nac         # Module template before rendering
│   │   ├── apply_rest_wiring.py     # Applies rlm_rest config to FreeRADIUS mods-enabled
│   │   ├── apply_rest_wiring_v2.py  # v2: handles edge cases in module path resolution
│   │   ├── create_freeradius_client.sh  # Creates RADIUS client entry in Keycloak
│   │   ├── find_files_occurrences.py    # Diagnostic: finds all keycloak-nac references on disk
│   │   ├── fix_reject_block.py      # Patches FreeRADIUS default site to fix auth reject block
│   │   ├── patch_default.py         # Patches FreeRADIUS default site for Keycloak integration
│   │   ├── patch_default_v2.py      # v2: idempotent version of patch_default
│   │   ├── render_keycloak_module.sh # Renders keycloak-nac module with live Keycloak IP/port
│   │   └── resolve_keycloak.sh      # Resolves Keycloak container IP for rlm_rest config
│   ├── quarantine/
│   │   ├── systemd/
│   │   │   ├── zta-posture-reverify.service       # Systemd service for periodic posture re-check
│   │   │   └── zta-posture-reverify.timer.template # Timer template; rendered by render_reverify_timer.sh
│   │   ├── vlan_assign_hook.sh      # Post-auth hook: reads zta-nac.log per MAC → VLAN assign
│   │   ├── reverify_posture.sh      # Re-probes live devices; CoA-Request:3799 on posture regression
│   │   ├── render_reverify_timer.sh # Generates systemd timer unit from template; installs + enables it
│   │   ├── setup_quarantine_net.sh  # Configures VLAN 90 (10.90.0.1/24) network if not present
│   │   └── release_from_quarantine.sh  # Manual operator: moves device from VLAN 90 → VLAN 10
│   └── device_onboard.py            # RADIUS auth → posture scoring → VLAN 10/90 decision logic
│
├── observability/
│   ├── render-configs.sh            # Resolves Suricata interface at runtime → writes suricata.yaml
│   └── detect-env.sh                # Detects VM network interface name for dynamic config generation
│
├── pomerium/
│   ├── demo-app/
│   │   └── html/
│   │       └── index.html           # Protected demo workload served through Pomerium ZTNA proxy
│   ├── config.yaml                  # ZTNA config: upstream NodePort:30088, OIDC client, policy rules
│   └── docker-compose.yml
│
├── python-scripts/
│   ├── ml/
│   │   ├── zeek_anomaly_detector.py # Isolation Forest; reads conn.log every 60s; scores + indexes to ES
│   │   └── zta_iforest_model.pkl    # Persisted trained model (baseline ZTA traffic)
│   └── threat_hunter.py             # Queries ES every 30s; deduplication via in-memory set; triggers Ansible
│
├── suricata/
│   └── suricata/
│       ├── suricata.yaml            # NF_PACKET mode; interface resolved by render-configs.sh at startup
│       ├── classification.config    # Alert classification categories
│       ├── reference.config         # Reference URLs for rule documentation
│       └── threshold.config         # Rate limiting / suppression rules to reduce noise
│
├── systemd/                         # All systemd unit files and service dropins for the lab
│   ├── service-dropins/
│   │   ├── freeradius.service.d/
│   │   │   └── keycloak-env.conf    # Injects Keycloak URL env vars into FreeRADIUS service
│   │   └── suricata.service.d/
│   │       └── override.conf        # Suricata service override: interface + AF_PACKET mode
│   ├── system/
│   │   ├── zeek_anomaly_detector.service  # Runs zeek_anomaly_detector.py as a managed service
│   │   ├── zeek-attacker.service    # Zeek sensor: attacker pod lxc veth
│   │   ├── zeek-database.service    # Zeek sensor: database pod lxc veth
│   │   ├── zeek-frontend.service    # Zeek sensor: frontend pod lxc veth
│   │   ├── zta-posture-reverify.service   # Runs reverify_posture.sh on a timer
│   │   ├── zta-posture-reverify.timer     # systemd timer: triggers posture re-check interval
│   │   └── zta-threat-hunter.service      # Runs threat_hunter.py as a managed background service
│   └── suricata-override.conf       # Top-level Suricata override (pre-dropin format)
│
├── zeek/
│   ├── zeek/
│   │   └── zeek.conf                # Zeek global config: log format, rotation, loaded scripts
│   ├── zkg/
│   │   └── config                   # Zeek package manager config (zkg)
│   ├── fix-zeek-interfaces.sh       # Resolves current Cilium lxc veths → rewrites node.cfg + systemd units atomically
│   ├── node.cfg                     # worker-backend (zeekctl), zeek-frontend/database/attacker (systemd)
│   ├── networks.cfg                 # Local network ranges for Zeek connection classification
│   └── zeekctl.cfg                  # zeekctl settings: log rotation, crash handling, mail
│
├── zta-identity-app/                # Containerized identity-aware demo application
│   ├── app.py                       # Flask app: validates Keycloak JWT on every request
│   └── Dockerfile                   # Container build for the identity app
│
├── ztacloud-site/                   # Cloud extension node — joins the same Tailscale mesh
│   ├── filebeat/
│   │   └── filebeat-ztacloud.yml    # Ships cloud node logs → on-prem Logstash:5044 (Tailscale IP)
│   ├── flask/
│   │   └── app.py                   # Cloud workload: Flask app protected by same Pomerium/Keycloak realm
│   ├── scripts/
│   │   └── failover-identity.sh     # Promotes Keycloak standby when primary is unreachable
│   ├── systemd/
│   │   ├── zta-cloud-app.service    # Manages Flask app lifecycle on the cloud node
│   │   └── zta-keycloak-standby.service  # Keycloak replica for identity failover
│   ├── README.md                    # Cloud node setup and join instructions
│   └── start-ztacloud.sh            # Brings up Flask app + Keycloak standby on the cloud node
│
├── .env.example                     # Template for required secrets (never commit .env itself)
├── .gitignore
├── attacker_sweep.sh                # Test traffic generator: BusyBox nc port sweep (1–200) + HTTP probes
│                                    # Executes from inside the attacker pod; verifies Cilium blocks it
├── backup.sh                        # Backs up live configs and ELK indexes to snapshot
├── bootstrap.sh                     # Initial lab provisioning script: installs deps, sets up k3s + Cilium
├── Caddyfile                        # Root-level Caddyfile (mirrors caddy/Caddyfile; used for quick edits)
├── lateral_sweep.sh                 # East-west sweep: queries ES Zeek data vs CNP allow matrix
│                                    # --loop / --auto-respond / --lookback=N / ES file fallback
├── secrets.enc.env                  # Age/GPG-encrypted secrets for lab services
└── zta_snapshot.sh                  # Full lab state snapshot: k3s, Cilium CNPs, ES indexes, configs
```

---

## 🎯 Zero Trust Principles in Practice

**1. Default-deny by default**
Cilium's `default-deny-all` CNP blocks all ingress/egress in the `zta-demo` namespace. Six static CNPs define the explicit allow matrix (frontend→backend→database only). Three dynamic `zta-block-<IP>` CNPs are auto-generated live by Ansible SOAR when the threat hunter fires.

**2. Identity-aware access, not IP-based**
Pomerium enforces access per-request based on Keycloak OIDC claims (`groups: admins`, `groups: engineers`) with JWT TTL=15min — not source IP or network zone. Keycloak realm=zta is the single IdP across both on-prem and cloud nodes.

**3. Continuous device posture evaluation**
`device_onboard.py` implements the real NAC flow: FreeRADIUS 802.1X EAP-TLS authentication → rlm_rest ROPC to Keycloak :8081 → posture scoring (crypto_managed key, LUKS encryption, unattended-upgrades, SSH state) → tiered VLAN decision:
- Tier 1 (posture=full/standard) → VLAN 10 Production
- Tier 2 (auth_only) → VLAN 90 Quarantine

`vlan_assign_hook.sh` reads `zta-nac.log` per MAC post-auth. `reverify_posture.sh` runs on a systemd timer and issues CoA-Request:3799 on posture regression. `release_from_quarantine.sh` handles manual operator promotion back to VLAN 10.

**4. Microsegmentation at L3/L4**
Cilium enforces the full allow matrix at the eBPF kernel level on each pod's lxc veth interface. The attacker pod is walled off by default-deny — all its traffic is dropped before it reaches the wire. `attacker_sweep.sh` generates controlled test traffic from the attacker pod to verify this enforcement is actually working; `demo-scripts/07-cilium.sh` runs the same proof live during demonstration.

**5. Behavioral anomaly detection**
A trained Isolation Forest model (`zta_iforest_model.pkl`) scores live Zeek conn.log features (duration, orig_bytes, pkts_per_sec, proto_enc, state_enc) every 60 seconds. Score < -0.15 → MEDIUM, < -0.08 → HIGH. Results indexed to `zta-ml-anomalies-*` in ES.

**6. Automated threat response (SOAR)**
`threat_hunter.py` queries ES every 30s for severity=high/medium across `zta-ml-anomalies-*`. On match, it triggers one of four Ansible playbooks:

| Trigger | Playbook |
|---|---|
| Attacker pod egress detected | `block_ip_cilium.yml` |
| Policy violation | `block_ip_cilium.yml` |
| IOC match | `block_ip_cilium.yml` + `revoke_keycloak_session.yml` |
| Workload anomaly | `isolate_workload.yml` |

MTTR target: **< 90 seconds** (T+0 attack → T+60s Zeek conn.log updated → T+90s threat_hunter polls → T+100s Ansible executes, CNP applied at eBPF kernel level).

---

## 🌐 Hybrid Cloud Design

The cloud extension node is live in `ztacloud-site/`. Moving any workload to a cloud Kubernetes cluster (AKS/EKS/GKE/OKE) requires exactly three changes:

1. `filebeat.yml` output.logstash host → on-prem Tailscale IP (100.96.17.20)
2. `fix-zeek-interfaces.sh` re-run on the cloud node (same script, resolves dynamically)
3. `tailscale up` to join the mesh

Everything else is identical: same Keycloak realm (with standby in `ztacloud-site/`), same `zta-cilium-consolidated.yaml` CNPs (Git-tracked), same Pomerium config, same single Kibana pane. Cloud provider security groups / VPC ACLs are perimeter controls only — all application-layer enforcement is Cilium/Pomerium/Keycloak regardless of what the cloud provider's firewall allows.

---

## 🔍 Observability Stack

**Logstash pipeline (`zta.conf`) — 3 branches:**
- Branch 1: `log_type=suricata` → parse eve.json → `zta-alerts-*`
- Branch 2: `log_type=zeek` → rename `id.*` fields → `zta-logs-*`
- Branch 3: `log_type=nac` → parse NAC JSON, GeoIP enrichment on src_ip → `zta-nac-*`

**Kibana dashboards (5 live, exported to `elk/`):**
- Master Posture Summary
- NAC Posture & Access
- ML Automation Triggers
- Security Alerts (GeoIP maps)
- Forensics via Discover

Dashboard exports live at `elk/kibana-dashboard-backup-20261003.ndjson` (current) and `elk/kibana_backup_20260907.ndjson` (September snapshot). Import via Kibana → Stack Management → Saved Objects.

**Hubble UI:** Real-time Cilium flow visualization active on the k3s cluster, accessible via `start_hubbleui.sh` or `demo-scripts/06-hubble-traffic.sh`.

---

## 🐛 Real Debugging Wins

These were root-caused independently, with post-mortems written afterward:

**CoreDNS stuck at `0/1 Ready`** — traced to Cilium's eBPF layer dropping pod-to-host traffic. Resolved with a `hostNetwork: true` patch and DNS loop fix in CoreDNS config. Cilium's default-deny-all was intercepting DNS before the allow-dns CNP was applied — order of policy application matters.

**UFW silently breaking overlay networking** — `DEFAULT_FORWARD_POLICY="DROP"` was blocking all Cilium lxc overlay traffic. Not documented anywhere obvious; found through systematic packet-level elimination (`tcpdump` on lxc interfaces vs enp0s3). `demo-scripts/02-ufw-proof.sh` demonstrates the before/after.

**Pomerium OIDC redirect loop** — caused by a missing `offline_access` scope in the Keycloak client configuration, compounded by a TLS scheme mismatch (http vs https) between Caddy's upstream and Pomerium's `authenticate_service_url`. Fixed by explicitly setting `authenticate_service_url` scheme and adding the offline_access scope.

**Zeek lxc interface drift** — Cilium re-allocates lxc veth names on every pod restart. `fix-zeek-interfaces.sh` was written to solve this: it queries the Cilium endpoint list via `cilium-dbg`, resolves the current interface name per pod IP, and rewrites both `node.cfg` and the standalone systemd unit files atomically. Also adds `WorkingDirectory=` enforcement to prevent stray logs landing at filesystem root (`/conn.log`, etc.).

**Suricata interface resolution** — NF_PACKET mode requires knowing the physical interface at startup (`enp0s3`). `render-configs.sh` / `detect-env.sh` resolve this dynamically so the same config works across different VM network configurations.

---

## ⚠️ Honest Scope Note

This lab distinguishes between what is **live and running** and what is **designed but not deployed**, because overclaiming helps no one.

**Live and verified:**
- k3s + Cilium v1.19.5 (9 active CNPs, Hubble UI, transparent WireGuard encryption mode)
- Keycloak 26.6.2 + PostgreSQL 15 (OIDC, realm=zta, groups, ROPC for NAC)
- Pomerium v0.32.3 (ZTNA proxy, per-request JWT enforcement)
- Caddy (TLS edge, :443/80)
- FreeRADIUS (802.1X EAP-TLS, rlm_rest → Keycloak, VLAN 10/90 assignment)
- Suricata 8.0.4 (52,151 ET Open rules, NF_PACKET, eve.json pipeline)
- Zeek (4 sensors, per-pod lxc veth, fix-zeek-interfaces.sh)
- ELK Stack 8.11.0 (Elasticsearch :9200, Logstash :5044, Kibana :5601, 490K+ indexed events)
- Isolation Forest ML detector (`zta_iforest_model.pkl`, live scoring)
- threat_hunter.py + lateral_sweep.sh (ES polling, deduplication)
- Ansible SOAR (4 playbooks, block/isolate/revoke/release)
- Tailscale WireGuard mesh (100.96.17.20, tag:ztalab)
- VLAN quarantine (VLAN 90, 10.90.0.1/24, CoA reverification timer)
- Cloud extension node (`ztacloud-site/`) with Keycloak standby + Filebeat log shipping

**Designed, not deployed:**
- PacketFence as a full NAC management plane
- Live MISP threat feed integration (IOC feed is currently file-loadable)
- Multi-cloud simultaneous deployment (design validated, not instantiated)
- Grafana unified posture dashboard (Kibana covers this in current build)

---

## 🚀 Getting Started

Each component is self-contained. If starting from scratch, run `bootstrap.sh` first to provision dependencies, k3s, and Cilium. Then bring up in this order:

```bash
# 0. Initial provisioning (first-time only)
bash bootstrap.sh

# 1. Copy and fill secrets
cp .env.example .env
# Fill: ELASTIC_PASSWORD, POSTGRES_PASSWORD, KEYCLOAK_ADMIN_PASSWORD,
#       POMERIUM_SHARED_SECRET, POMERIUM_COOKIE_SECRET, POMERIUM_IDP_CLIENT_SECRET

# 2. Identity provider
cd keycloak && docker compose up -d
./create-user.sh && ./create-groups.sh
# To restore a previous realm: import zta-realm-export.json via Keycloak admin UI

# 3. ZTNA proxy + TLS edge
cd ../pomerium && docker compose up -d
# Root Caddyfile or caddy/Caddyfile — start alongside pomerium

# 4. SIEM stack
cd ../elk && docker compose up -d
# Restore dashboards: import elk/kibana-dashboard-backup-20261003.ndjson via Kibana UI

# 5. Filebeat (log shipper)
sudo systemctl start filebeat

# 6. Network policies (requires k3s + Cilium already running)
kubectl apply -f cilium/zta-cilium-consolidated.yaml
kubectl apply -f cilium/zta-cilium-demo.yaml

# 7. Suricata — resolve interface then start
cd observability && bash render-configs.sh
sudo systemctl start suricata

# 8. Fix Zeek interface bindings (run after every pod restart)
cd ../zeek && sudo bash fix-zeek-interfaces.sh
# Install systemd units from systemd/system/ then:
sudo systemctl start zeek-frontend zeek-backend zeek-database zeek-attacker

# 9. ML detector + threat hunter (via systemd or manually)
sudo systemctl start zeek_anomaly_detector zta-threat-hunter
# Or manually: python python-scripts/ml/zeek_anomaly_detector.py &
#              python python-scripts/threat_hunter.py &

# 10. NAC wiring (first-time only)
cd nac/keycloak-federation && bash render_keycloak_module.sh && bash resolve_keycloak.sh
python3 apply_rest_wiring_v2.py

# 11. Verify enforcement (generates attacker test traffic)
bash attacker_sweep.sh

# 12. Lateral movement detection (continuous mode)
ES_USER=elastic ES_PASS=<pass> bash lateral_sweep.sh --loop --auto-respond

# 13. Cloud node (on the cloud VM)
cd ztacloud-site && bash start-ztacloud.sh
```

> **Secrets:** `secrets.enc.env` holds encrypted lab secrets. `.env.example` lists every variable needed before anything starts. Never commit a plaintext `.env`.

> **Snapshots:** `zta_snapshot.sh` captures a full lab state (CNPs, ES indexes, configs). `backup.sh` backs up live configs and Kibana exports.

> **Demo:** To run the full oral defense demonstration sequence, use `demo-scripts/00-precheck.sh` first to verify all services are healthy, then run scripts 01–13 in order.

---

## 📄 License

Shared for educational and portfolio purposes. Architecture, configuration approach, and debugging methodology are free to reference for your own learning.

---

<div align="center">

**Built as a hands-on deep dive into Zero Trust — default deny, verify explicitly, never trust the network.**

[GitHub](https://github.com/Aarib26) · [LinkedIn](https://linkedin.com/in/aarib-ali-khan-0b782b322)

</div>
