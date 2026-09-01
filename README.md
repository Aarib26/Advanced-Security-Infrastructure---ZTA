<div align="center">

# 🛡️ Advanced Security Infrastructure — Zero Trust Architecture

**A self-built Zero Trust lab spanning identity, network microsegmentation, NAC, IDS/NSM, ML-based anomaly detection, and centralized SIEM — deployed and debugged end-to-end on a home lab.**

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

Every component here was deployed on a real Ubuntu lab machine (`ztauser`) over Tailscale WireGuard, with actual traffic flowing through it — Keycloak 26.6.2 issuing OIDC tokens, Pomerium v0.32.3 enforcing per-request policy, Cilium v1.19.5 dropping packets at the eBPF layer with 9 active CNPs, Suricata 8.0.4 and Zeek watching four pod-pinned lxc interfaces, and Python scripts scoring device posture and flagging anomalies in real time via a trained Isolation Forest model.

> **Design philosophy:** default-deny everywhere, verify explicitly at every layer, never trust network location as a substitute for identity.

---

## 🗺️ Architecture Diagrams

### System Architecture
![System Architecture](System_Arch_drawio.png)

### Network Topology
![Network Topology](Network_Topology_Diagram_drawio.png)

### Data Flow Diagram (DFD — Level 0 + Level 1)
![Data Flow Diagram](DFD_drawio.png)

### Security Architecture — Trust Boundaries
![Security Architecture Trust Boundaries](Security_Architecture__Trust_Boundaries__drawio.png)

### Hybrid Cloud Architecture — Provider-Agnostic Design
![Hybrid Cloud Architecture](Hybrid_Cloud_Architecture_drawio.png)

### Process Flow — Automated Threat Response (SOAR)
![SOAR Process Flow](Process_Flow__Full_Threat_Response_Workflow_drawio.png)

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
```

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

---

## 📁 Repository Structure

```
.
├── ansible/                    # SOAR playbooks — triggered by threat_hunter.py
│   ├── block_ip_cilium.yml     # Adds dynamic zta-block-<IP> CNP, labels pod quarantine
│   ├── isolate_workload.yml    # Namespace-wide block CNP for compromised workloads
│   ├── revoke_keycloak_session.yml  # Admin REST: DELETE /users/{id}/sessions
│   ├── release_ip_cilium.yml   # Removes zta-block-* CNPs (manual, operator-authenticated)
│   └── inventory.ini
├── caddy/
│   └── Caddyfile               # TLS routing: :443/80 → Pomerium:8444, Keycloak:8081, Kibana:5601
├── cilium/
│   ├── zta-cilium-consolidated.yaml  # 9 CNPs — default-deny-all + explicit allow matrix
│   ├── zta-cilium-demo.yaml          # Demo namespace workload definitions
│   └── start_hubbleui.sh
├── elk/
│   ├── docker-compose.yml
│   └── logstash/pipeline/zta.conf    # 3-branch pipeline: suricata→eve, zeek→rename, nac→GeoIP
├── filebeat/
│   └── filebeat.yml            # Ships Suricata/Zeek/NAC logs → Logstash:5044
├── freeradius/
│   ├── clients.conf
│   ├── mods-available/keycloak-nac   # rlm_rest → Keycloak ROPC validation
│   └── sites-enabled/default
├── keycloak/
│   ├── docker-compose.yml
│   ├── create-user.sh
│   ├── create-groups.sh
│   └── verify-keycloack.sh
├── nac/
│   ├── device_onboard.py       # RADIUS auth → posture check → VLAN 10/90 decision
│   ├── keycloak-federation/    # FreeRADIUS ↔ Keycloak ROPC wiring scripts
│   └── quarantine/
│       ├── vlan_assign_hook.sh          # Post-auth hook: reads zta-nac.log → VLAN assign
│       ├── reverify_posture.sh          # Re-probes live devices; CoA-Request:3799 on regression
│       ├── render_reverify_timer.sh
│       └── systemd/                     # zta-posture-reverify.service/.timer
├── observability/
│   ├── render-configs.sh       # Resolves Suricata interface at runtime → suricata.yaml
│   └── detect-env.sh
├── pomerium/
│   ├── config.yaml             # upstream: NodePort:30088 (k3s frontend)
│   ├── policy.yaml             # groups=admins, groups=engineers allow rules
│   └── demo-app/
├── python-scripts/
│   ├── ml/
│   │   ├── zeek_anomaly_detector.py    # Isolation Forest; reads conn.log every 60s
│   │   └── zta_iforest_model.pkl       # Persisted trained model
│   └── threat_hunter.py                # Queries ES every 30s; deduplication via in-memory set
├── suricata/suricata/
│   ├── suricata.yaml           # NF_PACKET mode, interface resolved by render-configs.sh
│   └── classification.config
├── zeek/
│   ├── fix-zeek-interfaces.sh  # Resolves current Cilium lxc veths → updates node.cfg + systemd
│   ├── node.cfg                # worker-backend (zeekctl), zeek-frontend/database/attacker (systemd)
│   └── networks.cfg
├── lateral_sweep.sh            # Checks east-west pairs vs CNP allow matrix → zta-hunt-* in ES
├── attacker_sweep.sh
└── startup.sh / afk_startup.sh / pers_start.sh   # Lab bring-up sequences
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

`vlan_assign_hook.sh` reads `zta-nac.log` per MAC post-auth. `reverify_posture.sh` runs on a systemd timer and issues CoA-Request:3799 on posture regression.

**4. Microsegmentation at L3/L4**
Cilium enforces the full allow matrix at the eBPF kernel level on each pod's lxc veth interface. The attacker pod is walled off by default-deny — all its traffic is dropped before it reaches the wire.

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

The architecture is designed to be provider-agnostic. Moving to a cloud Kubernetes cluster (AKS/EKS/GKE/OKE) requires exactly three changes:

1. `filebeat.yml` output.logstash host → on-prem Tailscale IP (100.96.17.20)
2. `fix-zeek-interfaces.sh` re-run on the cloud node (same script, resolves dynamically)
3. `tailscale up` to join the mesh

Everything else is identical: same Keycloak realm, same `zta-cilium-consolidated.yaml` CNPs (Git-tracked), same Pomerium config, same single Kibana pane. Cloud provider security groups / VPC ACLs serve as perimeter controls only — all application-layer security is enforced by Cilium/Pomerium/Keycloak regardless of what the cloud provider's firewall allows.

---

## 🔍 Observability Stack

**Logstash pipeline (`zta.conf`) — 3 branches:**
- Branch 1: `log_type=suricata` → parse eve.json → `zta-alerts-*`
- Branch 2: `log_type=zeek` → rename `id.*` fields → `zta-logs-*`
- Branch 3: `log_type=nac` → parse NAC JSON, GeoIP enrichment on src_ip → `zta-nac-*`

**Kibana dashboards (5 live):**
- Master Posture Summary
- NAC Posture & Access
- ML Automation Triggers
- Security Alerts (GeoIP maps)
- Forensics via Discover

**Hubble UI:** Real-time Cilium flow visualization active on the k3s cluster, accessible via `start_hubbleui.sh`.

---

## 🐛 Real Debugging Wins

These were root-caused independently, with post-mortems written afterward:

**CoreDNS stuck at `0/1 Ready`** — traced to Cilium's eBPF layer dropping pod-to-host traffic. Resolved with a `hostNetwork: true` patch and DNS loop fix in CoreDNS config. Cilium's default-deny-all was intercepting DNS before the allow-dns CNP was applied — order of policy application matters.

**UFW silently breaking overlay networking** — `DEFAULT_FORWARD_POLICY="DROP"` was blocking all Cilium lxc overlay traffic. Not documented anywhere obvious; found through systematic packet-level elimination (`tcpdump` on lxc interfaces vs enp0s3).

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

**Designed, not deployed:**
- PacketFence as a full NAC management plane
- Live MISP threat feed integration (IOC feed is currently file-loadable)
- Multi-cloud simultaneous deployment (design validated, not instantiated)
- Grafana unified posture dashboard (Kibana covers this in current build)

---

## 🚀 Getting Started

Each component is self-contained. Recommended bring-up order:

```bash
# 1. Identity provider
cd keycloak && docker compose up -d
./create-user.sh && ./create-groups.sh

# 2. ZTNA proxy + TLS edge
cd ../pomerium && docker compose up -d
# Caddy config lives in caddy/Caddyfile — start alongside pomerium

# 3. SIEM stack
cd ../elk && docker compose up -d

# 4. Filebeat (log shipper)
# Edit filebeat/filebeat.yml output.logstash.hosts to match your Logstash IP
sudo systemctl start filebeat

# 5. Network policies (requires k3s + Cilium already installed)
kubectl apply -f cilium/zta-cilium-consolidated.yaml
kubectl apply -f cilium/zta-cilium-demo.yaml

# 6. Fix Zeek interface bindings (run after every pod restart)
cd zeek && sudo bash fix-zeek-interfaces.sh

# 7. Detection stack
# Suricata: sudo systemctl start suricata
# render-configs.sh resolves interface before start

# 8. ML detector + threat hunter (in ztaenv virtualenv)
source python-scripts/ztaenv/bin/activate
python python-scripts/ml/zeek_anomaly_detector.py &
python python-scripts/threat_hunter.py &
```

> **Note:** This repo ships configuration, not secrets. You'll need your own `.env` with `ELASTIC_PASSWORD`, `POSTGRES_PASSWORD`, `KEYCLOAK_ADMIN_PASSWORD`, and Pomerium's `SHARED_SECRET` / `COOKIE_SECRET` / `IDP_CLIENT_SECRET` before anything will actually start.

---

## 📄 License

Shared for educational and portfolio purposes. Architecture, configuration approach, and debugging methodology are free to reference for your own learning.

---

<div align="center">

**Built as a hands-on deep dive into Zero Trust — default deny, verify explicitly, never trust the network.**

[GitHub](https://github.com/Aarib26) · [LinkedIn](https://linkedin.com/in/aarib-ali-khan-0b782b322)

</div>
