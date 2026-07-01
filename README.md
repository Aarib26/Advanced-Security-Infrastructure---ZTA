
<div align="center">

# 🛡️ Advanced Security Infrastructure — Zero Trust Architecture

**A self-built Zero Trust lab spanning identity, network microsegmentation, NAC, IDS/NSM, ML-based anomaly detection, and centralized SIEM — deployed and debugged end-to-end on a home lab.**

[![Zero Trust](https://img.shields.io/badge/Architecture-Zero%20Trust-black?style=flat-square)](#)
[![Cilium](https://img.shields.io/badge/eBPF-Cilium-orange?style=flat-square)](#)
[![Keycloak](https://img.shields.io/badge/Identity-Keycloak%20OIDC-blue?style=flat-square)](#)
[![Pomerium](https://img.shields.io/badge/ZTNA-Pomerium-green?style=flat-square)](#)
[![ELK](https://img.shields.io/badge/SIEM-ELK%20Stack-005571?style=flat-square)](#)
[![Ansible](https://img.shields.io/badge/IaC-Ansible-red?style=flat-square)](#)

</div>

---

## 📌 What This Is

This repo is the working configuration for a **Zero Trust Architecture lab** built from first principles — not a tutorial clone, not a single `docker-compose up` demo. It's the actual identity, network, NAC, detection, and automation layer I built, broke, root-caused, and fixed while learning how a real Zero Trust stack fits together.

Every component here was deployed on a real Ubuntu lab machine over Tailscale, with actual traffic flowing through it — Keycloak issuing tokens, Pomerium enforcing policy, Cilium dropping packets at the eBPF layer, Suricata and Zeek watching the wire, and Python scripts scoring device posture and flagging anomalies in real time.

> **Design philosophy:** default-deny everywhere, verify explicitly at every layer, and never trust network location as a substitute for identity.

---

## 🏗️ Architecture

```
                            ┌─────────────────────┐
                            │   Caddy (TLS edge)   │
                            │  reverse proxy + TLS  │
                            └──────────┬───────────┘
                                       │
                 ┌─────────────────────┼─────────────────────┐
                 ▼                     ▼                     ▼
        ┌────────────────┐   ┌─────────────────┐   ┌──────────────────┐
        │   Keycloak      │   │    Pomerium      │   │  Kibana / ELK     │
        │  OIDC Identity  │──▶│  ZTNA Proxy      │   │  SIEM Dashboard    │
        │  Provider       │   │  (policy engine) │   └──────────────────┘
        └────────────────┘   └────────┬─────────┘
                                       │ allow/deny per-request
                                       ▼
                          ┌─────────────────────────┐
                          │   Cilium (eBPF) on k3s    │
                          │  L3/L4/L7 microsegmentation│
                          └────────────┬─────────────┘
                                       │
                 ┌─────────────────────┼─────────────────────┐
                 ▼                     ▼                     ▼
        ┌────────────────┐   ┌─────────────────┐   ┌──────────────────┐
        │  FreeRADIUS    │   │  Suricata IDS   │   │  Zeek NSM         │
        │  802.1X NAC    │   │  + Zeek anomaly  │   │  + ML detector    │
        └────────────────┘   │  detector        │   └──────────────────┘
                              └─────────────────┘
                                       │
                                       ▼
                          ┌─────────────────────────┐
                          │   Logstash → Elasticsearch │
                          │   490K+ indexed events      │
                          └─────────────────────────┘
```

---

## 🔧 Stack Components

| Layer | Technology | Purpose |
|---|---|---|
| **Identity** | Keycloak + PostgreSQL | OIDC provider, realm/group/user management |
| **ZTNA Proxy** | Pomerium | Per-request policy enforcement, identity-aware access |
| **Edge / TLS** | Caddy | Reverse proxy, TLS termination |
| **Microsegmentation** | Cilium (eBPF) on k3s | L3/L4/L7 network policy enforcement |
| **NAC** | FreeRADIUS + `device_onboard.py` | 802.1X device authentication + posture scoring |
| **IDS/NSM** | Suricata + Zeek | Real-time traffic inspection and network security monitoring |
| **Anomaly Detection** | Python (scikit-learn, Isolation Forest) | Unsupervised anomaly scoring on network/device behavior |
| **Threat Hunting** | `threat_hunter.py` | Correlates IOCs against ingested log data |
| **SIEM** | ELK Stack (Elasticsearch, Logstash, Kibana) | Centralized log ingestion, search, and visualization |
| **Automation** | Ansible | Idempotent deployment/verification of the detection stack |
| **Mesh Networking** | Tailscale (WireGuard) | Encrypted overlay between lab nodes |

---

## 📁 Repository Structure

```
.
├── ansible/              # IaC — deploys and verifies Suricata, Zeek, Filebeat
│   ├── deploy_zta_stack.yml
│   └── inventory.ini
├── cilium/                # eBPF network policies (default-deny, DNS-only, L7 HTTP)
│   ├── zta-network-policies.yaml
│   ├── zta-cilium-17-policy.yaml
│   ├── zta-cilium-dns-only.yaml
│   └── zta-cilium-demo.yaml
├── elk/                   # SIEM stack — Elasticsearch, Logstash, Kibana
│   ├── docker-compose.yml
│   └── logstash/pipeline/zta.conf
├── keycloak/               # Identity provider — users, groups, realm setup
│   ├── docker-compose.yml
│   ├── create-user.sh
│   ├── create-groups.sh
│   └── verify-keycloack.sh
├── nac/                    # Network Access Control simulation
│   └── device_onboard.py   # RADIUS auth → posture check → access decision
├── pomerium/                # ZTNA proxy — identity-aware access policy
│   ├── config.yaml
│   ├── policy.yaml
│   └── demo-app/
├── python_scripts/          # Detection & hunting logic
│   ├── zeek_anomaly_detector.py  # Isolation Forest anomaly scoring
│   └── threat_hunter.py          # IOC correlation against ES data
├── suricata/                # IDS engine config and rule classification
├── zeek/                    # Network Security Monitor config
└── Caddyfile                 # TLS reverse proxy routing
```

---

## 🎯 Zero Trust Principles in Practice

**1. Default-deny by default**
Cilium's `default-deny-all` policy blocks all ingress/egress in the demo namespace before anything else is allowed — nothing is trusted just for being on the network.

**2. Identity-aware access, not IP-based**
Pomerium enforces access per-request based on Keycloak OIDC claims (`groups: admins`, `groups: engineers`) — not source IP or network zone.

**3. Continuous device posture evaluation**
`device_onboard.py` simulates the real NAC flow: RADIUS 802.1X authentication → osquery-style posture scoring (patch level, disk encryption, AV status) → tiered access decision (`FULL ACCESS` / `LIMITED ACCESS` / `REMEDIATION` / `IOT-RESTRICTED`).

**4. Microsegmentation at L3/L4/L7**
Cilium enforces not just "can this pod talk to that pod" but "can this pod send a `GET /api/*` request" — application-layer policy, not just network-layer.

**5. Behavioral anomaly detection**
An Isolation Forest model (unsupervised, no labeled attack data required) scores live traffic patterns and flags deviations from baseline behavior.

---

## 🐛 Real Debugging Wins

These weren't copy-pasted from a guide — they were root-caused independently, with post-mortems written afterward:

- **CoreDNS stuck at `0/1 Ready`** — traced to Cilium's eBPF layer dropping pod-to-host traffic; resolved with a `hostNetwork: true` patch and DNS loop fix.
- **UFW silently breaking overlay networking** — `DEFAULT_FORWARD_POLICY="DROP"` was blocking all Cilium overlay traffic; not documented anywhere obvious, found through systematic elimination.
- **Pomerium OIDC redirect loop** — caused by a missing `offline_access` scope in Keycloak, compounded by a TLS scheme mismatch between Caddy and Pomerium.

---

## ⚠️ Honest Scope Note

This lab distinguishes between what's **live and running** and what's **designed but not deployed**, because overclaiming helps no one:

**Live components:** FreeRADIUS NAC, Isolation Forest anomaly detector, ELK ingestion pipeline, Cilium eBPF policies on k3s, Ansible automation, Pomerium + Keycloak OIDC flow, Tailscale mesh.

**Designed, not deployed:** PacketFence, live MISP threat feed integration, Grafana/Kibana unified posture dashboard, multi-cloud (AWS/Azure) deployment.

---

## 🚀 Getting Started

Each component is self-contained with its own `docker-compose.yml` or config. General order of operations:

```bash
# 1. Identity provider
cd keycloak && docker compose up -d
./create-user.sh && ./create-groups.sh

# 2. ZTNA proxy
cd ../pomerium && docker compose up -d

# 3. SIEM stack
cd ../elk && docker compose up -d

# 4. Network policies (requires an existing k3s cluster with Cilium installed)
kubectl apply -f cilium/zta-network-policies.yaml
kubectl apply -f cilium/zta-cilium-demo.yaml

# 5. Detection stack (via Ansible)
cd ../ansible && ansible-playbook -i inventory.ini deploy_zta_stack.yml
```

> **Note:** This repo ships configuration, not secrets. You'll need your own `.env` with `ELASTIC_PASSWORD`, `POSTGRES_PASSWORD`, `KEYCLOAK_ADMIN_PASSWORD`, and Pomerium's `SHARED_SECRET` / `COOKIE_SECRET` / `IDP_CLIENT_SECRET` before anything will actually start.

---

## 📄 License

This project is shared for educational and portfolio purposes. Feel free to reference the architecture and approach for your own learning.

---

<div align="center">

**Built as a hands-on deep dive into Zero Trust, not a checkbox exercise.**

[GitHub](https://github.com/Aarib26) · [LinkedIn](https://linkedin.com/in/aarib-ali-khan-0b782b322)

</div>
