# ztacloud — DR Secondary Site

Components deployed on ztacloud (100.111.196.121):

- **Flask cloud-app** (`flask/app.py`) — ZTA-protected workload on port 8080. Zero auth; trusts Pomerium identity headers.
- **Filebeat** (`filebeat/filebeat.yml`) — Ships syslog and Suricata eve.json to ztauser ELK on port 5044 over Tailscale.
- **Suricata** — IDS on enp0s3; eve.json picked up by Filebeat.
- **PostgreSQL 15** — Hot standby replica streaming WAL from ztauser's keycloak-db (100.96.17.20:5432). Lag: sub-second.
- **Keycloak warm standby** (`systemd/zta-keycloak-standby.service`) — Installed, disabled. Activates on failover.
- **UFW** — Deny all inbound except tailscale0. Public interface (enp0s3/10.0.2.15) fully closed.

## Failover procedure
Run `failover-identity.sh` on ztauser. RTO ~2 minutes, RPO near-zero.
