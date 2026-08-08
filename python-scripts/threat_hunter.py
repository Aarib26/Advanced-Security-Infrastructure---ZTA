#!/usr/bin/env python3
"""
ZTA Automated Threat Hunter
Runs scheduled retrospective hunts against ELK, triggers Cilium isolation via Ansible.

DYNAMIC BASE DIR (hybrid on-prem+cloud, portable clone location):
  ZTA_BASE_DIR is no longer hardcoded to /home/zta_user/oral_arch. It's
  resolved at import time by walking up from this file's own location
  until an ansible/ directory is found — so this works whether the repo
  is cloned to ~/oral_arch, ~/git_oral_arch/..., a cloud VM's /opt/, or
  anywhere else, without editing the script per-host. Override with the
  ZTA_BASE_DIR env var if the auto-walk ever picks the wrong root.

DYNAMIC ES ENDPOINT: same resolution strategy as zeek_anomaly_detector.py —
  explicit env wins, then co-located check, then Tailscale MagicDNS fallback.
"""

import json
import logging
import os
import socket
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from elasticsearch import Elasticsearch

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


# -----------------------------
# Dynamic base dir resolution
# -----------------------------
def resolve_base_dir() -> Path:
    explicit = os.getenv("ZTA_BASE_DIR")
    if explicit:
        return Path(explicit)

    here = Path(__file__).resolve()
    for candidate in [here.parent, *here.parents]:
        if (candidate / "ansible" / "inventory.ini").exists():
            return candidate

    # Fall back to script's own dir — will fail loudly at ansible-playbook
    # invocation time with a clear "no such file" rather than silently
    # pointing at a nonexistent hardcoded path.
    log.warning("Could not locate ansible/inventory.ini by walking up from %s; "
                "falling back to script directory. Set ZTA_BASE_DIR explicitly if this is wrong.", here)
    return here.parent


ZTA_BASE_DIR = resolve_base_dir()
ANSIBLE_BIN = os.getenv(
    "ZTA_ANSIBLE_BIN",
    str(ZTA_BASE_DIR / "python-scripts" / "ztaenv" / "bin" / "ansible-playbook"),
)
ANSIBLE_INVENTORY = os.getenv("ZTA_ANSIBLE_INVENTORY", "ansible/inventory.ini")
ISOLATION_PLAYBOOK = os.getenv("ZTA_ISOLATION_PLAYBOOK", "ansible/block_ip_cilium.yml")


# -----------------------------
# Dynamic ES endpoint resolution (mirrors zeek_anomaly_detector.py)
# -----------------------------
def resolve_es_host() -> str:
    explicit = os.getenv("ES_HOST")
    if explicit:
        return explicit
    try:
        socket.create_connection(("localhost", 9200), timeout=0.5).close()
        return "http://localhost:9200"
    except OSError:
        pass
    ts_domain = os.getenv("ZTA_TAILSCALE_DOMAIN")
    if ts_domain:
        return f"https://{ts_domain}:9200"
    log.warning("Could not resolve ES host dynamically — falling back to localhost:9200")
    return "http://localhost:9200"


ES_HOST = resolve_es_host()
ES_USER = os.getenv("ELASTIC_USER", "elastic")
ES_PASS = os.getenv("ELASTIC_PASSWORD", "ztaelk26")

ES = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASS), verify_certs=False, request_timeout=120, max_retries=5, retry_on_timeout=True)

HUNT_INTERVAL = int(os.getenv("ZTA_HUNT_INTERVAL", "300"))


# -----------------------------
# Threat Intel — swappable demo feed
# -----------------------------
# Static list kept as a LAB-labeled seed (this is a demo IOC feed, not a
# live threat-intel subscription). Made file-loadable so it's swappable
# without editing source, and so a live feed could be dropped in later
# without changing the hunt logic.
DEFAULT_BAD_IPS = ["198.51.100.1", "203.0.113.42"]
DEFAULT_BAD_DOMAINS = ["malware.example.com", "c2.badactor.net"]


def load_threat_intel() -> tuple[list, list]:
    ioc_path = os.getenv("ZTA_IOC_FEED")
    if ioc_path and os.path.exists(ioc_path):
        try:
            with open(ioc_path) as f:
                data = json.load(f)
            return data.get("bad_ips", DEFAULT_BAD_IPS), data.get("bad_domains", DEFAULT_BAD_DOMAINS)
        except (json.JSONDecodeError, OSError) as e:
            log.warning(f"Could not load IOC feed {ioc_path}, using defaults: {e}")
    return DEFAULT_BAD_IPS, DEFAULT_BAD_DOMAINS


KNOWN_BAD_IPS, KNOWN_BAD_DOMAINS = load_threat_intel()
LATERAL_MOVE_PORTS = [22, 3389, 445, 135, 5985]

already_isolated = set()  # simple in-memory de-dupe, resets on service restart


def utc_now():
    return datetime.now(timezone.utc)


# -----------------------------
# AUTOMATED RESPONSE
# -----------------------------
def trigger_isolation(ip: str, reason: str):
    if ip in already_isolated:
        log.info(f"Skipping isolation for {ip} — already isolated this run ({reason})")
        return

    if not Path(ANSIBLE_BIN).exists():
        log.error(f"Ansible binary not found at {ANSIBLE_BIN} — cannot isolate {ip}. "
                   f"Check ZTA_BASE_DIR / ZTA_ANSIBLE_BIN.")
        return

    log.warning(f"TRIGGERING ISOLATION: {ip} (reason: {reason})")

    try:
        result = subprocess.run(
            [ANSIBLE_BIN, "-i", ANSIBLE_INVENTORY, ISOLATION_PLAYBOOK, "-e", f"target_ip={ip}"],
            cwd=str(ZTA_BASE_DIR),
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode == 0:
            log.info(f"Isolation playbook succeeded for {ip}")
            already_isolated.add(ip)
        else:
            log.error(
                f"Isolation playbook FAILED for {ip} (rc={result.returncode})\n"
                f"stdout: {result.stdout[-1000:]}\n"
                f"stderr: {result.stderr[-1000:]}"
            )
    except subprocess.TimeoutExpired:
        log.error(f"Isolation playbook TIMED OUT for {ip}")
    except Exception as e:
        log.exception(f"Isolation trigger failed for {ip}: {e}")


# -----------------------------
# IOC HUNTING
# -----------------------------
def hunt_ioc_hits(hours_back=24):
    since = (utc_now() - timedelta(hours=hours_back)).isoformat()
    results = []

    for ioc in KNOWN_BAD_IPS:
        resp = ES.search(
            index="zta-logs-*",
            body={
                "query": {"bool": {"must": [
                    {"term": {"src_ip.keyword": ioc}},
                    {"range": {"@timestamp": {"gte": since}}},
                ]}},
                "size": 10,
            },
        )
        hits = resp["hits"]["hits"]
        if hits:
            log.warning(f"IOC HIT: {ioc} → {len(hits)} events")
            results.append({"ioc": ioc, "type": "bad_ip", "hits": len(hits), "time": utc_now().isoformat()})

    return results


# -----------------------------
# LATERAL MOVEMENT HUNT
# -----------------------------
def hunt_lateral_movement():
    since = (utc_now() - timedelta(hours=1)).isoformat()
    findings = []

    resp = ES.search(
        index="zta-logs-*",
        body={
            "size": 0,
            "query": {"bool": {"must": [
                {"terms": {"dest_port": LATERAL_MOVE_PORTS}},
                {"range": {"@timestamp": {"gte": since}}},
            ]}},
            "aggs": {"by_src": {
                "terms": {"field": "src_ip.keyword", "size": 50},
                "aggs": {"unique_dests": {"cardinality": {"field": "dest_ip.keyword"}}},
            }},
        },
    )

    buckets = resp["aggregations"]["by_src"]["buckets"]

    for b in buckets:
        src = b["key"]
        unique_dests = b["unique_dests"]["value"]

        if unique_dests > 3:
            severity = "high" if unique_dests > 10 else "medium"
            log.warning(f"LATERAL MOVEMENT SUSPECTED: {src} → {unique_dests} hosts")

            finding = {
                "src_ip": src,
                "unique_dests": unique_dests,
                "severity": severity,
                "hunt_type": "lateral_movement",
                "detection_time": utc_now().isoformat(),
            }
            ES.index(index=f"zta-hunts-{utc_now().strftime('%Y.%m.%d')}", document=finding)
            findings.append(finding)

    return findings


# -----------------------------
# ML ANOMALY HUNT
# -----------------------------
def hunt_ml_anomalies(hours_back=1):
    since = (utc_now() - timedelta(hours=hours_back)).isoformat()
    findings = []

    resp = ES.search(
        index="zta-ml-anomalies-*",
        body={
            "size": 50,
            "query": {"bool": {"must": [
                {"term": {"severity": "high"}},
                {"range": {"detection_time": {"gte": since}}},
            ]}},
        },
    )

    hits = resp["hits"]["hits"]

    for hit in hits:
        source = hit["_source"]
        src_ip = source.get("id.orig_h")

        # Ignore Tailscale, local host, and IPv6 link-local addresses —
        # these ranges are structural (not deployment-specific), so this
        # stays a constant rather than becoming an env var.
        if src_ip and not src_ip.startswith(("100.", "127.", "fe80:")):
            log.warning(f"ML ANOMALY HIT: {src_ip} (Score: {source.get('anomaly_score')})")
            findings.append({"src_ip": src_ip, "type": "ml_anomaly_high"})

    return findings


# -----------------------------
# MAIN LOOP
# -----------------------------
def run_scheduled_hunts():
    log.info(f"Threat Hunter started ({HUNT_INTERVAL}s cycle) — ES={ES_HOST}, "
             f"base_dir={ZTA_BASE_DIR}, ansible_bin={ANSIBLE_BIN}")

    while True:
        log.info("=== New Hunt Cycle ===")

        try:
            ioc = hunt_ioc_hits()
            lateral = hunt_lateral_movement()
            ml_anomalies = hunt_ml_anomalies()

            log.info(f"Cycle Complete → IOC: {len(ioc)} | Lateral: {len(lateral)} | ML: {len(ml_anomalies)}")

            for finding in ioc:
                trigger_isolation(finding["ioc"], reason="ioc_hit")
            for finding in lateral:
                trigger_isolation(finding["src_ip"], reason="lateral_movement")
            for finding in ml_anomalies:
                trigger_isolation(finding["src_ip"], reason="high_ml_anomaly")

        except Exception as e:
            log.exception(f"Hunt cycle failed: {e}")

        time.sleep(HUNT_INTERVAL)


if __name__ == "__main__":
    run_scheduled_hunts()
