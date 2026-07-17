#!/usr/bin/env python3
"""
ZTA Automated Threat Hunter — Phase 7
Runs scheduled retrospective hunts against ELK using IOC feeds
"""

import os
import time
import subprocess
import logging
from datetime import datetime, timedelta, timezone
from elasticsearch import Elasticsearch

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

log = logging.getLogger(__name__)

ES_USER = os.getenv("ELASTIC_USER", "elastic")
ES_PASS = os.getenv("ELASTIC_PASSWORD", "ztaelk26")

# Elasticsearch connection
ES = Elasticsearch(
    "http://localhost:9200",
    basic_auth=(ES_USER, ES_PASS)
)

# -----------------------------
# Threat Intel (static demo feed)
# -----------------------------
KNOWN_BAD_IPS = [
    "198.51.100.1",
    "203.0.113.42",
]

KNOWN_BAD_DOMAINS = [
    "malware.example.com",
    "c2.badactor.net"
]

LATERAL_MOVE_PORTS = [22, 3389, 445, 135, 5985]

# -----------------------------
# Automated response config
# -----------------------------
ZTA_BASE_DIR = "/home/zta_user/oral_arch"
ANSIBLE_BIN = f"{ZTA_BASE_DIR}/python-scripts/ztaenv/bin/ansible-playbook"
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

    log.warning(f"TRIGGERING ISOLATION: {ip} (reason: {reason})")

    try:
        result = subprocess.run(
            [
                ANSIBLE_BIN,
                "-i", "ansible/inventory.ini",
                "ansible/block_ip_cilium.yml",
                "-e", f"target_ip={ip}"
            ],
            cwd=ZTA_BASE_DIR,
            capture_output=True,
            text=True,
            timeout=60
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
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"src_ip.keyword": ioc}},
                            {"range": {"@timestamp": {"gte": since}}}
                        ]
                    }
                },
                "size": 10
            }
        )

        hits = resp["hits"]["hits"]

        if hits:
            log.warning(f"IOC HIT: {ioc} → {len(hits)} events")
            results.append({
                "ioc": ioc,
                "type": "bad_ip",
                "hits": len(hits),
                "time": utc_now().isoformat()
            })

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
            "query": {
                "bool": {
                    "must": [
                        {"terms": {"dest_port": LATERAL_MOVE_PORTS}},
                        {"range": {"@timestamp": {"gte": since}}}
                    ]
                }
            },
            "aggs": {
                "by_src": {
                    "terms": {"field": "src_ip.keyword", "size": 50},
                    "aggs": {
                        "unique_dests": {
                            "cardinality": {"field": "dest_ip.keyword"}
                        }
                    }
                }
            }
        }
    )

    buckets = resp["aggregations"]["by_src"]["buckets"]

    for b in buckets:
        src = b["key"]
        unique_dests = b["unique_dests"]["value"]

        if unique_dests > 3:
            severity = "high" if unique_dests > 10 else "medium"

            log.warning(
                f"LATERAL MOVEMENT SUSPECTED: {src} → {unique_dests} hosts"
            )

            finding = {
                "src_ip": src,
                "unique_dests": unique_dests,
                "severity": severity,
                "hunt_type": "lateral_movement",
                "detection_time": utc_now().isoformat()
            }

            ES.index(
                index=f"zta-hunts-{utc_now().strftime('%Y.%m.%d')}",
                document=finding
            )

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
            "query": {
                "bool": {
                    "must": [
                        {"term": {"severity": "high"}},
                        {"range": {"detection_time": {"gte": since}}}
                    ]
                }
            }
        }
    )

    hits = resp["hits"]["hits"]

    for hit in hits:
        source = hit["_source"]
        src_ip = source.get("id.orig_h")

        # Ignore Tailscale, local host, and IPv6 link-local addresses
        if src_ip and not src_ip.startswith(("100.", "127.", "fe80:")):
            log.warning(f"ML ANOMALY HIT: {src_ip} (Score: {source.get('anomaly_score')})")
            findings.append({
                "src_ip": src_ip,
                "type": "ml_anomaly_high"
            })
    return findings

# -----------------------------
# MAIN LOOP
# -----------------------------
def run_scheduled_hunts():
    log.info("Threat Hunter started (5 min cycle)")

    while True:
        log.info("=== New Hunt Cycle ===")

        try:
            ioc = hunt_ioc_hits()
            lateral = hunt_lateral_movement()
            ml_anomalies = hunt_ml_anomalies() # ADDED

            log.info(
                f"Cycle Complete → IOC: {len(ioc)} | Lateral: {len(lateral)} | ML: {len(ml_anomalies)}"
            )

            for finding in ioc:
                trigger_isolation(finding["ioc"], reason="ioc_hit")

            for finding in lateral:
                trigger_isolation(finding["src_ip"], reason="lateral_movement")
                
            # ADDED
            for finding in ml_anomalies:
                trigger_isolation(finding["src_ip"], reason="high_ml_anomaly")

        except Exception as e:
            log.exception(f"Hunt cycle failed: {e}")

        time.sleep(300)

if __name__ == "__main__":
    run_scheduled_hunts()
