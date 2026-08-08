#!/usr/bin/env python3
"""
ZTA ML Anomaly Detector — Isolation Forest on Zeek conn.log
Detects anomalous east-west traffic and sends alerts to Elasticsearch.

DYNAMIC SOURCE DISCOVERY & MODEL PERSISTENCE:
  - Globs all Zeek logs (live and historical).
  - Separates Training and Inference lifecycles.
  - If no model is found, ingests ALL historical (.gz) and live (.log) data,
    trains the baseline, and saves it to disk (model.pkl). Active attacks
    are evaluated against this frozen baseline and cannot poison the model.
"""

import glob
import gzip
import json
import logging
import os
import pickle
import socket
import time
from datetime import datetime, UTC
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from elasticsearch import Elasticsearch

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# -----------------------------
# Configuration & Discovery
# -----------------------------
DEFAULT_GLOBS = [
    "/opt/zeek/spool/*/conn.log",
    "/opt/zeek/logs/current/conn.log",
    "/opt/zeek/logs/frontend/conn.log",
    "/opt/zeek/logs/database/conn.log",
    "/opt/zeek/logs/attacker/conn.log",
]
ZEEK_SPOOL_GLOBS = os.getenv("ZEEK_SPOOL_GLOBS")
SPOOL_GLOBS = ZEEK_SPOOL_GLOBS.split(":") if ZEEK_SPOOL_GLOBS else DEFAULT_GLOBS

# History globs for building the persistent baseline
HISTORY_GLOBS = ["/opt/zeek/logs/202*/*conn*.log.gz"]

NAC_LOG_PATH = os.getenv("ZTA_NAC_LOG", "/var/log/zta-nac.log")
MODEL_FILE = Path(__file__).parent / "zta_iforest_model.pkl"

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

CONTAMINATION = float(os.getenv("ZTA_ML_CONTAMINATION", "0.15"))
SCAN_INTERVAL = int(os.getenv("ZTA_ML_SCAN_INTERVAL", "60"))
MAX_LINES_PER_SOURCE = int(os.getenv("ZTA_ML_MAX_LINES", "10000"))

# -----------------------------
# Discovery & Parsing
# -----------------------------
def discover_conn_logs(patterns: list) -> list[dict]:
    sources = []
    seen = set()
    for pattern in patterns:
        for path in glob.glob(pattern):
            resolved_path = Path(path).resolve()
            resolved = str(resolved_path)
            if resolved in seen:
                continue
            seen.add(resolved)
            source_name = resolved_path.parent.name
            sources.append({"path": path, "source_name": source_name, "source_type": "k8s-pod"})
    return sources

def load_nac_device_context() -> dict:
    context = {}
    if not os.path.exists(NAC_LOG_PATH):
        return context
    try:
        with open(NAC_LOG_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                device_id = entry.get("device_id")
                if device_id:
                    context[device_id] = entry
    except (PermissionError, OSError) as e:
        log.warning(f"Could not read NAC log at {NAC_LOG_PATH}: {e}")
    return context

def parse_zeek_conn_log(path: str, source_name: str, max_lines: int = MAX_LINES_PER_SOURCE) -> pd.DataFrame:
    records = []
    try:
        open_func = gzip.open if path.endswith(".gz") else open
        mode = "rt" if path.endswith(".gz") else "r"
        with open_func(path, mode) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if "orig_ip_bytes" in record and "orig_bytes" not in record:
                    record["orig_bytes"] = record["orig_ip_bytes"]
                if "resp_ip_bytes" in record and "resp_bytes" not in record:
                    record["resp_bytes"] = record["resp_ip_bytes"]

                record["_source_name"] = source_name
                records.append(record)

                if len(records) >= max_lines:
                    break
    except FileNotFoundError:
        log.warning(f"Zeek log disappeared mid-cycle: {path}")
        return pd.DataFrame()
    except PermissionError:
        log.error(f"Permission denied reading: {path}")
        return pd.DataFrame()
    except Exception as e:
        log.error(f"Error reading {path}: {e}")
        return pd.DataFrame()

    return pd.DataFrame(records)

def collect_all_sources(sources: list) -> pd.DataFrame:
    if not sources:
        return pd.DataFrame()

    frames = []
    for src in sources:
        df = parse_zeek_conn_log(src["path"], src["source_name"])
        if not df.empty:
            frames.append(df)

    if not frames:
        return pd.DataFrame()

    combined = pd.concat(frames, ignore_index=True)
    return combined

def enrich_with_nac_context(df: pd.DataFrame, nac_context: dict) -> pd.DataFrame:
    if df.empty or not nac_context:
        return df
    df["byod_context_available"] = bool(nac_context)
    df["byod_devices_seen"] = ",".join(nac_context.keys())
    return df

# -----------------------------
# Feature Engineering Lifecycle
# -----------------------------
def to_num(series: pd.Series) -> pd.Series:
    return pd.to_numeric(series.replace("-", 0), errors="coerce").fillna(0)

def extract_features_train(df: pd.DataFrame):
    for col in ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]:
        if col in df.columns:
            df[col] = to_num(df[col])
        else:
            df[col] = 0

    proto_series = df["proto"] if "proto" in df.columns else pd.Series(["unknown"] * len(df))
    state_series = df["conn_state"] if "conn_state" in df.columns else pd.Series(["OTH"] * len(df))

    le_proto = LabelEncoder()
    le_state = LabelEncoder()

    df["proto_enc"] = le_proto.fit_transform(proto_series.fillna("unknown").astype(str))
    df["state_enc"] = le_state.fit_transform(state_series.fillna("OTH").astype(str))

    total_bytes = df["orig_bytes"] + df["resp_bytes"] + 1
    df["bytes_ratio"] = df["orig_bytes"] / total_bytes
    df["pkts_per_sec"] = (df["orig_pkts"] + df["resp_pkts"]) / (df["duration"] + 0.001)

    features = df[["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "proto_enc", "state_enc", "bytes_ratio", "pkts_per_sec"]]
    return features, le_proto, le_state

def extract_features_infer(df: pd.DataFrame, le_proto, le_state):
    for col in ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]:
        if col in df.columns:
            df[col] = to_num(df[col])
        else:
            df[col] = 0

    proto_series = df["proto"] if "proto" in df.columns else pd.Series(["unknown"] * len(df))
    state_series = df["conn_state"] if "conn_state" in df.columns else pd.Series(["OTH"] * len(df))

    proto_dict = {cls: idx for idx, cls in enumerate(le_proto.classes_)}
    state_dict = {cls: idx for idx, cls in enumerate(le_state.classes_)}

    df["proto_enc"] = proto_series.fillna("unknown").astype(str).map(proto_dict).fillna(-1)
    df["state_enc"] = state_series.fillna("OTH").astype(str).map(state_dict).fillna(-1)

    total_bytes = df["orig_bytes"] + df["resp_bytes"] + 1
    df["bytes_ratio"] = df["orig_bytes"] / total_bytes
    df["pkts_per_sec"] = (df["orig_pkts"] + df["resp_pkts"]) / (df["duration"] + 0.001)

    return df[["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "proto_enc", "state_enc", "bytes_ratio", "pkts_per_sec"]]

def send_to_elasticsearch(es: Elasticsearch, anomalies: list):
    for doc in anomalies:
        clean_doc = {
            k: (None if isinstance(v, float) and (v != v or v in (float("inf"), float("-inf"))) else v)
            for k, v in doc.items()
        }
        es.index(index=f"zta-ml-anomalies-{datetime.now(UTC).strftime('%Y.%m.%d')}", document=clean_doc)
    if anomalies:
        log.info(f"Indexed {len(anomalies)} anomalies to Elasticsearch")

# -----------------------------
# Main Engine
# -----------------------------
def run_detection():
    es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASS), verify_certs=False)
    log.info(f"ZTA ML Anomaly Detector started — ES={ES_HOST}")

    while True:
        try:
            nac_context = load_nac_device_context()

            # ==========================================
            # TRAINING MODE
            # ==========================================
            if not MODEL_FILE.exists():
                log.warning(f"No frozen model at {MODEL_FILE}. Entering TRAINING MODE...")
                train_globs = SPOOL_GLOBS + HISTORY_GLOBS
                sources = discover_conn_logs(train_globs)
                df_raw = collect_all_sources(sources)

                if df_raw.empty:
                    log.info("No data found for training. Waiting...")
                    time.sleep(SCAN_INTERVAL)
                    continue

                df_raw = enrich_with_nac_context(df_raw, nac_context)

                # Baseline sanitation
                if "proto" in df_raw.columns:
                    df_raw = df_raw[df_raw["proto"] != "icmp"]
                if "id.resp_h" in df_raw.columns:
                    df_raw = df_raw[~df_raw["id.resp_h"].astype(str).str.startswith("ff02::")]
                if "id.orig_h" in df_raw.columns:
                    df_raw = df_raw[~df_raw["id.orig_h"].astype(str).str.startswith("fe80::")]

                if len(df_raw) < 10:
                    log.info(f"Only {len(df_raw)} clean connections available for training. Waiting...")
                    time.sleep(SCAN_INTERVAL)
                    continue

                log.info(f"Training persistent baseline on {len(df_raw)} historical connections...")
                features, le_proto, le_state = extract_features_train(df_raw.copy())

                model = IsolationForest(contamination=CONTAMINATION, random_state=42, n_estimators=200)
                model.fit(features)

                with open(MODEL_FILE, "wb") as f:
                    pickle.dump({
                        "model": model,
                        "le_proto": le_proto,
                        "le_state": le_state
                    }, f)

                log.info(f"Model successfully trained and saved to {MODEL_FILE}. BASELINE LOCKED.")
                time.sleep(5)
                continue

            # ==========================================
            # INFERENCE MODE
            # ==========================================
            with open(MODEL_FILE, "rb") as f:
                saved = pickle.load(f)
                model = saved["model"]
                le_proto = saved["le_proto"]
                le_state = saved["le_state"]

            sources = discover_conn_logs(SPOOL_GLOBS) # Live logs only
            df_raw = collect_all_sources(sources)

            if df_raw.empty:
                log.info("No new live Zeek data. Waiting...")
                time.sleep(SCAN_INTERVAL)
                continue

            df_raw = enrich_with_nac_context(df_raw, nac_context)

            # Baseline sanitation
            if "proto" in df_raw.columns:
                df_raw = df_raw[df_raw["proto"] != "icmp"]
            if "id.resp_h" in df_raw.columns:
                df_raw = df_raw[~df_raw["id.resp_h"].astype(str).str.startswith("ff02::")]
            if "id.orig_h" in df_raw.columns:
                df_raw = df_raw[~df_raw["id.orig_h"].astype(str).str.startswith("fe80::")]

            if df_raw.empty:
                time.sleep(SCAN_INTERVAL)
                continue

            features = extract_features_infer(df_raw.copy(), le_proto, le_state)
            scores = model.decision_function(features)
            predictions = model.predict(features)

            anomaly_mask = predictions == -1
            anomaly_count = int(anomaly_mask.sum())

            log.info(f"INFERENCE: Scanned {len(df_raw)} live connections, found {anomaly_count} anomalies")

            if anomaly_count > 0:
                anomaly_rows = df_raw[anomaly_mask].copy()
                anomaly_rows["anomaly_score"] = scores[anomaly_mask]
                anomaly_rows["detection_time"] = datetime.now(UTC).isoformat()
                anomaly_rows["detector"] = "isolation_forest"
                anomaly_rows["severity"] = anomaly_rows["anomaly_score"].apply(
                    lambda s: "high" if s < -0.15 else ("medium" if s < -0.08 else "low")
                )

                docs = anomaly_rows.to_dict(orient="records")
                send_to_elasticsearch(es, docs)

                cols = [c for c in [
                    "_source_name", "id.orig_h", "id.resp_h", "id.resp_p",
                    "proto", "orig_bytes", "resp_bytes", "anomaly_score", "severity",
                ] if c in anomaly_rows.columns]
                if cols:
                    print("\n=== TOP ANOMALIES ===")
                    print(anomaly_rows.nsmallest(3, "anomaly_score")[cols].to_string(index=False))

        except Exception as e:
            log.error(f"Detection error: {e}")

        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    run_detection()
