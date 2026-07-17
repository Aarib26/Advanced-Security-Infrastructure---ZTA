#!/usr/bin/env python3
"""
ZTA ML Anomaly Detector — Isolation Forest on Zeek conn.log
Detects anomalous east-west traffic and optionally sends alerts to Elasticsearch.
"""

import time
import logging
from datetime import datetime, UTC
import os

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from elasticsearch import Elasticsearch

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

# Use the real path from your Zeek install
ZEEK_CONN_LOG = "/opt/zeek/logs/current/conn.log"

ES_HOST = "http://localhost:9200"
ES_USER = "elastic"
ES_PASS=os.getenv("ES_PASS")

CONTAMINATION = 0.15
SCAN_INTERVAL = 60


def parse_zeek_conn_log(path: str, max_lines: int = 5000) -> pd.DataFrame:
    records = []
    fields = None

    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()

                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    continue

                if line.startswith("#") or not line:
                    continue

                if fields:
                    vals = line.split("\t")
                    if len(vals) == len(fields):
                        records.append(dict(zip(fields, vals)))

                if len(records) >= max_lines:
                    break

    except FileNotFoundError:
        log.warning(f"Zeek log not found: {path}")
        return pd.DataFrame()
    except PermissionError:
        log.error(f"Permission denied reading: {path}")
        return pd.DataFrame()

    return pd.DataFrame(records)


def to_num(series: pd.Series) -> pd.Series:
    return pd.to_numeric(series.replace("-", 0), errors="coerce").fillna(0)


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

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

    return df[
        [
            "duration",
            "orig_bytes",
            "resp_bytes",
            "orig_pkts",
            "resp_pkts",
            "proto_enc",
            "state_enc",
            "bytes_ratio",
            "pkts_per_sec",
        ]
    ]


def send_to_elasticsearch(es: Elasticsearch, anomalies: list):
    for doc in anomalies:
        es.index(
            index=f"zta-ml-anomalies-{datetime.now(UTC).strftime('%Y.%m.%d')}",
            document=doc,
        )

    if anomalies:
        log.info(f"Indexed {len(anomalies)} anomalies to Elasticsearch")


def run_detection():
    es = Elasticsearch(
        ES_HOST,
        basic_auth=(ES_USER, ES_PASS),
        verify_certs=False
    )

    model = IsolationForest(
        contamination=CONTAMINATION,
        random_state=42,
        n_estimators=200
    )

    log.info("ZTA ML Anomaly Detector started")

    while True:
        try:
            df_raw = parse_zeek_conn_log(ZEEK_CONN_LOG)

            if df_raw.empty or len(df_raw) < 10:
                log.info("Not enough Zeek data yet, waiting...")
                time.sleep(SCAN_INTERVAL)
                continue

            features = extract_features(df_raw.copy())

            model.fit(features)
            scores = model.decision_function(features)
            predictions = model.predict(features)

            anomaly_mask = predictions == -1
            anomaly_count = int(anomaly_mask.sum())

            log.info(f"Scanned {len(df_raw)} connections, found {anomaly_count} anomalies")

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

                cols = [c for c in ["id.orig_h", "id.resp_h", "id.resp_p", "proto", "orig_bytes", "resp_bytes", "anomaly_score", "severity"] if c in anomaly_rows.columns]
                if cols:
                    print("\n=== TOP ANOMALIES ===")
                    print(anomaly_rows.nsmallest(3, "anomaly_score")[cols].to_string(index=False))

        except Exception as e:
            log.error(f"Detection error: {e}")

        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    run_detection()


CONTAMINATION = 0.15
SCAN_INTERVAL = 60


def parse_zeek_conn_log(path: str, max_lines: int = 5000) -> pd.DataFrame:
    records = []
    fields = None

    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()

                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    continue

                if line.startswith("#") or not line:
                    continue

                if fields:
                    vals = line.split("\t")
                    if len(vals) == len(fields):
                        records.append(dict(zip(fields, vals)))

                if len(records) >= max_lines:
                    break

    except FileNotFoundError:
        log.warning(f"Zeek log not found: {path}")
        return pd.DataFrame()
    except PermissionError:
        log.error(f"Permission denied reading: {path}")
        return pd.DataFrame()

    return pd.DataFrame(records)


def to_num(series: pd.Series) -> pd.Series:
    return pd.to_numeric(series.replace("-", 0), errors="coerce").fillna(0)


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

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

    return df[
        [
            "duration",
            "orig_bytes",
            "resp_bytes",
            "orig_pkts",
            "resp_pkts",
            "proto_enc",
            "state_enc",
            "bytes_ratio",
            "pkts_per_sec",
        ]
    ]


def send_to_elasticsearch(es: Elasticsearch, anomalies: list):
    for doc in anomalies:
        es.index(
            index=f"zta-ml-anomalies-{datetime.now(UTC).strftime('%Y.%m.%d')}",
            document=doc,
        )

    if anomalies:
        log.info(f"Indexed {len(anomalies)} anomalies to Elasticsearch")


def run_detection():
    es = Elasticsearch(
        ES_HOST,
        basic_auth=(ES_USER, ES_PASS),
        verify_certs=False
    )

    model = IsolationForest(
        contamination=CONTAMINATION,
        random_state=42,
        n_estimators=200
    )

    log.info("ZTA ML Anomaly Detector started")

    while True:
        try:
            df_raw = parse_zeek_conn_log(ZEEK_CONN_LOG)

            if df_raw.empty or len(df_raw) < 10:
                log.info("Not enough Zeek data yet, waiting...")
                time.sleep(SCAN_INTERVAL)
                continue

            features = extract_features(df_raw.copy())

            model.fit(features)
            scores = model.decision_function(features)
            predictions = model.predict(features)

            anomaly_mask = predictions == -1
            anomaly_count = int(anomaly_mask.sum())

            log.info(f"Scanned {len(df_raw)} connections, found {anomaly_count} anomalies")

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

                cols = [c for c in ["id.orig_h", "id.resp_h", "id.resp_p", "proto", "orig_bytes", "resp_bytes", "anomaly_score", "severity"] if c in anomaly_rows.columns]
                if cols:
                    print("\n=== TOP ANOMALIES ===")
                    print(anomaly_rows.nsmallest(3, "anomaly_score")[cols].to_string(index=False))

        except Exception as e:
            log.error(f"Detection error: {e}")

        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    run_detection()

