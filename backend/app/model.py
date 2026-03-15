# # import torch

# # labels = ["Normal","DoS Attack","Port Scan"]

# # def predict(packet_rate, port):

# #     if packet_rate > 800:
# #         return "DoS Attack"

# #     if port < 100 and packet_rate > 200:
# #         return "Port Scan"

# #     return "Normal"

# import numpy as np
# import pandas as pd
# from sklearn.ensemble import IsolationForest
# from sklearn.preprocessing import StandardScaler
# import joblib
# import os

# # ── Feature Engineering ──────────────────────────────────────────────────────

# # Ports associated with high-risk / commonly attacked services
# HIGH_RISK_PORTS = {21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 1433, 3306, 3389, 8080, 8443}
# CRITICAL_PORTS  = {22, 23, 3389, 445, 1433}   # SSH, Telnet, RDP, SMB, MSSQL

# def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
#     """
#     Takes raw log DataFrame and returns enriched feature matrix.
#     Raw columns expected: src_ip, port, packet_rate, packet_size
#     """
#     feat = pd.DataFrame()

#     feat["packet_rate"]       = df["packet_rate"].astype(float)
#     feat["packet_size"]       = df["packet_size"].astype(float)
#     feat["port"]              = df["port"].astype(float)

#     # Risk score: well-known dangerous ports get higher weight
#     feat["port_risk"]         = df["port"].apply(
#         lambda p: 2.0 if p in CRITICAL_PORTS else (1.0 if p in HIGH_RISK_PORTS else 0.0)
#     )

#     # Interaction: high packet rate on a risky port is a strong signal
#     feat["rate_x_risk"]       = feat["packet_rate"] * (feat["port_risk"] + 1)

#     # Packet size anomaly: very small or very large packets are suspicious
#     feat["size_anomaly"]      = (feat["packet_size"] < 60).astype(float) + \
#                                 (feat["packet_size"] > 1400).astype(float)

#     # Ratio of packet rate to size — DoS often has tiny packets at high rate
#     feat["rate_size_ratio"]   = feat["packet_rate"] / (feat["packet_size"] + 1)

#     return feat


# # ── Model ─────────────────────────────────────────────────────────────────────

# _MODEL_PATH  = os.path.join(os.path.dirname(__file__), "isolation_forest.pkl")
# _SCALER_PATH = os.path.join(os.path.dirname(__file__), "scaler.pkl")

# _clf     = None
# _scaler  = None


# def _load_or_train():
#     """Load persisted model or train a fresh one on synthetic baseline data."""
#     global _clf, _scaler

#     if os.path.exists(_MODEL_PATH) and os.path.exists(_SCALER_PATH):
#         _clf    = joblib.load(_MODEL_PATH)
#         _scaler = joblib.load(_SCALER_PATH)
#         return

#     # Synthetic "normal" traffic to bootstrap the unsupervised model.
#     # In production: replace with a clean, labelled baseline CSV.
#     rng = np.random.default_rng(42)
#     n   = 2000

#     normal_data = pd.DataFrame({
#         "src_ip":      ["192.168.1.1"] * n,
#         "port":        rng.choice([22, 80, 443, 8080, 3306], size=n).tolist(),
#         "packet_rate": rng.normal(loc=200, scale=60, size=n).clip(10, 600).tolist(),
#         "packet_size": rng.normal(loc=512, scale=150, size=n).clip(40, 1500).tolist(),
#     })

#     feats   = engineer_features(normal_data)
#     scaler  = StandardScaler()
#     X       = scaler.fit_transform(feats)

#     clf = IsolationForest(
#         n_estimators=200,
#         contamination=0.05,   # expect ~5 % anomalies in real traffic
#         random_state=42,
#         max_samples="auto",
#     )
#     clf.fit(X)

#     joblib.dump(clf,    _MODEL_PATH)
#     joblib.dump(scaler, _SCALER_PATH)

#     _clf    = clf
#     _scaler = scaler


# def _classify_anomaly(row: pd.Series, score: float) -> str:
#     """
#     Map IsolationForest anomaly score + heuristics → human-readable label.
#     score < 0  ⟹ anomaly  (more negative = more anomalous)
#     """
#     port        = int(row["port"])
#     packet_rate = float(row["packet_rate"])
#     packet_size = float(row["packet_size"])

#     if score >= 0:
#         return "Normal"

#     # DoS / DDoS: flood of packets regardless of size
#     if packet_rate > 700:
#         return "DoS Attack"

#     # Port scan: many different low-numbered ports, low packet size
#     if port < 1024 and packet_size < 120 and packet_rate > 150:
#         return "Port Scan"

#     # Brute-force: sustained moderate rate on auth ports
#     if port in CRITICAL_PORTS and 100 < packet_rate < 700:
#         return "Brute-Force Attempt"

#     # Exfiltration: large packets at moderate rate on non-standard ports
#     if packet_size > 1200 and port not in HIGH_RISK_PORTS:
#         return "Data Exfiltration"

#     return "Suspicious Activity"


# def predict_row(packet_rate: float, port: int, packet_size: float = 512.0) -> dict:
#     """
#     Predict a single log row.
#     Returns { prediction, threat_level, anomaly_score, confidence }
#     """
#     _load_or_train()

#     row = pd.Series({"src_ip": "0.0.0.0", "port": port,
#                      "packet_rate": packet_rate, "packet_size": packet_size})
#     df_row = pd.DataFrame([row])

#     feats = engineer_features(df_row)
#     X     = _scaler.transform(feats)

#     raw_score = float(_clf.decision_function(X)[0])   # higher = more normal
#     label     = _classify_anomaly(row, raw_score)

#     # Normalise score to [0, 1] confidence (approx)
#     confidence = min(max(abs(raw_score) * 2, 0.0), 1.0)

#     threat_map = {
#         "Normal":               "low",
#         "Suspicious Activity":  "medium",
#         "Port Scan":            "medium",
#         "Brute-Force Attempt":  "high",
#         "Data Exfiltration":    "high",
#         "DoS Attack":           "critical",
#     }

#     return {
#         "prediction":    label,
#         "threat_level":  threat_map.get(label, "medium"),
#         "anomaly_score": round(raw_score, 4),
#         "confidence":    round(confidence, 3),
#     }


# def predict_dataframe(df: pd.DataFrame) -> list[dict]:
#     """Vectorised prediction for a full CSV — fast."""
#     _load_or_train()

#     feats = engineer_features(df)
#     X     = _scaler.transform(feats)
#     scores = _clf.decision_function(X)

#     results = []
#     for i, (_, row) in enumerate(df.iterrows()):
#         result = _classify_anomaly(row, scores[i])
#         confidence = min(max(abs(float(scores[i])) * 2, 0.0), 1.0)
#         threat_map = {
#             "Normal":               "low",
#             "Suspicious Activity":  "medium",
#             "Port Scan":            "medium",
#             "Brute-Force Attempt":  "high",
#             "Data Exfiltration":    "high",
#             "DoS Attack":           "critical",
#         }
#         results.append({
#             "prediction":    result,
#             "threat_level":  threat_map.get(result, "medium"),
#             "anomaly_score": round(float(scores[i]), 4),
#             "confidence":    round(confidence, 3),
#         })

#     return results

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os

# ── Feature Engineering ──────────────────────────────────────────────────────

HIGH_RISK_PORTS = {21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 1433, 3306, 3389, 8080, 8443}
CRITICAL_PORTS  = {22, 23, 3389, 445, 1433}

def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Takes raw log DataFrame and returns enriched feature matrix.
    Raw columns expected: src_ip, port, packet_rate, packet_size
    """
    feat = pd.DataFrame()

    feat["packet_rate"]     = df["packet_rate"].astype(float)
    feat["packet_size"]     = df["packet_size"].astype(float)
    feat["port"]            = df["port"].astype(float)

    feat["port_risk"]       = df["port"].apply(
        lambda p: 2.0 if p in CRITICAL_PORTS else (1.0 if p in HIGH_RISK_PORTS else 0.0)
    )
    feat["rate_x_risk"]     = feat["packet_rate"] * (feat["port_risk"] + 1)
    feat["size_anomaly"]    = (feat["packet_size"] < 60).astype(float) + \
                              (feat["packet_size"] > 1400).astype(float)
    feat["rate_size_ratio"] = feat["packet_rate"] / (feat["packet_size"] + 1)

    return feat


# ── Persistence ───────────────────────────────────────────────────────────────

_MODEL_PATH  = os.path.join(os.path.dirname(__file__), "isolation_forest.pkl")
_SCALER_PATH = os.path.join(os.path.dirname(__file__), "scaler.pkl")

_clf    = None
_scaler = None


def _load_or_train():
    """Load persisted model or bootstrap on synthetic normal traffic."""
    global _clf, _scaler

    if os.path.exists(_MODEL_PATH) and os.path.exists(_SCALER_PATH):
        _clf    = joblib.load(_MODEL_PATH)
        _scaler = joblib.load(_SCALER_PATH)
        return

    rng = np.random.default_rng(42)
    n   = 2000

    normal_data = pd.DataFrame({
        "src_ip":      ["192.168.1.1"] * n,
        "port":        rng.choice([22, 80, 443, 8080, 3306], size=n).tolist(),
        "packet_rate": rng.normal(loc=200, scale=60, size=n).clip(10, 600).tolist(),
        "packet_size": rng.normal(loc=512, scale=150, size=n).clip(40, 1500).tolist(),
    })

    feats  = engineer_features(normal_data)
    scaler = StandardScaler()
    X      = scaler.fit_transform(feats)

    clf = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42,
        max_samples="auto",
    )
    clf.fit(X)

    joblib.dump(clf,    _MODEL_PATH)
    joblib.dump(scaler, _SCALER_PATH)

    _clf    = clf
    _scaler = scaler


# ── Threat Classification ─────────────────────────────────────────────────────

_THREAT_MAP = {
    "Normal":               "low",
    "Suspicious Activity":  "medium",
    "Port Scan":            "medium",
    "Brute-Force Attempt":  "high",
    "Data Exfiltration":    "high",
    "DoS Attack":           "critical",
}

def _classify_anomaly(row: pd.Series, score: float) -> str:
    port        = int(row["port"])
    packet_rate = float(row["packet_rate"])
    packet_size = float(row["packet_size"])

    if score >= 0:
        return "Normal"
    if packet_rate > 700:
        return "DoS Attack"
    if port < 1024 and packet_size < 120 and packet_rate > 150:
        return "Port Scan"
    if port in CRITICAL_PORTS and 100 < packet_rate < 700:
        return "Brute-Force Attempt"
    if packet_size > 1200 and port not in HIGH_RISK_PORTS:
        return "Data Exfiltration"
    return "Suspicious Activity"


def _make_result(row: pd.Series, score: float) -> dict:
    label      = _classify_anomaly(row, score)
    confidence = min(max(abs(score) * 2, 0.0), 1.0)
    return {
        "prediction":        label,
        "threat_level":      _THREAT_MAP.get(label, "medium"),
        "anomaly_score":     round(float(score), 4),
        "threat_confidence": round(confidence, 3),
    }


# ── Public API ────────────────────────────────────────────────────────────────

def predict_batch(df: pd.DataFrame) -> list[dict]:
    """Vectorised prediction for a full DataFrame — fast path used by all routes."""
    _load_or_train()
    feats  = engineer_features(df)
    X      = _scaler.transform(feats)
    scores = _clf.decision_function(X)

    return [_make_result(row, scores[i]) for i, (_, row) in enumerate(df.iterrows())]


# kept for backwards-compat / single-row callers
def predict_row(packet_rate: float, port: int, packet_size: float = 512.0) -> dict:
    row = pd.Series({"src_ip": "0.0.0.0", "port": port,
                     "packet_rate": packet_rate, "packet_size": packet_size})
    return predict_batch(pd.DataFrame([row]))[0]


def predict_dataframe(df: pd.DataFrame) -> list[dict]:
    """Alias kept for any legacy callers."""
    return predict_batch(df)


# ── Retraining ────────────────────────────────────────────────────────────────

LABEL_COLUMN = "label"

def retrain(df: pd.DataFrame) -> dict:
    """
    Retrain IsolationForest on a labelled CSV and overwrite persisted artefacts.

    The CSV must contain the four raw feature columns plus an optional `label`
    column (Normal, DoS Attack, Port Scan, Brute-Force Attempt,
    Data Exfiltration, Suspicious Activity).  The label column is used only to
    compute a contamination estimate; IsolationForest itself is unsupervised.

    Returns a summary dict with training statistics.
    """
    global _clf, _scaler

    required = {"src_ip", "port", "packet_rate", "packet_size"}
    missing  = required - set(df.columns)
    if missing:
        raise ValueError(f"Training CSV missing columns: {missing}")

    # Estimate contamination from labels if present, else default to 0.05
    contamination = 0.05
    if LABEL_COLUMN in df.columns:
        n_anomalies   = (df[LABEL_COLUMN].str.lower() != "normal").sum()
        contamination = float(np.clip(n_anomalies / max(len(df), 1), 0.01, 0.50))

    feats  = engineer_features(df)
    scaler = StandardScaler()
    X      = scaler.fit_transform(feats)

    clf = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
        max_samples="auto",
    )
    clf.fit(X)

    joblib.dump(clf,    _MODEL_PATH)
    joblib.dump(scaler, _SCALER_PATH)

    _clf    = clf
    _scaler = scaler

    return {
        "status":        "retrained",
        "rows_used":     len(df),
        "contamination": round(contamination, 4),
        "features":      list(feats.columns),
    }