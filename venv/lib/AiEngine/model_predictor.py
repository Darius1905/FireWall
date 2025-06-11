import joblib
from AiEngine.feature_engineering import normalize_features
from FireWallUpdate.rule_generator import generate_rule
from modules.logger.log_manager import log_anomaly
from pathlib import Path
import os

MODEL_PATH = Path('AiEngine/model/network_model.joblib')
SCALER_PATH = Path('AiEngine/model/scaler.joblib')
selected_features = [
    'dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl',
    'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit',
    'swin', 'dwin', 'tcprtt', 'synack', 'ackdat'
]


def predict_flow_df(flow_df):
    if not MODEL_PATH.exists() or not SCALER_PATH.exists():
        raise FileNotFoundError("[!] Model or scaler file not found")

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    missing = [col for col in selected_features if col not in flow_df.columns]
    if missing:
        raise ValueError(f'[!] Missing required columns: {missing}')

    x_scaled, _ = normalize_features(flow_df[selected_features], scaler=scaler)

    prediction = model.predict(x_scaled)

    alerts = []

    for i, label in enumerate(prediction):
        if label == 1:
            row = flow_df.iloc[i]

            # Convert to JSON-safe types
            alert = {
                "src_ip": str(row["src_ip"]) if "src_ip" in row else "unknown",
                "dst_ip": str(row["dst_ip"]) if "dst_ip" in row else "unknown",
                "protocol": str(row["protocol"]) if "protocol" in row else "unknown",
                "src_port": int(row["src_port"]) if "src_port" in row else -1,
                "dst_port": int(row["dst_port"]) if "dst_port" in row else -1,
                "issues": "⚠️ ML model detected suspicious flow"
            }

            alerts.append(alert)
            generate_rule(alert)
            log_anomaly([alert])  # Expecting a list

    return alerts
