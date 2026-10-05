# ================================================
# Network IDS - Anomaly Detector
# Author: Ansh
# Phase 5 - ML Based Detection
# ================================================

import joblib
import numpy as np
import json
import os
from datetime import datetime
import pandas as pd

# ── Config ───────────────────────────────────────
# ── Session-Based Logging ─────────────────────────
SESSION_DIR = os.environ.get(
    'SESSION_LOG_DIR', 'logs'
)
os.makedirs(SESSION_DIR, exist_ok=True)
ML_LOG = os.path.join(SESSION_DIR, "ml_alerts.json")

# ── Protocol Map ─────────────────────────────────
PROTO_MAP = {
    "TCP"  : 0,
    "UDP"  : 1,
    "ICMP" : 2,
    "OTHER": 3
}

# ── Load Model ───────────────────────────────────
def load_or_train_model():
    """Load existing model or train a new one"""
    global model, scaler, FEATURES

    if os.path.exists(MODEL_PATH) and \
       os.path.exists(SCALER_PATH):
        try:
            model  = joblib.load(MODEL_PATH)
            scaler = joblib.load(SCALER_PATH)
            with open(FEATURE_PATH) as f:
                FEATURES = json.load(f)
            print("✅ ML Model loaded successfully!")
            return True
        except Exception as e:
            print(f"⚠️  Model load error: {e}")

    # Auto train if model not found
    print("🤖 Model not found — Auto training...")
    try:
        import subprocess
        result = subprocess.run(
            ["python3", "ml/train_model.py"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            model  = joblib.load(MODEL_PATH)
            scaler = joblib.load(SCALER_PATH)
            with open(FEATURE_PATH) as f:
                FEATURES = json.load(f)
            print("✅ Model auto-trained and loaded!")
            return True
        else:
            print("❌ Auto-training failed!")
            print(result.stderr)
            return False
    except Exception as e:
        print(f"❌ Training error: {e}")
        return False

# Load or train model on startup
model   = None
scaler  = None
FEATURES = []
load_or_train_model()


# ── Cooldown for ML Alerts ───────────────────────
last_ml_alert = {}
ML_COOLDOWN   = 15  # seconds

def should_ml_alert(src_ip, dst_port):
    key = f"{src_ip}_{dst_port}"
    now = __import__('time').time()
    if key not in last_ml_alert or \
       now - last_ml_alert[key] > ML_COOLDOWN:
        last_ml_alert[key] = now
        return True
    return False

# ── Predict Single Packet ────────────────────────
def predict_packet(packet_entry):
    if model is None or scaler is None:
        return False

    try:
        # Extract features from packet
        features = np.array([[
            packet_entry.get("length", 0),
            packet_entry.get("src_port")  or 0,
            packet_entry.get("dst_port")  or 0,
            PROTO_MAP.get(
                packet_entry.get("protocol", "OTHER"), 3
            ),
            packet_entry.get("ttl", 64)
        ]])

        # Scale features (using DataFrame to match feature names)
        features_df     = pd.DataFrame(features,
                            columns=FEATURES)
        features_scaled = scaler.transform(features_df)

        # Predict
        result = model.predict(features_scaled)[0]
        score  = model.score_samples(features_scaled)[0]

        # -1 = anomaly, 1 = normal
        # Only flag if score is below threshold
        # -0.3 means genuinely anomalous
        # Higher threshold = fewer false positives
        is_anomaly = result == -1 and score < -0.3

        if is_anomaly:
            src_ip   = packet_entry.get("src_ip")
            dst_port = packet_entry.get("dst_port")

            if not should_ml_alert(src_ip, dst_port):
                return True

            alert = {
                "timestamp"    : datetime.now().strftime(
                                    "%Y-%m-%d %H:%M:%S"),
                "type"         : "ML_ANOMALY",
                "src_ip"       : src_ip,
                "dst_ip"       : packet_entry.get("dst_ip"),
                "protocol"     : packet_entry.get("protocol"),
                "dst_port"     : dst_port,
                "anomaly_score": round(score, 4),
                "detail"       : (
                    f"Score:{score:.4f} | "
                    f"Port:{dst_port} | "
                    f"Proto:{packet_entry.get('protocol')}"
                )
            }

            # Print ML alert
            print(f"\n{'='*50}")
            print(f"🤖 ML ANOMALY DETECTED!")
            print(f"   Source   : {alert['src_ip']}")
            print(f"   Target   : {alert['dst_ip']}")
            print(f"   Protocol : {alert['protocol']}")
            print(f"   Port     : {alert['dst_port']}")
            print(f"   Score    : {score:.4f}")
            print(f"{'='*50}\n")

            # Save to log
            with open(ML_LOG, "a") as f:
                f.write(json.dumps(alert) + "\n")

        return is_anomaly

    except Exception as e:
        print(f"ML Error: {e}")
        return False
