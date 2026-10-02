# ================================================
# Network IDS - ML Model Training
# Author: Ansh
# Phase 5 - Isolation Forest Anomaly Detection
# ================================================

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import json
import os

os.makedirs("ml", exist_ok=True)

print("="*50)
print("🤖 Network IDS - ML Model Training")
print("="*50)

# ── Step 1: Generate Training Data ───────────────
print("\n📊 Step 1: Generating training dataset...")
np.random.seed(42)

# Normal traffic
# Normal traffic - MORE REALISTIC
n = 3000
normal = pd.DataFrame({
    "packet_length": np.random.normal(200, 100, n).clip(20, 1500),
    "src_port"     : np.random.randint(1024, 65535, n),
    # Include ALL common ports not just 5
    "dst_port"     : np.random.choice([
                        80, 443, 53, 22, 8080,
                        8443, 3306, 5432, 25, 110,
                        143, 993, 995, 3389, 5900,
                        # Also include random ports
                        *np.random.randint(1024, 65535, 20).tolist()
                     ], n),
    "protocol"     : np.random.choice([0,1,2], n,
                        p=[0.6, 0.3, 0.1]),
    "ttl"          : np.random.choice([64, 128, 255], n,
                        p=[0.6, 0.3, 0.1]),
    "label"        : 0
})

# Attack traffic - MORE SPECIFIC
a = 300
attack = pd.DataFrame({
    "packet_length": np.concatenate([
        np.random.normal(1400, 100, a//3),  # DoS
        np.random.normal(40,   10,  a//3),  # Scan
        np.random.normal(800,  50,  a//3),  # Exploit
    ])[:a].clip(20, 1500),
    "src_port"     : np.random.randint(1, 1024, a),
    "dst_port"     : np.random.choice([
                        4444, 1337, 31337,  # Backdoors
                        6667, 6666,          # IRC/Botnet
                        9001, 9002,          # Tor
                        23, 21,              # Telnet/FTP
                     ], a),
    "protocol"     : np.random.choice([0,1], a),
    "ttl"          : np.random.choice([1, 255], a),
    "label"        : 1
})

df = pd.concat([normal, attack]).sample(
        frac=1, random_state=42
     ).reset_index(drop=True)

print(f"   Normal  samples : {n}")
print(f"   Attack  samples : {a}")
print(f"   Total   samples : {len(df)}")

# ── Step 2: Prepare Features ─────────────────────
print("\n⚙️  Step 2: Preparing features...")

FEATURES = ["packet_length","src_port",
            "dst_port","protocol","ttl"]
X = df[FEATURES]
y = df["label"]

scaler   = StandardScaler()
X_scaled = scaler.fit_transform(X)
print(f"   Features : {FEATURES}")

# ── Step 3: Train Model ──────────────────────────
print("\n🌲 Step 3: Training Isolation Forest...")

model = IsolationForest(
    contamination=0.05,  # ← Change from 0.15 to 0.05
    n_estimators=200,    # ← More trees = better accuracy
    random_state=42
)
model.fit(X_scaled)
print("   ✅ Model trained!")

# ── Step 4: Evaluate ─────────────────────────────
print("\n📈 Step 4: Evaluating model...")

preds       = model.predict(X_scaled)
pred_labels = (preds == -1).astype(int)
accuracy    = (pred_labels == y).mean() * 100

print(f"   Accuracy        : {accuracy:.2f}%")
print(f"   Anomalies found : {pred_labels.sum()}")
print(f"   Normal found    : {(pred_labels==0).sum()}")

# ── Step 5: Save Model ───────────────────────────
print("\n💾 Step 5: Saving model files...")

joblib.dump(model,  "ml/model.pkl")
joblib.dump(scaler, "ml/scaler.pkl")

with open("ml/features.json", "w") as f:
    json.dump(FEATURES, f)

print("   Saved: ml/model.pkl")
print("   Saved: ml/scaler.pkl")
print("   Saved: ml/features.json")

print("\n" + "="*50)
print("✅ ML Training Complete!")
print("="*50)
