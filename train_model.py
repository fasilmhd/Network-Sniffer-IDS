# train_model.py
# ─────────────────────────────────────────────────────────────────────────────
# Run this ONCE to train a Random Forest on CIC-IDS-2017 and save the model.
#
#   Usage (inside the project root, venv active):
#       python train_model.py
#
# Outputs:
#   ids_model.pkl       – trained RandomForestClassifier
#   scaler.pkl          – fitted StandardScaler
#   label_encoder.pkl   – fitted LabelEncoder
# ─────────────────────────────────────────────────────────────────────────────

import os
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score

DATASET_DIR = os.path.join(os.path.dirname(__file__), "dataset")
DATASET_FILES = [
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
]

# Columns that are not useful as features
DROP_COLUMNS = [
    "Flow ID", "Source IP", "Destination IP",
    "Src IP", "Dst IP", "Timestamp",
    "SimillarHTTP", "Inbound",           # present in some CIC versions
]

LABEL_COLUMN = " Label"   # CIC-IDS files have a leading space in the header

SAMPLE_SIZE   = 80_000    # rows to sample (set None to use full dataset)
MODEL_OUT     = "ids_model.pkl"
SCALER_OUT    = "scaler.pkl"
ENCODER_OUT   = "label_encoder.pkl"


def load_data():
    frames = []
    for fname in DATASET_FILES:
        path = os.path.join(DATASET_DIR, fname)
        if not os.path.exists(path):
            print(f"[WARN] Dataset not found: {path} — skipping")
            continue
        print(f"[INFO] Loading {fname} …")
        df = pd.read_csv(path, encoding="utf-8", low_memory=False)
        frames.append(df)
        print(f"       {df.shape[0]:,} rows  ×  {df.shape[1]} cols")

    if not frames:
        raise FileNotFoundError("No dataset CSV files found in dataset/")

    data = pd.concat(frames, ignore_index=True)
    print(f"\n[INFO] Combined dataset: {data.shape[0]:,} rows  ×  {data.shape[1]} cols")
    return data


def clean(data: pd.DataFrame) -> pd.DataFrame:
    # Strip column name whitespace
    data.columns = data.columns.str.strip()

    # Replace inf / -inf with NaN then drop them
    data.replace([np.inf, -np.inf], np.nan, inplace=True)
    before = len(data)
    data.dropna(inplace=True)
    print(f"[INFO] Dropped {before - len(data):,} rows containing NaN / inf")

    return data


def prepare_features(data: pd.DataFrame):
    label_col = "Label"
    if label_col not in data.columns:
        raise KeyError(f"Column '{label_col}' not found. Available: {list(data.columns[:10])}")

    # Drop non-feature columns
    drop = [c for c in DROP_COLUMNS if c in data.columns] + [label_col]
    X = data.drop(columns=drop, errors="ignore")

    # Keep only numeric columns
    X = X.select_dtypes(include=[np.number])

    y_raw = data[label_col].astype(str).str.strip()
    return X, y_raw


def main():
    print("=" * 60)
    print("  ML-IDS — Random Forest Trainer")
    print("=" * 60)

    # 1. Load
    data = load_data()

    # 2. Clean
    data = clean(data)

    # 3. Optional down-sample for speed
    if SAMPLE_SIZE and len(data) > SAMPLE_SIZE:
        data = data.sample(n=SAMPLE_SIZE, random_state=42)
        print(f"[INFO] Sampled {SAMPLE_SIZE:,} rows for training")

    # 4. Features + labels
    X, y_raw = prepare_features(data)
    print(f"[INFO] Feature count: {X.shape[1]}")
    print(f"[INFO] Label distribution:\n{y_raw.value_counts().to_string()}\n")

    # 4b. Remove classes with too few samples (stratified split needs ≥ 2)
    MIN_SAMPLES = 5
    label_counts = y_raw.value_counts()
    rare_classes = label_counts[label_counts < MIN_SAMPLES].index.tolist()
    if rare_classes:
        print(f"[INFO] Removing rare classes (< {MIN_SAMPLES} samples): {rare_classes}")
        data = data[~data["Label"].isin(rare_classes)]
        X, y_raw = prepare_features(data)
        print(f"[INFO] Dataset after filtering: {len(data):,} rows\n")

    # 5. Encode labels
    encoder = LabelEncoder()
    y = encoder.fit_transform(y_raw)
    print(f"[INFO] Classes: {list(encoder.classes_)}")

    # 6. Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # 7. Split
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\n[INFO] Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # 8. Train
    print("\n[INFO] Training Random Forest (n_estimators=100) …")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_train, y_train)

    # 9. Evaluate
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n[RESULT] Accuracy: {acc:.4f}  ({acc*100:.2f}%)\n")
    print(classification_report(y_test, y_pred, target_names=encoder.classes_))

    # 10. Save artefacts
    joblib.dump(model,   MODEL_OUT)
    joblib.dump(scaler,  SCALER_OUT)
    joblib.dump(encoder, ENCODER_OUT)
    print(f"[OK] Model  saved → {MODEL_OUT}")
    print(f"[OK] Scaler saved → {SCALER_OUT}")
    print(f"[OK] Encoder saved → {ENCODER_OUT}")

    # 11. Train Anomaly Detection (Isolation Forest)
    print("\n[INFO] Training Isolation Forest for Anomaly Detection (zero-day detection) …")
    
    # Train only on BENIGN traffic so it learns "normal" mapping
    benign_mask = (y_raw == "BENIGN")
    if benign_mask.sum() > 0:
        X_benign = X[benign_mask]
        X_benign_scaled = scaler.transform(X_benign)
        
        iso_model = IsolationForest(
            contamination=0.01, 
            random_state=42, 
            n_jobs=-1
        )
        iso_model.fit(X_benign_scaled)
        
        joblib.dump(iso_model, "anomaly_model.pkl")
        print(f"[OK] Anomaly Model saved → anomaly_model.pkl")
    else:
        print("[WARN] No BENIGN traffic found to train Isolation Forest.")

    print("\nTraining complete. You can now run main.py for live ML-IDS predictions.")


if __name__ == "__main__":
    main()
