import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.ml_ids_engine import MLIDSEngine

def main():
    print("Testing ML IDS Engine...")
    ready = MLIDSEngine.is_ready()
    print(f"Engine Ready: {ready}")
    
    if not ready:
        print("Engine failed to load. Are models present?")
        return

    # Simulate a generic feature dictionary
    features = {
        'Flow Duration': 1000,
        'Total Fwd Packets': 2,
        'Total Backward Packets': 2,
        'Fwd Packet Length Max': 50,
        'Bwd Packet Length Max': 50,
        'Flow Bytes/s': 10000,
        'Flow Packets/s': 400,
        'SYN Flag Count': 1,
        'ACK Flag Count': 1
    }

    print("\n--- Testing Supervised Model ---")
    label, conf = MLIDSEngine.predict(features)
    print(f"Predicted Label: {label}")
    print(f"Confidence: {conf:.2%}")

    print("\n--- Testing Unsupervised Anomaly Model ---")
    is_anomaly, score = MLIDSEngine.predict_anomaly(features)
    print(f"Is Anomaly: {is_anomaly}")
    print(f"Anomaly Score: {score:.4f}")
    
    # Simulate extreme values
    attack_features = {
        'Flow Duration': 5,
        'Total Fwd Packets': 5000,
        'Fwd Packet Length Max': 1500,
        'Flow Bytes/s': 99999999,
        'Flow Packets/s': 999999,
        'SYN Flag Count': 500
    }
    
    print("\n--- Testing Attack Properties ---")
    label, conf = MLIDSEngine.predict(attack_features)
    print(f"Predicted Label: {label}")
    print(f"Confidence: {conf:.2%}")
    
    is_anomaly, score = MLIDSEngine.predict_anomaly(attack_features)
    print(f"Is Anomaly: {is_anomaly}")
    print(f"Anomaly Score: {score:.4f}")

if __name__ == '__main__':
    main()
