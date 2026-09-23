import os
import joblib
import pandas as pd
import numpy as np

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(MODEL_DIR, "threat_model.pkl")
ENCODER_PATH = os.path.join(MODEL_DIR, "label_encoder.pkl")

# Initialize globally
clf = None
le = None

def load_model():
    global clf, le
    if os.path.exists(MODEL_PATH) and os.path.exists(ENCODER_PATH):
        clf = joblib.load(MODEL_PATH)
        le = joblib.load(ENCODER_PATH)
        return True
    return False

def map_severity(label: str) -> str:
    if label == "Normal":
        return "LOW"
    elif label == "Port Scan":
        return "MEDIUM"
    elif label == "Brute Force":
        return "HIGH"
    elif label == "DoS":
        return "CRITICAL"
    return "UNKNOWN"

def analyze_event(event_data: dict) -> dict:
    if clf is None or le is None:
        if not load_model():
            return {"error": "Model not trained yet."}
            
    # Expected features: packet_size, duration, failed_logins, unique_ports_accessed, bytes_sent
    features = ['packet_size', 'duration', 'failed_logins', 'unique_ports_accessed', 'bytes_sent']
    
    # Fill missing with 0
    row = {f: event_data.get(f, 0) for f in features}
    df = pd.DataFrame([row])
    
    # Predict
    pred_idx = clf.predict(df)[0]
    probabilities = clf.predict_proba(df)[0]
    
    confidence = float(np.max(probabilities))
    label = le.inverse_transform([pred_idx])[0]
    
    return {
        "prediction": label,
        "confidence": confidence,
        "severity": map_severity(label)
    }
