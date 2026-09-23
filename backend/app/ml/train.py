import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib
import os

# Create model directory if it doesn't exist
MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(MODEL_DIR, "threat_model.pkl")
ENCODER_PATH = os.path.join(MODEL_DIR, "label_encoder.pkl")

def generate_synthetic_data(samples=10000):
    np.random.seed(42)
    
    # Normal Traffic (60%)
    normal_samples = int(samples * 0.6)
    normal = pd.DataFrame({
        'packet_size': np.random.normal(500, 200, normal_samples),
        'duration': np.random.exponential(1.5, normal_samples),
        'failed_logins': np.random.poisson(0.1, normal_samples),
        'unique_ports_accessed': np.random.randint(1, 5, normal_samples),
        'bytes_sent': np.random.normal(1500, 500, normal_samples),
        'label': 'Normal'
    })
    
    # Port Scan (15%)
    port_scan_samples = int(samples * 0.15)
    port_scan = pd.DataFrame({
        'packet_size': np.random.normal(60, 20, port_scan_samples),
        'duration': np.random.exponential(0.5, port_scan_samples),
        'failed_logins': np.zeros(port_scan_samples),
        'unique_ports_accessed': np.random.randint(50, 1000, port_scan_samples),
        'bytes_sent': np.random.normal(200, 50, port_scan_samples),
        'label': 'Port Scan'
    })
    
    # Brute Force (15%)
    brute_force_samples = int(samples * 0.15)
    brute_force = pd.DataFrame({
        'packet_size': np.random.normal(120, 30, brute_force_samples),
        'duration': np.random.exponential(5.0, brute_force_samples),
        'failed_logins': np.random.randint(5, 50, brute_force_samples),
        'unique_ports_accessed': np.random.randint(1, 3, brute_force_samples),
        'bytes_sent': np.random.normal(500, 100, brute_force_samples),
        'label': 'Brute Force'
    })
    
    # DoS (10%)
    dos_samples = int(samples * 0.1)
    dos = pd.DataFrame({
        'packet_size': np.random.normal(1500, 100, dos_samples),
        'duration': np.random.exponential(10.0, dos_samples),
        'failed_logins': np.zeros(dos_samples),
        'unique_ports_accessed': np.random.randint(1, 5, dos_samples),
        'bytes_sent': np.random.normal(10000, 2000, dos_samples),
        'label': 'DoS'
    })
    
    df = pd.concat([normal, port_scan, brute_force, dos], ignore_index=True)
    # Ensure no negative values
    for col in ['packet_size', 'duration', 'bytes_sent']:
        df[col] = df[col].apply(lambda x: max(0, x))
        
    return df

def train_model():
    print("Generating synthetic data...")
    df = generate_synthetic_data()
    
    X = df.drop('label', axis=1)
    y = df['label']
    
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)
    
    print("Training Random Forest Classifier...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    
    accuracy = clf.score(X_test, y_test)
    print(f"Model Accuracy on Test Set: {accuracy * 100:.2f}%")
    
    print(f"Saving model to {MODEL_PATH}...")
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(le, ENCODER_PATH)
    print("Training complete!")

if __name__ == "__main__":
    train_model()
