import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from AiEngine.feature_engineering import normalize_features
from pathlib import Path

# Paths for saving the trained model and scaler
MODEL_PATH = 'model/network_model.joblib'
SCALER_PATH = 'model/scaler.joblib'

# Path to the dataset
CSV_PATH = Path(__file__).resolve().parent.parent / "data" / "archive" / "UNSW_NB15_training-set.csv"

# Features to use
selected_features = [
    'dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl',
    'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit',
    'swin', 'dwin', 'tcprtt', 'synack', 'ackdat'
]


def load_dataset(csv_file):
    if not csv_file.exists():
        raise FileNotFoundError(f"❌ File not found at: {csv_file.resolve()}")

    data = pd.read_csv(csv_file)

    # Gỡ các hàng thiếu dữ liệu
    data.dropna(inplace=True)

    return data


def train_model(csv_file):
    data = load_dataset(csv_file)

    # Feature matrix và labels
    X = data[selected_features]
    y = data['label']

    # Normalize
    X_scaled, scaler = normalize_features(X)

    # Train-test split
    x_train, x_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.3, random_state=42)

    # Train model
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(x_train, y_train)

    # Predict & Evaluate
    y_pred = clf.predict(x_test)
    print("[*] Classification Report:\n", classification_report(y_test, y_pred))

    # Save model and scaler
    Path(MODEL_PATH).parent.mkdir(parents=True, exist_ok=True)
    Path(MODEL_PATH).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    print(f"[+] Saved model to {MODEL_PATH}")
    print(f"[+] Saved scaler to {SCALER_PATH}")


if __name__ == '__main__':
    train_model(CSV_PATH)
