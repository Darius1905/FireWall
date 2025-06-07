# import re
# import joblib
# import os
# import math
# import pandas as pd
# from sklearn.ensemble import RandomForestClassifier
#
# MODEL_PATH = "models/phishing_model.pkl"
#
# def calc_entropy(s):
#     prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
#     entropy = - sum([p * math.log(p, 2) for p in prob])
#     return entropy
#
# def extract_features(url):
#     return {
#         'url_length': len(url),
#         'has_ip_address': int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))),
#         'count_dots': url.count('.'),
#         'has_https': int(url.startswith('https')),
#         'has_at_symbol': int('@' in url),
#         'count_slashes': url.count('/'),
#         'contains_login_keyword': int(bool(re.search(r'login|secure|verify|update', url.lower()))),
#         'entropy': calc_entropy(url)
#     }
#
# def train_model():
#     # Sample data (real use: load from CSV)
#     data = [
#         {"url": "http://192.168.1.1/login", "label": 1},
#         {"url": "https://secure.google.com/account", "label": 0},
#         {"url": "http://phishingsite.com/verify", "label": 1},
#         {"url": "https://www.bank.com", "label": 0},
#         {"url": "http://malicious.ru/secure/update", "label": 1},
#         {"url": "https://login.microsoft.com", "label": 0},
#     ]
#     df = pd.DataFrame(data)
#     X = pd.DataFrame([extract_features(url) for url in df["url"]])
#     y = df["label"]
#
#     clf = RandomForestClassifier()
#     clf.fit(X, y)
#
#     os.makedirs("models", exist_ok=True)
#     joblib.dump(clf, MODEL_PATH)
#     print(f"[+] Model saved to {MODEL_PATH}")
#
# def load_model():
#     if not os.path.exists(MODEL_PATH):
#         print("[!] Model not found, training...")
#         train_model()
#     return joblib.load(MODEL_PATH)
#
# # Load model when module is imported
# _model = load_model()
#
# def predict_url(url):
#     features = pd.DataFrame([extract_features(url)])
#     pred = _model.predict(features)
#     return bool(pred[0])  # True if phishing
