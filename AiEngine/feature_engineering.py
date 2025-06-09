import pandas as pd
from sklearn.preprocessing import StandardScaler

FEATURE_COLUMNS = ['packet_count', 'byte_count', 'duration', 'avg_packet_size']

def extract_features(flow_df):
    features = flow_df.copy()
    if 'avg_packet_size' not in features.columns:
        features['avg_packet_size'] = features['byte_count']/ features['packet_count'].re
