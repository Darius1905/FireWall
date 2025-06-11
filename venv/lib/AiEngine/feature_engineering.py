import pandas as pd
from sklearn.preprocessing import StandardScaler

FEATURE_COLUMNS = ['packet_count', 'byte_count', 'duration', 'avg_packet_size']


def extract_features(flow_df):
    features = flow_df.copy()
    if 'avg_packet_size' not in features.columns:
        features['avg_packet_size'] = features['byte_count'] / features['packet_count']

    return features[FEATURE_COLUMNS]


def normalize_features(feature_df, scaler=None):
    if scaler is None:
        # Used during training
        scaler = StandardScaler()
        scaled = scaler.fit_transform(feature_df)
    else:
        # Used during prediction
        scaled = scaler.transform(feature_df)

    return scaled, scaler


def transform_with_scaler(feature, scaler):
    return scaler.transform(feature)
