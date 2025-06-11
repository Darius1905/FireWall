import json
import os
from datetime import datetime

LOG_DIR = r'/logs/log_anomalies'
LOG_FILE = os.path.join(LOG_DIR, 'anomalies.log')


def log_anomaly(anomalies):
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(LOG_FILE, 'a', encoding='utf-8') as file:
        for entry in anomalies:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': entry.get('src_ip', ''),
                'dst_ip': entry.get('dst_ip', ''),
                'protocol': entry.get('protocol', ''),
                'src_port': entry.get('src_port', ''),
                'dst_port': entry.get('dst_port', ''),
                'issues': entry.get('issues', [])
            }
            file.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
    print(f'[+] Log saved to {LOG_FILE}')


def unify_and_log(payload_alerts, sender_alerts):
    os.makedirs(LOG_DIR, exist_ok=True)

    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        # Log payload alerts
        for alert in payload_alerts:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "src_ip": alert.get('src_ip', ''),
                "dst_ip": alert.get('dst_ip', ''),
                "packet_count": None,
                "alert_type": "payload",
                "alert_detail": alert.get('alert', '')
            }
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")

        # Log sender alerts
        for alert in sender_alerts:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "src_ip": alert.get('src_ip', ''),
                "dst_ip": '',
                "packet_count": alert.get('packet_count', 0),
                "alert_type": "heavy_sender",
                "alert_detail": alert.get('issues', '')
            }
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")

    print(f'[+] Unified logs saved to {LOG_FILE}')
