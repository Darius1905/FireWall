from collections import defaultdict
import pyshark


def detect_heavy_senders(pcap_file, threshold=20):
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)
    ip_counter = defaultdict(int)

    try:
        for packet in cap:
            try:
                src_ip = packet.ip.src
                ip_counter[src_ip] += 1
            except AttributeError:
                continue
    finally:
        cap.close()

    anomalies = []
    for ip, count in ip_counter.items():
        if count > threshold:
            anomalies.append({
                'src_ip': ip,
                'packet_count': count,
                'issues': "Unusual number of packets (possible scan/DoS)"
            })

    return anomalies
