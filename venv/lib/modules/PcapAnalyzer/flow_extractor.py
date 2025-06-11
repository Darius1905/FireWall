import pyshark
import pandas as pd
from collections import defaultdict
import time


def extract_packet_info(pkt):
    # Extract IP information, port, and protocol from a packet.
    try:
        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst
        protocol = pkt.transport_layer
        src_port = pkt[protocol].srcport
        dst_port = pkt[protocol].dstport
        return src_ip, dst_ip, protocol, src_port, dst_port
    except AttributeError:
        return None


def is_unique_flow(flow_id, seen):
    # Check if the flow has been encountered before.
    if flow_id in seen:
        return False
    seen.add(flow_id)
    return True


def extract_flow(pcap_file):
    cap = pyshark.FileCapture(pcap_file, keep_packets=True)

    flow_stats = defaultdict(lambda: {
        "start_time": None,
        "end_time": None,
        "sbytes": 0,
        "dbytes": 0,
        "spkts": 0,
        "dpkts": 0,
        "protocol": "",
        "packets": []
    })

    for packet in cap:
        try:
            ip_layer = packet.ip
            proto = packet.transport_layer
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = packet[proto].srcport
            dst_port = packet[proto].dstport
            flow_key = (src_ip, dst_ip, proto, src_port, dst_port)

            timestamp = float(packet.sniff_timestamp)
            pkt_len = int(packet.length)

            direction = "forward"  # src → dst
            if flow_stats[flow_key]["start_time"] is None:
                flow_stats[flow_key]["start_time"] = timestamp

            flow_stats[flow_key]["end_time"] = timestamp
            flow_stats[flow_key]["protocol"] = proto
            flow_stats[flow_key]["packets"].append((timestamp, pkt_len, direction))
            flow_stats[flow_key]["sbytes"] += pkt_len
            flow_stats[flow_key]["spkts"] += 1

        except Exception:
            continue

    # Build DataFrame
    rows = []
    for (src_ip, dst_ip, proto, src_port, dst_port), stats in flow_stats.items():
        dur = stats["end_time"] - stats["start_time"]
        row = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": proto,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "dur": dur,
            "spkts": stats["spkts"],
            "dpkts": stats["dpkts"],  # placeholder; bidirectional flows need handling
            "sbytes": stats["sbytes"],
            "dbytes": stats["dbytes"],  # same here
            # Fill remaining required fields with 0 or mock for now
            "rate": stats["sbytes"] / dur if dur > 0 else 0,
            "sttl": 64, "dttl": 64,
            "sload": 0, "dload": 0,
            "sloss": 0, "dloss": 0,
            "sinpkt": 0, "dinpkt": 0,
            "sjit": 0, "djit": 0,
            "swin": 8192, "dwin": 8192,
            "tcprtt": 0, "synack": 0, "ackdat": 0
        }
        rows.append(row)

    return pd.DataFrame(rows)


def build_dataframe(src_ips, dst_ips, protocols, src_ports, dst_ports):
    data = pd.DataFrame({
        'src_ip': src_ips,
        'dst_ip': dst_ips,
        'protocol': protocols,
        'src_port': src_ports,
        'dst_port': dst_ports
    })
    return data
