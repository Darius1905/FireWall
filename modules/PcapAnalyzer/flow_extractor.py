import pyshark
import pandas as pd


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
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)
    src_ips, dst_ips = [], []
    src_ports, dst_ports = [], []
    protocols = []

    seen = set()
    for packet in cap:
        info = extract_packet_info(packet)
        if info is None:
            continue
        src_ip, dst_ip, protocol, src_port, dst_port = info
        flow_id = (src_ip, dst_ip, protocol, src_port, dst_port)

        if not is_unique_flow(flow_id, seen):
            continue

        src_ips.append(src_ip)
        dst_ips.append(dst_ip)
        protocols.append(protocol)
        src_ports.append(src_port)
        dst_ports.append(dst_port)

    return build_dataframe(src_ips, dst_ips, protocols, src_ports, dst_ports)


def build_dataframe(src_ips, dst_ips, protocols, src_ports, dst_ports):
    data = pd.DataFrame({
        'src_ip': src_ips,
        'dst_ip': dst_ips,
        'protocol': protocols,
        'src_port': src_ports,
        'dst_port': dst_ports
    })
    return data


