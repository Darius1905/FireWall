from scapy.all import rdpcap, Raw, IP

SUSPICIOUS_SIGs = [b'MZ', b'This program cannot', b'\x90\x90\x90', b'ELF', b'dll']


def scan_payloads(pcap_file):
    packets = rdpcap(pcap_file)
    alerts = []

    for packet in packets:
        if packet.haslayer(Raw) and packet.haslayer(IP):
            payload = bytes(packet[Raw].load)
            for sig in SUSPICIOUS_SIGs:
                if sig in payload:
                    alerts.append({
                        'src_ip': packet[IP].src,
                        'dst_ip': packet[IP].dst,
                        'alert': f'Suspicious payload: {sig.decode(errors="ignore")}'
                    })
                    break

    return alerts
