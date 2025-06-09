# generate_test_pcap.py

from scapy.all import Ether, IP, TCP, UDP, wrpcap

def generate_pcap(output_file="test_flows.pcap"):
    packets = []

    # TCP packet: 192.168.1.10 -> 8.8.8.8:80
    pkt1 = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=12345, dport=80)
    packets.append(pkt1)

    # TCP packet: 192.168.1.11 -> 1.1.1.1:443
    pkt2 = Ether() / IP(src="192.168.1.11", dst="1.1.1.1") / TCP(sport=23456, dport=443)
    packets.append(pkt2)

    # UDP packet: 192.168.1.12 -> 8.8.8.8:53
    pkt3 = Ether() / IP(src="192.168.1.12", dst="8.8.8.8") / UDP(sport=34567, dport=53)
    packets.append(pkt3)

    # Gói lặp lại để test chống trùng flow
    packets.append(pkt1)

    wrpcap(output_file, packets)
    print(f"[+] PCAP đã được tạo: {output_file}")

if __name__ == "__main__":
    generate_pcap()
