from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

def generate_test_pcap(filename="test_anomaly.pcap"):
    packets = []

    # 1. Gửi 30 gói TCP từ cùng 1 IP -> bất thường (giống scanning/DDoS)
    for i in range(30):
        pkt = Ether() / IP(src="10.10.10.10", dst="8.8.8.8") / TCP(sport=1024+i, dport=80)
        packets.append(pkt)

    # 2. Gói có payload chứa "MZ" (giống file EXE/DLL)
    exe_payload = b"MZ\x90\x00\x03\x00FakeEXEcontent"
    pkt_exe = Ether() / IP(src="192.168.1.2", dst="192.168.1.3") / TCP(sport=4444, dport=80) / Raw(load=exe_payload)
    packets.append(pkt_exe)

    # 3. Gói có payload shellcode giả (NOP sled + mã giả)
    shellcode = b"\x90" * 20 + b"\xcc\xcc\xcc"
    pkt_shell = Ether() / IP(src="192.168.1.2", dst="192.168.1.3") / TCP(sport=1234, dport=80) / Raw(load=shellcode)
    packets.append(pkt_shell)

    # 4. Gói UDP bình thường (để so sánh)
    pkt_udp = Ether() / IP(src="10.0.0.5", dst="1.1.1.1") / UDP(sport=5353, dport=53)
    packets.append(pkt_udp)

    # Ghi file PCAP
    wrpcap(filename, packets)
    print(f"[+] Đã tạo file {filename} thành công!")

# Gọi hàm
if __name__ == "__main__":
    generate_test_pcap()
