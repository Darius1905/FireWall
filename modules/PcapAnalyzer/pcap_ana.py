import pyshark
import threading
import tkinter as tk
from collections import defaultdict
import platform
import subprocess
import asyncio
class RealtimeAnalyzer:
    def __init__(self, interface, threshold=50):
        self.interface = interface
        self.threshold = threshold
        self.ip_counter = defaultdict(int)
        self.alerted_ips = set()

        # GUI setup
        self.root = tk.Tk()
        self.root.title("SIEM - Realtime Network Monitor")
        self.text = tk.Text(self.root, height=20, width=60)
        self.text.pack()

    def log_gui(self, msg):
        self.text.insert(tk.END, msg + "\n")
        self.text.see(tk.END)

    def block_ip(self, ip):
        if ip in self.alerted_ips:
            return
        self.alerted_ips.add(ip)

        self.log_gui(f"[⚠] Chặn IP bất thường: {ip}")

        os_type = platform.system()
        if os_type == "Windows":
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                            f"name=Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"])
        elif os_type == "Linux":
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        else:
            self.log_gui("Chặn IP không hỗ trợ trên hệ điều hành này.")

    def packet_callback(self, packet):
        try:
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                self.ip_counter[src_ip] += 1
                count = self.ip_counter[src_ip]

                if count == self.threshold:
                    self.log_gui(f"[!] IP {src_ip} gửi {count} gói (bất thường)")
                    self.block_ip(src_ip)
        except AttributeError:
            pass

    import asyncio

    def start_capture(self):
        asyncio.set_event_loop(asyncio.new_event_loop())
        self.log_gui(f"Bắt đầu giám sát mạng trên: {self.interface}")
        capture = pyshark.LiveCapture(interface=self.interface)
        capture.apply_on_packets(self.packet_callback)

    def run(self):
        t = threading.Thread(target=self.start_capture, daemon=True)
        t.start()
        self.root.mainloop()

if __name__ == "__main__":
    iface = input("Nhập tên interface mạng (VD: eth0, en0, Wi-Fi): ")
    analyzer = RealtimeAnalyzer(interface=iface, threshold=50)
    analyzer.run()
