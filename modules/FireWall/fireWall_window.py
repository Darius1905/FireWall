import win32evtlog
import subprocess
import time
import os

BLOCK_IPS = set()

def block_ip(ip):
    if ip in BLOCK_IPS:
        return
    print(f"🛡 Chặn IP trên Windows: {ip}")
    rule_name = f"Block_{ip}"
    subprocess.run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"
    ])
    BLOCK_IPS.add(ip)

    # Ghi log vào file
    os.makedirs("log", exist_ok=True)
    with open("log/firewall_block.log", "a") as f:
        f.write(f"[{time.ctime()}] BLOCKED: {ip}\n")

def extract_ip_from_event(event):
    if not event.StringInserts:
        return None
    for field in event.StringInserts:
        if field and "." in field and field.count('.') == 3:
            return field
    return None

def run():
    print("🪟 Đang giám sát Windows Security Event Log...")
    server = "localhost"
    logtype = "Security"

    hand = win32evtlog.OpenEventLog(server, logtype)
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        for event in events:
            if event.EventID == 4625:  # Failed login
                ip = extract_ip_from_event(event)
                if ip:
                    print(f"[!] Phát hiện đăng nhập thất bại từ IP: {ip}")
                    block_ip(ip)
        time.sleep(3)

if __name__ == "__main__":
    run()