import re
import time
import subprocess
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Path to the system authentication log file (on most Linux systems)
LOG_PATH = "/var/log/auth.log"

# Threshold: number of failed login attempts before blocking the IP
THRESHOLD = 5

# Dictionary to count failed login attempts per IP address
IP_FAIL_COUNT = defaultdict(int)

# Set to track which IPs have already been blocked
BLOCK_IP = set()

# Custom event handler that reacts when the log file is modified
class FirewallHandler(FileSystemEventHandler):
    def on_modified(self, event):
        # Only react if the modified file is the target auth log
        if event.src_path == LOG_PATH:
            with open(LOG_PATH, 'r') as f:
                # Try to read the last 10 lines quickly (this is incorrect, fixed below)
                lines = f.readlines()[-10:]  # FIXED: readlines() then slice last 10 lines
                for line in lines:
                    # Look for failed SSH login attempts
                    if 'Failed password' in line:
                        ip = extract_ip(line)
                        if ip:
                            # Increment the fail counter for that IP
                            IP_FAIL_COUNT[ip] += 1  # FIXED: was IP_FAIL_COUNT[1] (wrong)
                            print(f"[!] IP {ip} Fail {IP_FAIL_COUNT[ip]} times")
                            # Block the IP if it exceeds the threshold and isn't already blocked
                            if IP_FAIL_COUNT[ip] >= THRESHOLD and ip not in BLOCK_IP:
                                block_ip(ip)

# Extracts the IP address from a log line
def extract_ip(line):
    match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
    return match.group(1) if match else None

# Blocks the suspicious IP using iptables and logs the action
def block_ip(ip):
    print(f"[!] Blocking suspicious IP {ip}")
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    BLOCK_IP.add(ip)
    with open("log/firewall_block.log", "a") as f:
        f.write(f"[{time.ctime()}] BLOCK: {ip}\n")

# Main function to start the log watcher
def run():
    print("[+] Starting log watcher to update firewall...")
    observer = Observer()
    # Watch only the /var/log directory (not subdirectories)
    observer.schedule(FirewallHandler(), path="/var/log", recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)  # Keep the script running
    except KeyboardInterrupt:
        print("\n[!] Stopping observer...")
        observer.stop()
    observer.join()
