import subprocess
import time
import re

# Set to keep track of already blocked IPs
BLOCK_IPS = set()

# Function to block an IP address using pf (Packet Filter) on macOS
def block_ip(ip):
    if ip in BLOCK_IPS:
        return  # Skip if the IP is already blocked

    print(f'🔒 Blocking IP on macOS: {ip}')

    # Create a pf rule to block traffic from this IP
    block_cmd = f"echo 'block drop from {ip} to any' | sudo pfctl -a com.siem.guardian -f -"
    subprocess.run(block_cmd, shell=True)

    # Add IP to blocked set
    BLOCK_IPS.add(ip)

    # Write the block action to a local log file
    with open("logs/firewall_logm.log", "a") as f:
        f.write(f"[{time.ctime()}] BLOCKED : {ip}\n")

# Function to monitor system logs and detect suspicious login failures
def run():
    log_file = "/var/log/system.log"
    print("👀 Watching macOS system log for authentication failures...")

    with open(log_file, "r") as f:
        f.seek(0, 2)  # Move to the end of the file (tailing behavior)

        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue

            # Look for failed login attempts
            if "authentication failure" in line:
                ip_match = re.search(r"\d+\.\d+\.\d+\.\d+", line)
                if ip_match:
                    ip = ip_match.group(0)  # FIXED: was group(1) which would raise IndexError
                    print(f"[!] Detected failed login from {ip}")
                    block_ip(ip)
