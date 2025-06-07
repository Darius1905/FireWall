import win32evtlog
import subprocess
import time
import os

# A set to keep track of already blocked IP addresses
BLOCK_IPS = set()

# Function to block an IP using Windows Firewall
def block_ip(ip):
    if ip in BLOCK_IPS:
        return  # Skip if already blocked

    print(f"🛡 Blocking IP on Windows: {ip}")
    rule_name = f"Block_{ip}"

    # Create a firewall rule using netsh
    subprocess.run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"
    ])

    BLOCK_IPS.add(ip)  # Mark IP as blocked

    # Log the blocked IP to a local file
    os.makedirs("log", exist_ok=True)
    with open("log/firewall_block.log", "a") as f:
        f.write(f"[{time.ctime()}] BLOCKED: {ip}\n")

# Function to extract IP address from the event log entry
def extract_ip_from_event(event):
    if not event.StringInserts:
        return None
    for field in event.StringInserts:
        # Very simple IP check (checks for 3 dots)
        if field and "." in field and field.count('.') == 3:
            return field
    return None

# Main function to start monitoring the Windows Security Event Log
def run():
    print("👁️  Watching Windows Security Event Log...")
    server = "localhost"
    logtype = "Security"

    # Open the Security event log on the local machine
    hand = win32evtlog.OpenEventLog(server, logtype)

    # Flags: read logs in forward and sequential order
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    while True:
        # Read a batch of log events
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        for event in events:
            # Event ID 4625 indicates failed login attempt
            if event.EventID == 4625:
                ip = extract_ip_from_event(event)
                if ip:
                    print(f"[!] Detected failed login from IP: {ip}")
                    block_ip(ip)
        time.sleep(3)  # Wait before reading the next batch
