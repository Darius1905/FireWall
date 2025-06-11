import platform
import subprocess

def apply_rule(rule):
    system = platform.system()
    cmd = ''

    if system == "Linux":
        # Assume TCP for simplicity if not provided
        protocol = rule.get("protocol", "tcp").lower()
        action = rule.get("action", "DROP").upper()
        cmd = (
            f"iptables -A INPUT -s {rule['src_ip']} -d {rule['dst_ip']} "
            f"-p {protocol} --dport {rule['dst_port']} -j {action}"
        )

    elif system == "Windows":
        protocol = rule.get('protocol', 'tcp').lower()
        cmd = (
            f'netsh advfirewall firewall add rule name="Block Suspicious" '
            f'dir=in action=block remoteip={rule["src_ip"]} protocol={protocol}'
        )

    elif system == "Darwin":
        cmd = (
            f"echo '{rule['src_ip']}' | sudo tee -a /etc/pf.blocklist && "
            f"sudo pfctl -f /etc/pf.conf && sudo pfctl -e"
        )

    else:
        raise NotImplementedError(f"Unsupported OS: {system}")

    print(f"[+] Applying firewall rule: {cmd}")

    try:
        subprocess.run(cmd, shell=True, check=True)
        print(f"[+] Rule applied successfully on {system}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to apply rule: {e}")
