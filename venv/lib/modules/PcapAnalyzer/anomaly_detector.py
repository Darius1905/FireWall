import pandas as pd

KNOW_PORTS = {
    'TCP': {80, 443, 22, 21, 25, 110},
    'UCP': {53, 67, 68, 123, 161, 162}
}

WHITELIST_IPS = {'8.8.8.8', '1.1.1.1'}


def check_ip_anomaly(ip):
    if ip not in WHITELIST_IPS:
        return 'Unknown source IP'

    return None


def check_port_anomaly(port, protocol):
    try:
        port = int(port)

    except:
        return "Invalid port"

    if protocol in KNOW_PORTS:
        if port not in KNOW_PORTS[protocol]:
            return "Unusual destination port"
        return None


def check_protocol_anomaly(protocol):
    if protocol not in KNOW_PORTS:
        return "Unusual protocol"
    return None


def detect_anomalies(df):
    anomalies = []

    for _, row in df.iterrows():
        issues = []

        ip_issue = check_ip_anomaly(row['src_ip'])
        port_issue = check_port_anomaly(row['dst_port'], row['protocol'])
        proto_issue = check_protocol_anomaly(row['protocol'])

        for issue in [ip_issue, port_issue, proto_issue]:
            if issue:
                issues.append(issue)

        if issues:
            anomalies.append({
                'src_ip': row['src_ip'],
                'dst_ip': row['dst_ip'],
                'protocol': row['protocol'],
                'src_port': row['src_port'],
                'dst_port': row['dst_port'],
                'issues': issues
            })
    return anomalies
