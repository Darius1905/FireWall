def generate_rule(anomalies):
    rules = []
    for anomaly in anomalies:
        src_ip = anomaly.get('src_ip')
        dst_ip = anomaly.get('dst_ip')
        src_port = anomaly.get('src_port')
        dst_port = anomaly.get('dst_port')
        protocol = anomaly.get('protocol', 'tcp').lower()

        rule = {
            'action': 'DROP',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol
        }
        rules.append(rule)
    return rules
