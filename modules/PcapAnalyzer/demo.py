from modules.PcapAnalyzer.anomaly_detector import detect_anomalies
from modules.PcapAnalyzer.flow_extractor import extract_flow
from modules.PcapAnalyzer.connection_analyzer import detect_heavy_senders
from modules.PcapAnalyzer.payload_scanner import scan_payloads
from modules.logger.log_manager import log_anomaly, unify_and_log


def main():
    file_pcap = r"C:\\Users\\Admin\\PycharmProjects\\FireWall\\FileTesting\\test_anomaly.pcap"
    print(f'[+] Currently analyzing {file_pcap} ')

    data = extract_flow(file_pcap)
    print(f'[+] count of flow {len(data)}')

    anomalies = detect_anomalies(data)
    print(f'[!] Detected {len(anomalies)} unusual flows')

    payload_alerts = scan_payloads(file_pcap)
    print(f'[!] Detected {len(payload_alerts)} suspicious payloads')

    sender_alerts = detect_heavy_senders(file_pcap)
    print(f'[!] Detected {len(sender_alerts)} heavy senders')
    if anomalies:
        log_anomaly(anomalies)

    if payload_alerts or sender_alerts:
        unify_and_log(payload_alerts, sender_alerts)


if __name__ == '__main__':
    main()
