from Model import packet_sniffer, packet_parser, detection, alert

def handle_packet(packet):
    info = packet_parser.parse_packet(packet)
    if info:
        result = detection.detect(info)
        if result:
            alert.send_alert(result)

if __name__ == "__main__":
    print("[*] Starting IDS...")
    packet_sniffer.start_sniff(handle_packet)
