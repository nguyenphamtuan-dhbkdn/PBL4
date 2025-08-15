from scapy.layers.inet import IP, TCP, UDP

def parse_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol, port = None, None

        if TCP in packet:
            protocol = "TCP"
            port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            port = packet[UDP].dport

        return {"src": src_ip, "dst": dst_ip, "protocol": protocol, "port": port}
    return None