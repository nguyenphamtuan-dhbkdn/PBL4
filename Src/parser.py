# src/parser.py
from scapy.layers.inet import IP, TCP, UDP

def parse_packet(pkt):
    if IP not in pkt:
        return None

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    protocol, port, flags = None, None, None

    if TCP in pkt:
        protocol = "TCP"
        port = pkt[TCP].dport
        flags = str(pkt[TCP].flags)
    elif UDP in pkt:
        protocol = "UDP"
        port = pkt[UDP].dport

    return {
        "src": src_ip,
        "dst": dst_ip,
        "protocol": protocol,
        "port": port,
        "tcp_flags": flags
    }
