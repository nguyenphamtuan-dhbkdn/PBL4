# Src/parser.py
from scapy.layers.inet import IP, TCP, UDP, ICMP

def parse_packet(pkt):
    # [TRACE P1] In ra tên lớp đầu tiên của gói tin (ví dụ: 'Ether' hoặc 'ARP')
    print(f"[PARSER DEBUG] Checking Pkt Type: {pkt.summary()}")

    if IP not in pkt:
        # [TRACE P2] Log rằng gói tin bị hủy vì không phải IP
        print("[PARSER DEBUG] Packet DROPPED (Not IP packet).")
        return None

    ip = pkt[IP]
    src_ip = ip.src
    dst_ip = ip.dst
    proto = ip.proto
    length = len(pkt)

    protocol, sport, dport, flags, payload_len = None, None, None, None, 0

    if TCP in pkt:
        t = pkt[TCP]
        protocol = "TCP"
        sport, dport = t.sport, t.dport
        flags = t.sprintf("%TCP.flags%")  # e.g. "S" or "SA"
        payload_len = len(t.payload)
    elif UDP in pkt:
        u = pkt[UDP]
        protocol = "UDP"
        sport, dport = u.sport, u.dport
        payload_len = len(u.payload)
    elif ICMP in pkt:
        protocol = "ICMP"

    return {
        "src": src_ip,
        "dst": dst_ip,
        "protocol": protocol,
        "sport": sport,
        "dport": dport,
        "tcp_flags": flags,
        "length": length,
        "payload_len": payload_len
    }