

# Lấy địa chỉ IP của host
import socket

from scapy.layers.inet import IP,UDP,TCP
from scapy.sendrecv import sniff

HOST_IP = socket.gethostbyname(socket.gethostname())
print(f"Host IP: {HOST_IP}")

def handle(pkt):
    if IP in pkt:
        ip = pkt[IP]
        # bỏ qua gói có src = host
        if ip.src != HOST_IP:
            proto = "OTHER"
            sport, dport = None, None
            if TCP in pkt:
                proto = "TCP"
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
            elif UDP in pkt:
                proto = "UDP"
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
            print(f"[+] Gói đến từ {ip.src} -> {ip.dst} ({proto} {sport}->{dport})")
            # # Dừng lại sau khi bắt được 1 gói
            # raise KeyboardInterrupt

print("Đang sniff... (Ctrl+C để dừng)")
try:
    sniff(prn=handle, store=False)
except KeyboardInterrupt:
    print("Đã bắt được gói tin cần thiết!")
