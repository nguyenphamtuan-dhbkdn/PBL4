#Src/sniffer.py
from scapy.all import sniff
from .parser import parse_packet
from .detect import detect
from .alert import send_alert
from .stats import feed, inc_alert
import yaml

with open("Config/settings.yaml", encoding="utf-8") as f:
    settings = yaml.safe_load(f)

def start_sniff():
    interface = settings.get("interface")
    print(f"[INFO] IDS listening on {interface or 'default'}...")

    def process(packet):
        try:
            packet_info = parse_packet(packet)
            if not packet_info:
                return
            feed(packet_info)  # thống kê
            result = detect(packet_info)
            if result:
                alert_type, msg, severity, extra = result
                send_alert(alert_type, msg, severity, packet_info, extra)
                inc_alert(alert_type)
        except Exception as e:
            print("[ERROR in process()]", e)


    sniff(iface=interface, prn=process, store=False)
