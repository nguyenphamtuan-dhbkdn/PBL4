from scapy.all import sniff
from .parser import parse_packet
from .detect import detect
from .alert import send_alert
from .stats import update_stats
import yaml

with open("config/settings.yaml") as f:
    settings = yaml.safe_load(f)

def start_sniff():
    interface = settings["interface"]
    print(f"[INFO] IDS listening on {interface or 'default'}...")

    def process(packet):
        packet_info = parse_packet(packet)
        if packet_info:
            result = detect(packet_info)
            if result:
                alert_type, alert_msg, severity, extra_info = result
                send_alert(alert_type, alert_msg, severity, packet_info, extra_info)
                update_stats(alert_type)

    sniff(iface=interface, prn=process, store=False)
