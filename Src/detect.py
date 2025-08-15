import time
from collections import defaultdict
import socket
import yaml, json

with open("config/settings.yaml") as f:
    settings = yaml.safe_load(f)

with open("config/rules.json") as f:
    rules = json.load(f)

scan_data = defaultdict(list)
flood_data = defaultdict(list)
my_ip = socket.gethostbyname(socket.gethostname())

def detect(packet_info):
    # if not packet_info:
    #     return None
    now = time.time()
    src, dst, port = packet_info["src"], packet_info["dst"], packet_info["port"]

    # if src == my_ip or dst == my_ip:
    #     return None

    # Port scan detection
    if port:
        scan_data[src].append((port, now))
        scan_data[src] = [(p, t) for p, t in scan_data[src] if now - t <= 10]
        unique_ports = set(p for p, _ in scan_data[src])
        if len(unique_ports) >= settings["port_scan_threshold"]:
            severity = "MEDIUM"
            if len(unique_ports) >= settings["port_scan_threshold"] * 2:
                severity = "HIGH"
                if len(unique_ports) >= settings["port_scan_threshold"] * 5:
                    severity = "CRITICAL"
            return (
                "Port Scan",
                rules["alerts"]["port_scan"].format(src=src),
                severity,
                f"IP {src} quét {len(unique_ports)} cổng trong {settings['time_window']}s"
            )

    # Flood detection
    flood_data[src].append(now)
    flood_data[src] = [t for t in flood_data[src] if now - t <= settings["time_window"]]
    if len(flood_data[src]) >= settings["flood_threshold"]:
        severity = "MEDIUM"
        if len(flood_data[src]) >= settings["flood_threshold"] * 2:
            severity = "HIGH"
        if len(flood_data[src]) >= settings["flood_threshold"] * 5:
            severity = "CRITICAL"

        return (
            "Flood Attack",
            rules["alerts"]["flood"].format(src=src),
            severity,
            f"IP {src} gửi {len(flood_data[src])} gói tin trong {settings['time_window']}s"
        )

    return None