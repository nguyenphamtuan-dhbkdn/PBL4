# Src/detect.py
import time
from collections import defaultdict
import socket, yaml, json, os

with open("Config/settings.yaml", encoding="utf-8") as f:
    settings = yaml.safe_load(f)

with open("Config/rules.json",encoding="utf-8") as f:
    rules = json.load(f)

scan_data = defaultdict(list)
flood_data = defaultdict(list)
last_alert_time = defaultdict(float)

def _my_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return None

MY_IP = _my_ip()

def _cooldown_ok(src, attack_type):
    cd = settings.get("alert_cooldown", 30)
    now = time.time()
    key = (src, attack_type)
    if now - last_alert_time.get(key, 0) >= cd:
        last_alert_time[key] = now
        return True
    return False

def detect(packet_info):
    if not packet_info:
        return None

    now = time.time()
    src, dst = packet_info["src"], packet_info["dst"]
    port, proto, flags = packet_info["port"], packet_info["protocol"], packet_info.get("tcp_flags")

    # chỉ inbound nếu mode host
    if settings.get("mode", "host") == "host" and dst != MY_IP:
        return None

    # ---- Port scan detection ----
    if proto == "TCP" and flags and "S" in flags and "A" not in flags:
        scan_data[src].append((port, now))
    elif proto == "UDP":
        scan_data[src].append((port, now))

    # cleanup
    win = settings.get("port_scan_window", 10)
    scan_data[src] = [(p, t) for p, t in scan_data[src] if now - t <= win]
    unique_ports = set(p for p, _ in scan_data[src] if p)

    if len(unique_ports) >= settings["port_scan_threshold"]:
        sev = "MEDIUM"
        if len(unique_ports) >= settings["port_scan_threshold"] * 2:
            sev = "HIGH"
        if len(unique_ports) >= settings["port_scan_threshold"] * 5:
            sev = "CRITICAL"

        if _cooldown_ok(src, "Port Scan"):
            return (
                "Port Scan",
                rules["alerts"]["port_scan"].format(src=src),
                sev,
                f"IP {src} quet {len(unique_ports)} cong trong {win}s"
            )

    # ---- Flood detection ----
    flood_data[src].append(now)
    tw = settings.get("time_window", 5)
    flood_data[src] = [t for t in flood_data[src] if now - t <= tw]

    if len(flood_data[src]) >= settings["flood_threshold"]:
        sev = "MEDIUM"
        if len(flood_data[src]) >= settings["flood_threshold"] * 2:
            sev = "HIGH"
        if len(flood_data[src]) >= settings["flood_threshold"] * 5:
            sev = "CRITICAL"

        if _cooldown_ok(src, "Flood Attack"):
            return (
                "Flood Attack",
                rules["alerts"]["flood"].format(src=src),
                sev,
                f"IP {src} gui {len(flood_data[src])} goi tin trong {tw}s"
            )

    return None
