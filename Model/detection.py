import time
from collections import defaultdict
from . import config

scan_data = defaultdict(list)
flood_data = defaultdict(list)

def detect(packet_info):
    now = time.time()
    src = packet_info["src"]
    port = packet_info["port"]

    # Port scan detection
    if port:
        scan_data[src].append((port, now))
        scan_data[src] = [(p, t) for p, t in scan_data[src] if now - t <= 10]
        unique_ports = set(p for p, _ in scan_data[src])
        if len(unique_ports) >= config.PORT_SCAN_THRESHOLD:
            return f"[ALERT] Port scan detected from {src}"

    # Flood detection
    flood_data[src].append(now)
    flood_data[src] = [t for t in flood_data[src] if now - t <= config.TIME_WINDOW]
    if len(flood_data[src]) >= config.FLOOD_THRESHOLD:
        return f"[ALERT] Flood attack detected from {src}"

    return None
