# Src/detect/portscan.py
import time
from collections import defaultdict
from .base import AttackDetector
from .utils import LOCAL_IPS

class PortScanDetector(AttackDetector):
    def __init__(self, settings, rules):
        super().__init__("Port Scan", settings, rules)
        self.history = defaultdict(list)

    def analyze(self, pkt):
        proto = pkt["protocol"]
        src, dst, port, flags = pkt["src"], pkt["dst"], pkt.get("dport"), pkt.get("tcp_flags")

        if src in LOCAL_IPS:
            return None

        now = time.time()

        if proto == "TCP" and flags and "S" in flags and "A" not in flags:
            self.history[src].append((port, now))
        elif proto == "UDP":
            self.history[src].append((port, now))

        win = self.settings.get("port_scan_window", 10)
        self.history[src] = [(p, t) for p, t in self.history[src] if now - t <= win]

        unique_ports = {p for p, _ in self.history[src] if p}
        count = len(unique_ports)
        if len(unique_ports) >= self.settings["port_scan_threshold"]:
            sev = self._severity(len(unique_ports))
            if self._cooldown_ok(src):
                msg = self.rules["alerts"]["port_scan"].format(src=src)
                extra = f"{len(unique_ports)} cổng bị quét trong {win}s"
                return ("Port Scan", msg, sev,count, extra)
        return None

    def _severity(self, n):
        base = self.settings["port_scan_threshold"]
        if n >= base * 5: return "CRITICAL"
        if n >= base * 2: return "HIGH"
        return "MEDIUM"
