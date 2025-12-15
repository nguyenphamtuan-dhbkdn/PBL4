# Src/detect/portscan.py - PHIÊN BẢN FIX CUỐI CÙNG
import time
from collections import defaultdict
from .base import AttackDetector
from .utils import LOCAL_IPS  # Giữ nguyên import


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

        # Logic kiểm tra gói TCP SYN/UDP
        if proto == "TCP" and flags and "S" in flags and "A" not in flags:
            self.history[src].append((port, now))
        elif proto == "UDP":
            self.history[src].append((port, now))

        # Nếu gói tin không phải SYN/UDP thì thoát (return None) ngay tại đây
        if not (proto == "TCP" or proto == "UDP"):
            return None

        win = self.settings.get("port_scan_window", 10)
        # Lọc các gói tin đã quá hạn 10s
        self.history[src] = [(p, t) for p, t in self.history[src] if now - t <= win]

        # Tính số cổng duy nhất
        unique_ports = {p for p, _ in self.history[src] if p}
        count = len(unique_ports)

        # --- TRACE 2: Báo cáo số cổng đếm được ---
        print(f"[{self.name} DEBUG] FINAL COUNT IP {src} ports: {count} / {self.settings['port_scan_threshold']}")

        if count >= self.settings["port_scan_threshold"]:
            sev = self._severity(len(unique_ports))
            if self._cooldown_ok(src):
                # --- TRACE 3: Báo động được kích hoạt ---
                print("!!! [PORT SCAN ALERT] ĐÃ VƯỢT NGƯỠNG, ĐANG GỬI CẢNH BÁO !!!")
                msg = self.rules["alerts"]["port_scan"].format(src=src)
                extra = f"{len(unique_ports)} cổng bị quét trong {win}s"
                return ("Port Scan", msg, sev, count, extra)
        return None

    def _severity(self, n):
        base = self.settings["port_scan_threshold"]
        if n >= base * 5: return "CRITICAL"
        if n >= base * 2: return "HIGH"
        return "MEDIUM"