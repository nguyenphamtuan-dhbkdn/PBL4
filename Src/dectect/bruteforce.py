# Src/detect/bruteforce.py
import time
from collections import defaultdict
from .base import AttackDetector
from .utils import LOCAL_IPS

class BruteForceDetector(AttackDetector):
    def __init__(self, settings, rules):
        super().__init__("Brute Force", settings, rules)
        self.attempts = defaultdict(list)

    def analyze(self, pkt):
        src, port = pkt["src"], pkt.get("dport")

        if src in LOCAL_IPS:
            return None

        if port not in (21, 22, 80, 443):  # ftp, ssh, web login
            return None

        now = time.time()
        self.attempts[src].append(now)
        win = self.settings.get("bruteforce_window", 15)
        self.attempts[src] = [t for t in self.attempts[src] if now - t <= win]

        count = len(self.attempts[src])
        if count >= self.settings.get("bruteforce_threshold", 10):
            sev = self._severity(count)
            if self._cooldown_ok(src):
                msg = self.rules["alerts"]["brute_force"].format(src=src)
                extra = f"{count} lần kết nối đến port {port} trong {win}s"
                return ("Brute-force", msg, sev,count, extra)
        return None

    def _severity(self, n):
        base = self.settings.get("bruteforce_threshold", 10)
        if n >= base * 5: return "CRITICAL"
        if n >= base * 2: return "HIGH"
        return "MEDIUM"
