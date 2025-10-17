# Src/detect/flood.py
import time
from collections import defaultdict
from .base import AttackDetector
from .utils import LOCAL_IPS

class FloodDetector(AttackDetector):
    def __init__(self, settings, rules):
        super().__init__("Flood Attack", settings, rules)
        self.history = defaultdict(list)

    def analyze(self, pkt):
        src = pkt["src"]
        if src in LOCAL_IPS:
            return None

        now = time.time()
        self.history[src].append(now)

        win = self.settings.get("time_window", 5)
        self.history[src] = [t for t in self.history[src] if now - t <= win]
        count = len(self.history[src])

        if count >= self.settings["flood_threshold"]:
            sev = self._severity(count)
            if self._cooldown_ok(src):
                msg = self.rules["alerts"]["flood"].format(src=src)
                extra = f"{count} gói tin gửi trong {win}s"
                return ("Flood Attack", msg, sev,count, extra)
        return None

    def _severity(self, n):
        base = self.settings["flood_threshold"]
        if n >= base * 5: return "CRITICAL"
        if n >= base * 2: return "HIGH"
        return "MEDIUM"
