# Src/detect/base.py
import time

class AttackDetector:
    def __init__(self, name, settings, rules):
        self.name = name
        self.settings = settings
        self.rules = rules
        self.last_alert_time = {}

    def _cooldown_ok(self, src, cooldown=None):
        cd = cooldown or self.settings.get("alert_cooldown", 30)
        now = time.time()
        if now - self.last_alert_time.get(src, 0) >= cd:
            self.last_alert_time[src] = now
            return True
        return False

    def analyze(self, packet):
        """Override ở lớp con"""
        raise NotImplementedError
