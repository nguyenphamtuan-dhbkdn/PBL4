# Src/detect/__init__.py
import yaml, json
from .portscan import PortScanDetector
from .flood import FloodDetector
from .bruteforce import BruteForceDetector

with open("Config/settings.yaml", encoding="utf-8") as f:
    settings = yaml.safe_load(f)
with open("Config/rules.json", encoding="utf-8") as f:
    rules = json.load(f)

detectors = [
    PortScanDetector(settings, rules),
    FloodDetector(settings, rules),
    BruteForceDetector(settings, rules)
]

def detect(packet_info):
    for d in detectors:
        alert = d.analyze(packet_info)
        if alert:
            return alert
    return None
