# src/stats.py
from collections import Counter

_total = 0
_proto = Counter()
_src = Counter()
_alerts = Counter()

def feed(packet_info):
    global _total
    _total += 1
    if packet_info.get("protocol"):
        _proto[packet_info["protocol"]] += 1
    if packet_info.get("src"):
        _src[packet_info["src"]] += 1

def inc_alert(kind):
    _alerts[kind] += 1

def snapshot():
    return {
        "total": _total,
        "protocols": _proto.most_common(5),
        "top_src": _src.most_common(5),
        "alerts": _alerts.most_common(5)
    }
def pretty_print():
    s = snapshot()
    print("\n=== STATISTICS ===")
    print(f"Total packets: {s['total']}")
    print("By protocol :", s["protocols"])
    print("Top sources :", s["top_src"])
    print("Alerts      :", s["alerts"])
    print("==================\n")
