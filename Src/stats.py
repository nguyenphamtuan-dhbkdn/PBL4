# Src/stats.py
from collections import Counter, defaultdict
from Data.models import insert_traffic

_total = 0
_proto = Counter()
_src = Counter()
_alerts = Counter()
_ip_alerts = defaultdict(Counter)
def reset_stats():
    global _total
    global _proto
    global _src
    global _alerts
    global _ip_alerts
    _total = 0
    _proto.clear()
    _src.clear()
    _alerts.clear()
    _ip_alerts.clear()
def feed(packet_info):
    """Nhận thông tin mỗi gói tin (packet_info từ parser)"""
    global _total
    _total += 1

    src = packet_info.get("src")
    dst = packet_info.get("dst")
    proto = packet_info.get("protocol")
    sport = packet_info.get("sport")
    dport = packet_info.get("port")

    # Đếm
    if proto:
        _proto[proto] += 1
    if src:
        _src[src] += 1

    # Ghi DB
    info = f"{proto} packet from {src}:{sport} to {dst}:{dport}"
    try:
        insert_traffic(src, dst, proto, sport, dport, info, 1)
    except Exception as e:
        print("[DB ERROR in feed()]", e)

def inc_alert(kind, src=None, count=1):
        _alerts[kind] += int(count)
        if src:
            _ip_alerts[src][kind] += int(count)


def snapshot():
    ip_alerts = {ip: dict(counter) for ip, counter in _ip_alerts.items()}
    return {
        "total_packets": _total,
        "protocols": dict(_proto),
        "top_sources": _src.most_common(5),
        "alerts": _alerts.most_common(5),
        "ip_alerts" : ip_alerts
    }

def pretty_print():
    s = snapshot()
    print("\n=== STATISTICS ===")
    print(f"Total Packets : {s['total_packets']}")
    print("Protocols     :", s["protocols"])
    print("Top Sources   :", s["top_sources"])
    print("Alerts        :", s["alerts"])
    print("==================\n")

