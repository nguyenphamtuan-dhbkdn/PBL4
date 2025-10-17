# Src/sniffer.py
import threading
import yaml
import time
from scapy.all import sniff
from .parser import parse_packet
from .stats import feed, inc_alert

# try import detect (may be package dectect)
try:
    from .dectect import detect
except Exception:
    try:
        from .dectect._init_ import detect
    except Exception:
        # fallback: detect must be provided by your package
        detect = None

# alert/send_alert and queue setter
from .alert import send_alert, set_alert_queue

with open("Config/settings.yaml", encoding="utf-8") as f:
    settings = yaml.safe_load(f)

_iface = settings.get("interface") or None
_sniff_thread = None
_stop_event = threading.Event()

def _process_packet(packet):
    if _stop_event.is_set():
        return
    try:
        packet_info = parse_packet(packet)
        if not packet_info:
            return

        # feed stats
        try:
            feed(packet_info)
        except Exception:
            pass

        # call detect if exists
        result = None
        if callable(detect):
            try:
                result = detect(packet_info)
            except Exception:
                result = None

        if result:
            # normalize result to (alert_type, msg, severity, count, extra)
            if len(result) == 4:
                alert_type, msg, severity, extra = result
                count = extra.get("count") if isinstance(extra, dict) and extra.get("count") else 1
            elif len(result) == 5:
                alert_type, msg, severity, count, extra = result
            else:
                # unknown format -> try best-effort
                try:
                    alert_type, msg, severity = result[0], result[1], result[2]
                    count = 1
                    extra = result[3] if len(result) > 3 else None
                except Exception:
                    return

            # call send_alert to log + insert DB
            try:
                send_alert(alert_type, msg, severity, packet_info, count=count, extra=extra)
            except Exception:
                pass

            # increment in-memory alert counter
            try:
                src_ip = packet_info.get("src")
                inc_alert(alert_type, src=src_ip)
            except Exception:
                pass

    except Exception as e:
        print("[ERROR in _process_packet]", e)

def _sniff_loop(iface=None):
    while not _stop_event.is_set():
        sniff(iface=iface, prn=_process_packet, store=False, timeout=1)

def start_sniff(iface=None):
    """Start sniffing in background thread. Returns True if started."""
    global _sniff_thread, _stop_event, _iface
    if _sniff_thread and _sniff_thread.is_alive():
        return False
    _stop_event.clear()
    _iface = iface or _iface
    _sniff_thread = threading.Thread(target=_sniff_loop, kwargs={"iface": _iface}, daemon=True)
    _sniff_thread.start()
    return True

def stop_sniff():
    global _sniff_thread, _stop_event
    _stop_event.set()
    if _sniff_thread:
        _sniff_thread.join(timeout=2)
    _sniff_thread = None
    return True
