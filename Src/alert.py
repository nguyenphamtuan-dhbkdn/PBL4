# Src/alert.py
import logging
import json
from Data.models import insert_alert

# file logging - utf-8
log_handler = logging.FileHandler("Logs/alerts.log", encoding="utf-8")
logging.basicConfig(level=logging.INFO, handlers=[log_handler], format="%(asctime)s - %(message)s")

_ALERT_QUEUE = None  # queue.Queue() do GUI set vào bằng set_alert_queue()


def set_alert_queue(q):
    """GUI gọi set_alert_queue(queue) để nhận alert realtime"""
    global _ALERT_QUEUE
    _ALERT_QUEUE = q


def _extra_to_str(extra):
    if not extra:
        return None
    if isinstance(extra, str):
        return extra
    try:
        return " | ".join(f"{k}={v}" for k, v in extra.items())
    except Exception:
        try:
            return json.dumps(extra, ensure_ascii=False)
        except:
            return str(extra)


def send_alert(alert_type, message, severity, packet_info, count=1, extra=None):
    """
    Ghi log, insert DB, và push 1 tuple alert vào queue nếu GUI đăng ký.
    alert tuple: (src, alert_type, full_msg, severity, count, extra)
    """
    src = packet_info.get("src", "unknown")
    dst = packet_info.get("dst", "unknown")
    proto = packet_info.get("protocol", "N/A")
    src_port = packet_info.get("sport") or packet_info.get("src_port")
    dst_port = packet_info.get("dport") or packet_info.get("dst_port") or packet_info.get("port")

    try:
        base_msg = message.format(src=src)
    except Exception:
        base_msg = f"{message} {src}"

    extra_str = _extra_to_str(extra)
    full_msg = base_msg if not extra_str else f"{base_msg} | {extra_str}"

    logging.info(f"[{severity}] {full_msg}")

    # --- 1. GUI PUSH (ƯU TIÊN: Đẩy lên giao diện trước để đảm bảo nhìn thấy) ---
    try:
        if _ALERT_QUEUE is not None:
            _ALERT_QUEUE.put_nowait((src, alert_type, full_msg, severity, count, extra))
            print(">>> [ALERT] PUSHED TO GUI <<<")
    except Exception as e:
        logging.exception("Failed to push alert to GUI queue")
        print(f"!!! GUI QUEUE FAILED: {e}")

    # --- 2. DB INSERTION (Thứ yếu: Nếu lỗi, in ra màn hình để debug DB) ---
    try:
        insert_alert(
            src_ip=src,
            dst_ip=dst,
            protocol=proto,
            attack_type=alert_type,
            severity=severity,
            description=full_msg,
            src_port=src_port,
            dst_port=dst_port,
            packet_count=int(count) if isinstance(count, (int, float, str)) and str(count).isdigit() else count,
            extra_info=extra_str
        )
        print(">>> [DB] Alert inserted successfully. <<<")
    except Exception as e:
        # HIỆN LỖI DB RA CONSOLE NGAY LẬP TỨC
        logging.error(f"[DB ERROR] insert_alert() failed: {e}")
        print(f"!!! [CRITICAL DB ERROR] FAILED TO INSERT ALERT: {e}")
        print("!!! THÔNG BÁO: Lỗi DB có thể khiến hệ thống hoạt động không ổn định !!!")

    # --- END OF send_alert ---