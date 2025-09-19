# Src/alert.py
import logging
from Data.models import insert_alert

logging.basicConfig(
    filename="Logs/alerts.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

def send_alert(alert_type, message, severity, packet_info, extra=None):
    desc = message if not extra else f"{message} | {extra}"
    logging.info(f"[{severity}] {desc}")

    try:
        insert_alert(
            packet_info["src"],
            packet_info["dst"],
            packet_info.get("protocol") or "N/A",
            alert_type,
            severity,
            desc
        )
    except Exception as e:
        logging.error(f"DB insert fail: {e}")

    if severity in ("HIGH", "CRITICAL"):
        print(f"[{severity}] {desc}")
