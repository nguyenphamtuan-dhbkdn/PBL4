import logging
from Data.models import insert_alert

logging.basicConfig(
    filename="Logs/alerts.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

def send_alert(alert_type, message,severity, packet_info, extra_info=None):
    # print(message)
    logging.info(f"[{severity}] {message}")

    insert_alert(
        src_ip=packet_info["src"],
        dst_ip=packet_info["dst"],
        protocol=packet_info["protocol"] or "N/A",
        attack_type=alert_type,
        severity=severity,
        description=message if not extra_info else f"{message} | {extra_info}"
    )

    # In console nếu severity cao
    if severity in ("HIGH", "CRITICAL"):
        print(f"[{severity}] {message}")
