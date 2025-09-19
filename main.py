# main.py
from Src.sniffer import start_sniff
from Src.stats import pretty_print
from Data.models import init_db
import threading, time

def stats_printer(interval=30):
    while True:
        time.sleep(interval)
        pretty_print()
if __name__ == "__main__":
    print("[START] IDS Project")
    init_db()
    threading.Thread(target=stats_printer, args=(30,), daemon=True).start()
    try:
        start_sniff()
    except KeyboardInterrupt:
        print("\n[STOP] User stopped IDS.")
    finally:
        print("[EXIT] IDS stopped.")
        print("[FINAL STATS]")
        pretty_print()
