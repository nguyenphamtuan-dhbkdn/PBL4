from Src.sniffer import start_sniff
from Src.stats import show_stats
from Data.models import init_db
import threading, time

def stats_printer():
    while True:
        time.sleep(100)
        print("[STATS]", show_stats())

if __name__ == "__main__":
    print("[START] IDS Project")
    init_db()
    threading.Thread(target=stats_printer, daemon=True).start()
    start_sniff()