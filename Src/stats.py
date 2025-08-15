event_counters = {"Port Scan": 0, "Flood Attack": 0}

def update_stats(alert_type):
    if alert_type in event_counters:
        event_counters[alert_type] += 1

def show_stats():
    return event_counters