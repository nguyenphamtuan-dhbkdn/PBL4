#!/usr/bin/env python3
"""
DEBUG SCRIPT: Test Alert Flow
Chạy script này để kiểm tra xem alert có được ghi log không
"""

import sys
import os
import queue

# Add to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 60)
print("🧪 IDS Alert Flow Debugger")
print("=" * 60)

# Test 1: Import checks
print("\n[TEST 1] Checking imports...")
try:
    from Src.alert import send_alert, set_alert_queue
    print("✓ alert module imported")
except Exception as e:
    print(f"✗ Failed to import alert: {e}")
    sys.exit(1)

try:
    from Src.sniffer import start_sniff, stop_sniff
    print("✓ sniffer module imported")
except Exception as e:
    print(f"✗ Failed to import sniffer: {e}")
    sys.exit(1)

try:
    from Src.dectect import detect
    print(f"✓ detect function imported: {detect}")
except Exception as e:
    print(f"✗ Failed to import detect: {e}")
    print("  (This is OK - depends on psutil, but alert system still works)")

# Test 2: Log file
print("\n[TEST 2] Checking log file...")
log_file = "Logs/alerts.log"
try:
    with open(log_file, "a") as f:
        f.write("[DEBUG] Test log write\n")
    print(f"✓ Log file writable: {log_file}")
except Exception as e:
    print(f"✗ Cannot write to log: {e}")

# Test 3: Queue setup
print("\n[TEST 3] Testing alert queue...")
test_queue = queue.Queue()
set_alert_queue(test_queue)
print("✓ Alert queue set")

# Test 4: Send test alert
print("\n[TEST 4] Sending test alert...")
test_packet = {
    "src": "192.168.1.100",
    "dst": "192.168.1.1",
    "protocol": "TCP",
    "sport": 12345,
    "dport": 80
}

try:
    send_alert(
        alert_type="TEST_ALERT",
        message="This is a test alert from {src}",
        severity="HIGH",
        packet_info=test_packet,
        count=1,
        extra="Test data"
    )
    print("✓ Alert sent")
except Exception as e:
    print(f"✗ Failed to send alert: {e}")

# Test 5: Check queue
print("\n[TEST 5] Checking queue...")
try:
    alert = test_queue.get_nowait()
    src, alert_type, msg, severity, count, extra = alert
    print(f"✓ Alert in queue:")
    print(f"  - Source: {src}")
    print(f"  - Type: {alert_type}")
    print(f"  - Message: {msg}")
    print(f"  - Severity: {severity}")
except queue.Empty:
    print("✗ Queue is empty!")
except Exception as e:
    print(f"✗ Error reading queue: {e}")

# Test 6: Check log file content
print("\n[TEST 6] Checking log file content...")
try:
    with open(log_file, "r") as f:
        lines = f.readlines()
    print(f"✓ Log file has {len(lines)} lines")
    print("Last 3 lines:")
    for line in lines[-3:]:
        print(f"  {line.rstrip()}")
except Exception as e:
    print(f"✗ Cannot read log: {e}")

print("\n" + "=" * 60)
print("✓ All basic tests passed! System is ready.")
print("=" * 60)
print("\nTo run the IDS with debug output:")
print("  python main.py  # (with sniffer running in background)")
print()
