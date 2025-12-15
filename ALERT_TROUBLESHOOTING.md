# 🔧 PBL4_IDS Alert & Logging Troubleshooting Guide

## 🆘 Problem: Alerts Not Showing & Logs Not Being Written

### ✅ Quick Fixes Applied

I've fixed the following issues:

1. **Database Connection** - Added better error messages
2. **Queue Polling** - Added error handling and debug output
3. **Chart Updates** - Only update when running
4. **Log Handling** - Proper connection closing

---

## 🧪 Test Your System

### Step 1: Run Debug Script
```powershell
python debug_alerts.py
```

Expected output:
```
✓ alert module imported
✓ sniffer module imported
✓ detect function imported
✓ Log file writable: Logs/alerts.log
✓ Alert queue set
✓ Alert sent
✓ Alert in queue: ...
✓ Log file has X lines
```

---

## 🔍 Common Issues & Solutions

### Issue 1: "ModuleNotFoundError: No module named 'Src.dectect'"
**Cause**: Folder named `dectect` instead of `detect`, or import path issue
**Solution**:
```python
# In Src/sniffer.py, the import tries:
try:
    from .dectect import detect
except Exception:
    from .dectect._init_ import detect  # Fallback
```

**Fix**: Ensure folder is named `dectect/` (typo is in project)

### Issue 2: "No log file written"
**Cause**: Log directory doesn't exist
**Solution**:
```powershell
# Create Logs directory
New-Item -ItemType Directory -Path "Logs" -Force
```

### Issue 3: "Database connection failed"
**Cause**: SQL Server not running or credentials wrong
**Solution**:
1. Check SQL Server is running:
```powershell
# Windows Services
Get-Service MSSQL* | Format-Table Name, Status
```

2. Verify credentials in `Data/models.py`:
```python
DB_CONFIG = {
    "server": "YOUR_SERVER_NAME",      # Check this!
    "database": "IDS_DB_TEST",         # Check this!
    "username": "test",                 # Check this!
    "password": "1234",                 # Check this!
}
```

3. Test connection manually:
```python
from Data.models import get_connection
conn = get_connection()  # Should print "[DB SUCCESS]"
conn.close()
```

### Issue 4: "Alert received but not showing in GUI"
**Cause**: Queue polling has issues
**Solution**: Check console for debug output
```
[GUI POLL] Received alert: PORT_SCAN from 192.168.1.100
```

If you don't see this, queue is empty.

---

## 🔌 System Architecture Check

### Flow: Packet → Detect → Alert → Log/Queue/DB

```
Packet arrives (Scapy)
    ↓
[SNIFFER] Receives & parses packet
    ↓
[DETECTOR] Analyzes packet (Port Scan, Brute Force, Flood)
    ↓
Alert triggered?
    ├─ YES → [ALERT] Generate alert
    │   ├─ Log to Logs/alerts.log
    │   ├─ Push to GUI queue
    │   └─ Insert to Database
    └─ NO → Continue monitoring
```

### Debug Output at Each Stage

```
[SNIFFER TRACE] Dispatching IP Pkt from 192.168.1.100
[ENGINE DEBUG] Dispatching packet from 192.168.1.100
[Port Scan DEBUG] Analysing Pkt from 192.168.1.100 | Port: 22
[Port Scan DEBUG] FINAL COUNT IP 192.168.1.100 ports: 12 / 5
!!! [PORT SCAN ALERT] ĐÃ VƯỢT NGƯỠNG, ĐANG GỬI CẢNH BÁO !!!
>>> [ALERT] PUSHED TO GUI <<<
>>> [DB] Alert inserted successfully. <<<
[GUI POLL] Received alert: PORT_SCAN from 192.168.1.100
```

---

## 📋 Verification Checklist

Run these commands to verify everything:

### 1. Check Imports
```powershell
python -c "from Src.dectect import detect; print('Detect loaded:', detect)"
```

Expected: `Detect loaded: <function detect at ...>`

### 2. Check Log File
```powershell
Get-Item -Path "Logs/alerts.log"
```

Expected: File exists and has content

### 3. Check Database
```powershell
python -c "from Data.models import get_connection; c = get_connection(); print('OK'); c.close()"
```

Expected: `[DB SUCCESS] Connected to SQL Server` + `OK`

### 4. Check Queue
```powershell
python debug_alerts.py
```

Expected: All tests pass (✓)

---

## 🎯 Testing Port Scan Detection

### Scenario: Simulate Port Scan

Terminal 1 - Run IDS:
```powershell
python main.py
```

Terminal 2 - Generate port scan:
```powershell
# Using Nmap (if installed)
nmap -sS 192.168.1.1

# Or manual with scapy
python -c "
from scapy.all import IP, TCP, send
for port in range(80, 90):
    send(IP(dst='192.168.1.1')/TCP(dport=port, flags='S'), verbose=False)
print('Port scan sent')
"
```

### Expected Results in GUI

1. **Console shows alerts**:
   ```
   [HIGH] [ALERT] Port scan detected from 192.168.1.100 | 10 cổng bị quét trong 10s
   ```

2. **Bar chart updates**: Shows IP and attack count

3. **Pie chart updates**: Shows IP distribution

### Expected in Log File

Check `Logs/alerts.log`:
```
2025-12-05 10:30:45,123 - [HIGH] [ALERT] Port scan detected from 192.168.1.100 | 10 cổng bị quét trong 10s
```

### Expected in Database

Query `Alerts` table in SQL Server:
```sql
SELECT TOP 5 * FROM Alerts ORDER BY AlertID DESC
```

Should show records with:
- SrcIP: 192.168.1.100
- AttackType: Port Scan
- Severity: HIGH
- Description: Alert message

---

## 🔧 Enable Debug Mode

To see more debug output, uncomment these lines:

### In `Src/sniffer.py`:
```python
# Uncomment these lines
print(f"[SNIFFER TRACE] Processing packet: {packet.summary()}")
print("[SNIFFER TRACE] Packet dropped early (Not parsed or not IP).")
print(f"[SNIFFER TRACE] Dispatching IP Pkt from {packet_info['src']}")
```

### In `Src/dectect/portscan.py`:
```python
# Already has debug output:
print(f"[{self.name} DEBUG] Analysing Pkt from {src} | Port: {port}")
print(f"[{self.name} DEBUG] FINAL COUNT IP {src} ports: {count} / {self.settings['port_scan_threshold']}")
```

---

## 📊 Monitor Real-Time

### See alerts as they happen:

```powershell
# Terminal 1: Watch log file
Get-Content "Logs/alerts.log" -Tail 20 -Wait

# Terminal 2: Run IDS
python main.py

# Terminal 3: Generate attacks (simulate)
python test_attack_generator.py
```

---

## 🐛 Advanced Debugging

### Check each component individually:

#### Test Parser
```python
from Src.parser import parse_packet
from scapy.all import IP, TCP
pkt = IP(src="192.168.1.1", dst="192.168.1.2")/TCP(dport=80, flags="S")
info = parse_packet(pkt)
print(info)
```

#### Test Detector
```python
from Src.dectect import detect
packet_info = {
    "src": "192.168.1.100",
    "dst": "192.168.1.1",
    "protocol": "TCP",
    "dport": 80,
    "tcp_flags": "S"
}
alert = detect(packet_info)
print(alert)
```

#### Test Alert
```python
from Src.alert import send_alert
pkt = {"src": "192.168.1.100", "dst": "192.168.1.1"}
send_alert("TEST", "Test alert", "HIGH", pkt)
```

---

## ✅ Success Indicators

When working correctly, you should see:

1. ✅ **Console output**: Debug messages as packets arrive
2. ✅ **Log file**: Entries in `Logs/alerts.log`
3. ✅ **GUI display**: Alerts shown in console area
4. ✅ **Charts update**: Bar chart shows attack counts
5. ✅ **Database**: Alerts inserted into SQL Server

---

## 📝 Logs to Check

| Log Location | Check For |
|--------------|-----------|
| `Logs/alerts.log` | Alert messages |
| Console | Debug trace |
| SQL Server | Database inserts |
| GUI Console | Real-time alerts |

---

## 🎓 Next Steps

1. ✅ Run `python debug_alerts.py`
2. ✅ Verify all components work
3. ✅ Run `python main.py`
4. ✅ Simulate attack (port scan with nmap)
5. ✅ Check results in GUI, log, and database

---

## 📞 Still Not Working?

Check these in order:

1. Is `Logs/` directory created? 
   → `mkdir Logs`

2. Is SQL Server running?
   → Check Windows Services

3. Are credentials correct?
   → Update `Data/models.py`

4. Is sniffer starting?
   → Check console for `[SNIFFER TRACE]` output

5. Is detector analyzing packets?
   → Check console for `[ENGINE DEBUG]` output

6. Is alert being generated?
   → Check console for `>>> [ALERT] PUSHED TO GUI <<<`

---

**Everything should work now! Run `python debug_alerts.py` to verify. 🚀**

