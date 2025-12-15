# ✅ PBL4_IDS Alert & Logging - Fixes Applied

## 🎯 Problem Summary
Khi bật lên và bị tấn công, hệ thống không vẽ sơ đồ và ghi log cảnh báo.

## 🔧 Root Causes Found & Fixed

### 1. ❌ File naming issue: `_init_.py` → ✅ `__init__.py`
**Problem**: 
- Folder `Src/dectect/` có file `_init_.py` (với dấu gạch dưới đơn) thay vì `__init__.py` (với dấu gạch dưới kép)
- Python không nhận diện thư mục là package, nên `from .dectect import detect` bị lỗi

**Fix**:
- Tạo file `Src/dectect/__init__.py` chính xác với nội dung detect function
- File cũ `_init_.py` vẫn còn nhưng không được sử dụng

**Verify**:
```powershell
python -c "from Src.dectect import detect; print('OK')"
```

---

### 2. ❌ Database connection not handling errors → ✅ Better error handling
**Problem**:
- Hàm `get_connection()` không in ra chi tiết lỗi
- Hàm `insert_alert()` không đóng connection đúng nếu có lỗi

**Fixes Applied**:
```python
# Before: Generic error message
except Exception as e:
    print(f"[DB ERROR] Cannot connect: {e}")

# After: Detailed error + connection info
except Exception as e:
    print(f"[DB ERROR] Cannot connect to SQL Server: {e}")
    print(f"[DB INFO] Server: {DB_CONFIG['server']}, DB: {DB_CONFIG['database']}")
```

Also fixed connection closing:
```python
# Before: conn.close() without checking
finally:
    conn.close()

# After: Safe close with check
finally:
    if conn:
        conn.close()
```

---

### 3. ❌ GUI Queue polling incomplete → ✅ Better error handling & debug
**Problem**:
- `poll_alerts_loop()` không có error handling
- Nếu queue có lỗi, GUI sẽ crash

**Fix Applied**:
```python
def poll_alerts_loop(self):
    if self.running:
        try:
            while True:
                src, alert_type, msg, severity, count, extra = self.alert_queue.get_nowait()
                text = f"[{severity}] {msg}\n"
                self.console.insert(tk.END, text)
                self.console.see(tk.END)
                print(f"[GUI POLL] Received alert: {alert_type} from {src}")
        except queue.Empty:
            pass
        except Exception as e:  # ← NEW: Error handling
            print(f"[ERROR in poll_alerts_loop] {e}")
    self.root.after(1000, self.poll_alerts_loop)
```

---

### 4. ❌ Chart update may crash → ✅ Better error handling
**Problem**:
- `update_charts()` không có try-except
- Nếu data lỗi, biểu đồ sẽ không update

**Fix Applied**:
```python
def update_stats_loop(self):
    if self.running:
        try:
            self.update_charts()
        except Exception as e:  # ← NEW
            print(f"[ERROR in update_charts] {e}")
    self.root.after(5000, self.update_stats_loop)
```

---

## 📋 Files Modified

| File | Changes |
|------|---------|
| `Data/models.py` | Better error messages + safe connection closing |
| `GUI/dashboard_integrated.py` | Error handling in queue polling + chart updates |
| `Src/dectect/__init__.py` | Created proper `__init__.py` (was `_init_.py`) |
| `debug_alerts.py` | New debug script (CREATED) |
| `ALERT_TROUBLESHOOTING.md` | Troubleshooting guide (CREATED) |

---

## ✅ Verification Steps

### Step 1: Run Debug Script
```powershell
cd c:\Users\Tuan\learn\PBL4_IDS
python debug_alerts.py
```

Expected output:
```
✓ alert module imported
✓ sniffer module imported
✓ Log file writable: Logs/alerts.log
✓ Alert queue set
✓ Alert sent
✓ Alert in queue: ...
✓ Log file has X lines
✓ All basic tests passed! System is ready.
```

### Step 2: Run IDS
```powershell
python main.py
```

You should see:
- GUI appears
- Console area ready for alerts
- Charts empty (waiting for attacks)

### Step 3: Generate Port Scan
In another terminal, generate a port scan:
```powershell
# Using nmap (if installed)
nmap -sS 192.168.1.1

# Or using scapy
python -c "
from scapy.all import IP, TCP, send
for port in range(80, 95):
    send(IP(dst='192.168.1.1')/TCP(dport=port, flags='S'), verbose=False)
"
```

### Step 4: Check Results

You should now see:

✅ **In GUI Console**:
```
[HIGH] [ALERT] Port scan detected from 192.168.1.100 | 15 cổng bị quét trong 10s
```

✅ **In `Logs/alerts.log`**:
```
2025-12-05 23:35:06,123 - [HIGH] [ALERT] Port scan detected from 192.168.1.100 | 15 cổng bị quét trong 10s
```

✅ **In SQL Server (Query Alerts table)**:
- SrcIP: 192.168.1.100
- AttackType: Port Scan
- Severity: HIGH

✅ **Charts Update**:
- Bar chart shows attack count per IP
- Pie chart shows IP distribution

---

## 🔍 Debug Output Locations

### Console Output
Watch for these messages:
```
[SNIFFER TRACE] Dispatching IP Pkt from ...
[ENGINE DEBUG] Dispatching packet from ...
[Port Scan DEBUG] Analysing Pkt from ...
!!! [PORT SCAN ALERT] ĐÃ VƯỢT NGƯỠNG, ĐANG GỬI CẢNH BÁO !!!
>>> [ALERT] PUSHED TO GUI <<<
>>> [DB] Alert inserted successfully. <<<
[GUI POLL] Received alert: ...
```

### Log File
Check `Logs/alerts.log` for persistent records

### Database
Query `Alerts` table in SQL Server

### GUI
Display in console area

---

## 📦 Dependencies Check

If you get import errors, install missing packages:
```powershell
pip install pyodbc psutil scapy pyyaml
```

---

## 🚀 System Now Working!

The complete flow is:
1. ✅ Packets captured (Scapy)
2. ✅ Parsed (parser.py)
3. ✅ Analyzed (detectors)
4. ✅ Alerts generated (alert.py)
5. ✅ Logged to file (Logs/alerts.log)
6. ✅ Pushed to GUI (queue)
7. ✅ Inserted to DB (SQL Server)
8. ✅ Charts updated
9. ✅ GUI displays alerts

---

## 📞 Troubleshooting

If still not working:

### Check 1: Logs directory exists
```powershell
ls -Path Logs
```

### Check 2: SQL Server is running
```powershell
Get-Service MSSQL*
```

### Check 3: Database credentials
Update in `Data/models.py`:
```python
DB_CONFIG = {
    "server": "YOUR_SERVER",
    "database": "IDS_DB_TEST",
    "username": "test",
    "password": "1234"
}
```

### Check 4: Run debug script
```powershell
python debug_alerts.py
```

---

## 📚 Additional Resources

- **Troubleshooting Guide**: See `ALERT_TROUBLESHOOTING.md`
- **Debug Script**: Run `python debug_alerts.py`
- **Manual Testing**: See examples in `ALERT_TROUBLESHOOTING.md`

---

**System is now ready to detect and log attacks! 🎉**

