#Data/models.py
import pyodbc
import os
from datetime import datetime

# ================== CONFIG ==================
DB_CONFIG = {
    "server": "LAPTOP-TDCQKAU9\\SQLEXPRESS",
    "database": "IDS_DB_TEST",
    "username": "test",
    "password": "1234",
    "driver": "ODBC Driver 17 for SQL Server"
}

# ================== CONNECTION ==================
def get_connection():
    """Kết nối SQL Server"""
    try:
        conn = pyodbc.connect(
            f"DRIVER={{{DB_CONFIG['driver']}}};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        print("[DB SUCCESS] Connected to SQL Server")
        return conn
    except Exception as e:
        print(f"[DB ERROR] Cannot connect to SQL Server: {e}")
        print(f"[DB INFO] Server: {DB_CONFIG['server']}, DB: {DB_CONFIG['database']}")
        raise

# ================== INSERT ALERT ==================
def insert_alert(src_ip, dst_ip, protocol, attack_type, severity, description,
                 src_port=None, dst_port=None, packet_count=1, extra_info=None):
    """Thêm một bản ghi cảnh báo (alert) vào DB"""
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO Alerts (SrcIP, DstIP, Protocol, SrcPort, DstPort,
                                AttackType, Severity, Description, PacketCount, ExtraInfo)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (src_ip, dst_ip, protocol, src_port, dst_port,
              attack_type, severity, description, packet_count, extra_info))
        conn.commit()
        print(f"[DB OK] Alert inserted: {attack_type} from {src_ip}")
    except Exception as e:
        print(f"[DB ERROR] insert_alert() failed: {e}")
        print(f"[DB DEBUG] Params: src_ip={src_ip}, attack_type={attack_type}, severity={severity}")
    finally:
        if conn:
            conn.close()

# ================== INSERT TRAFFIC ==================
def insert_traffic(src_ip, dst_ip, protocol, src_port, dst_port, info, packet_count=1):
    """Thêm thống kê traffic (mỗi gói tin / tổng hợp)"""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO Traffic (SrcIP, DstIP, Protocol, SrcPort, DstPort, PacketCount, Info)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (src_ip, dst_ip, protocol, src_port, dst_port, packet_count, info))
        conn.commit()
    except Exception as e:
        print(f"[DB ERROR] insert_traffic() failed: {e}")
    finally:
        conn.close()

# ================== QUERY FUNCTIONS ==================
def get_attack_summary():
    """Truy vấn tổng số lượng từng loại tấn công"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT AttackType, COUNT(*) AS Count
        FROM Alerts
        GROUP BY AttackType
        ORDER BY Count DESC
    """)
    results = cursor.fetchall()
    conn.close()
    return [(r[0], r[1]) for r in results]

def get_top_attackers(limit=10):
    """Truy vấn IP tấn công nhiều nhất"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(f"""
        SELECT TOP {limit} SrcIP, COUNT(*) AS Count
        FROM Alerts
        GROUP BY SrcIP
        ORDER BY Count DESC
    """)
    results = cursor.fetchall()
    conn.close()
    return [(r[0], r[1]) for r in results]

def init_db():
    """Khởi tạo database từ schema.sql"""
    conn = get_connection()
    cursor = conn.cursor()
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        sql_script = f.read()
    statements = [stmt.strip() for stmt in sql_script.split("GO") if stmt.strip()]
    for stmt in statements:
        try:
            cursor.execute(stmt)
        except Exception as e:
            print(f"[DB ERROR] {e}\nSQL: {stmt[:100]}...")
    conn.commit()
    conn.close()
    print("[DB] Schema initialized successfully.")
def get_distinct_alert_ips(limit=1000):
    """Trả về danh sách IP nguồn có trong bảng Alerts (unique, có sort theo count)"""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT SrcIP, COUNT(*) AS cnt
            FROM Alerts
            GROUP BY SrcIP
            ORDER BY cnt DESC
        """)
        rows = cur.fetchall()
        ips = [r[0] for r in rows if r[0]]
        return ips[:limit]
    finally:
        conn.close()

def query_alerts(start_dt, end_dt, src_ip=None, limit=10000):
    """
    Truy vấn alerts theo thời gian và IP.
    start_dt, end_dt: datetime or string ISO (YYYY-MM-DD HH:MM:SS)
    src_ip: nếu None => tất cả IP
    Trả về list of dict: [{Id, Timestamp, SrcIP, DstIP, Protocol, AttackType, Severity, Description}, ...]
    """
    # convert datetimes to string if needed
    if isinstance(start_dt, datetime):
        s = start_dt.strftime("%Y-%m-%d %H:%M:%S")
    else:
        s = str(start_dt)
    if isinstance(end_dt, datetime):
        e = end_dt.strftime("%Y-%m-%d %H:%M:%S")
    else:
        e = str(end_dt)

    conn = get_connection()
    cur = conn.cursor()
    try:
        if src_ip:
            sql = """
                SELECT Id, Timestamp, SrcIP, DstIP, Protocol, AttackType, Severity, Description
                FROM Alerts
                WHERE Timestamp >= ? AND Timestamp <= ? AND SrcIP = ?
                ORDER BY Timestamp ASC
            """
            cur.execute(sql, (s, e, src_ip))
        else:
            sql = """
                SELECT Id, Timestamp, SrcIP, DstIP, Protocol, AttackType, Severity, Description
                FROM Alerts
                WHERE Timestamp >= ? AND Timestamp <= ?
                ORDER BY Timestamp ASC
            """
            cur.execute(sql, (s, e))

        rows = cur.fetchmany(limit)
        result = []
        for r in rows:
            result.append({
                "Id": r[0],
                "Timestamp": r[1],
                "SrcIP": r[2],
                "DstIP": r[3],
                "Protocol": r[4],
                "AttackType": r[5],
                "Severity": r[6],
                "Description": r[7]
            })
        return result
    finally:
        conn.close()
