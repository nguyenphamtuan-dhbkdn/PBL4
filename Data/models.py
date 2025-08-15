import pyodbc
import os

# ================== CONFIG ==================
DB_CONFIG = {
    "server": "ADMIN\\VANQUI",
    "database": "IDS_DB",
    "username": "sa",
    "password": "Password.1",
    "driver": "ODBC Driver 17 for SQL Server"
}

# ================== CONNECTION ==================
def get_connection():
    try:
        conn = pyodbc.connect(
            f"DRIVER={{{DB_CONFIG['driver']}}};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        return conn
    except Exception as e:
        print(f"[DB ERROR] Cannot connect: {e}")
        raise

# ================== INSERT FUNCTIONS ==================
def insert_alert(src_ip, dst_ip, protocol, attack_type, severity, description, extra_info=None):
    """Thêm một alert vào DB"""
    conn = get_connection()
    cursor = conn.cursor()
    if extra_info:
        description = f"{description} | {extra_info}"

    cursor.execute("""
        INSERT INTO Alerts (SrcIP, DstIP, Protocol, AttackType, Severity, Description)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (src_ip, dst_ip, protocol, attack_type, severity, description))

    conn.commit()
    conn.close()


def insert_traffic(src_ip, dst_ip, protocol, info,packet_count):
    """Thêm thống kê traffic vào DB"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO Traffic (SrcIP, DstIP, Protocol, Info,PacketCount)
        VALUES (?, ?, ?, ?, ?)
    """, (src_ip, dst_ip, protocol, info,packet_count))

    conn.commit()
    conn.close()

# ================== INIT DB ==================
def init_db():
    """Chạy schema.sql để tạo bảng nếu chưa có"""
    conn = get_connection()
    cursor = conn.cursor()

    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        sql_script = f.read()

    # Xử lý script: tách theo GO
    statements = [stmt.strip() for stmt in sql_script.split("GO") if stmt.strip()]

    for stmt in statements:
        try:
            cursor.execute(stmt)
        except Exception as e:
            print(f"[DB ERROR] Lỗi khi chạy lệnh SQL: {e}\n---SQL---\n{stmt}\n")

    conn.commit()
    conn.close()
    print("[DB] Database initialized from schema.sql.")
