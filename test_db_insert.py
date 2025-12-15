# test_db_insert.py
import sys
import os

# Thêm thư mục hiện tại vào đường dẫn để Python tìm thấy module Data
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import hàm insert_alert từ file Data/models.py
try:
    from Data.models import insert_alert

    print(">> Đã import thành công insert_alert")
except ImportError as e:
    print(f"Lỗi Import: {e}")
    sys.exit(1)


def run_test():
    print(">> Đang bắt đầu test insert_alert...")

    # --- DỮ LIỆU GIẢ LẬP ĐỂ TEST ---
    test_src = "192.168.1.50"  # IP nguồn giả
    test_dst = "10.0.0.1"  # IP đích giả
    test_proto = "TCP"  # Giao thức
    test_attack = "TEST_MANUAL"  # Loại tấn công (đặt tên lạ để dễ tìm trong DB)
    test_severity = "LOW"  # Mức độ
    test_desc = "Đây là bản ghi test thủ công từ script python"
    test_sport = 4444  # Cổng nguồn
    test_dport = 80  # Cổng đích
    test_count = 10  # Số gói tin
    test_extra = "Test note 123"  # Thông tin thêm

    # --- GỌI HÀM ---
    try:
        insert_alert(
            src_ip=test_src,
            dst_ip=test_dst,
            protocol=test_proto,
            attack_type=test_attack,
            severity=test_severity,
            description=test_desc,
            src_port=test_sport,
            dst_port=test_dport,
            packet_count=test_count,
            extra_info=test_extra
        )
        print(">> Hàm insert_alert đã chạy xong (không báo lỗi Exception).")
        print(">> Hãy kiểm tra trong SQL Server xem có bản ghi mới không.")
    except Exception as e:
        print(f"!!! Lỗi khi chạy insert_alert: {e}")


if __name__ == "__main__":
    run_test()