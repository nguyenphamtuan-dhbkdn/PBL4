import socket
import psutil

def get_local_ips():
    """Trả về danh sách các địa chỉ IP cục bộ của máy đang giám sát"""
    local_ips = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                local_ips.append(addr.address)
    return local_ips

# Danh sách IP cục bộ khi chương trình khởi động
LOCAL_IPS = get_local_ips()
