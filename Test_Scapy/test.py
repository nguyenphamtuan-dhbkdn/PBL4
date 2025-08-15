from scapy.layers.inet import ICMP, traceroute
from scapy.layers.inet import IP

from scapy.all import *
from scapy.layers.l2 import Ether, ARP

# Tạo gói tin ICMP (ping tới 8.8.8.8)

# packet = IP(dst="8.8.8.8")/ICMP()
# packet.show()   # Hiển thị cấu trúc gói tin

# send(IP(dst="8.8.8.8")/ICMP())   # Gửi ICMP nhưng không chờ phản hồi
# sr1(IP(dst="8.8.8.8")/ICMP())   # Gửi ICMP và chờ nhận phản hồi đầu tiên

# packets = sniff(count=5)   # Bắt 5 gói tin bất kỳ
# packets.summary()          # In tóm tắt
# packets.show()

# sniff(filter="tcp", count=10, prn=lambda x: x.summary())
# # Bắt 10 gói TCP, và in ra từng gói khi nhận

# pkt = IP(dst="8.8.8.8")/ICMP()
# print(pkt[IP].dst)   # Lấy đích IP
# print(pkt[IP].src)   # Lấy nguồn IP

# ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), timeout=2)
# ans.summary()
# unans.summary()

# traceroute(["8.8.8.8", "1.1.1.1"])
# my_ip = socket.gethostbyname(socket.gethostname())
# print(my_ip)


import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QListWidget,
                             QListWidgetItem, QLabel, QVBoxLayout, QWidget)
from PyQt5.QtCore import Qt, QMimeData
from PyQt5.QtGui import QDrag


class DraggableListWidget(QListWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setDragDropMode(QListWidget.DragOnly)
        self.setSelectionMode(QListWidget.SingleSelection)

        # Thêm các item có thể kéo
        items = ["Item 1", "Item 2", "Item 3", "Item 4"]
        for item in items:
            self.addItem(item)


class DropLabel(QLabel):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setAcceptDrops(True)
        self.setAlignment(Qt.AlignCenter)
        self.setStyleSheet("border: 2px dashed gray; padding: 20px;")
        self.dropped_items = []

    def dragEnterEvent(self, event):
        if event.mimeData().hasText():
            event.acceptProposedAction()

    def dropEvent(self, event):
        text = event.mimeData().text()
        self.dropped_items.append(text)
        self.setText(f"Đã thả: {', '.join(self.dropped_items)}")
        event.acceptProposedAction()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Kéo thả với PyQt5")
        self.setGeometry(100, 100, 600, 400)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()

        # Danh sách có thể kéo
        self.list_widget = DraggableListWidget()
        layout.addWidget(QLabel("Kéo các item từ đây:"))
        layout.addWidget(self.list_widget)

        # Vùng thả
        self.drop_area = DropLabel("Thả item vào đây")
        layout.addWidget(QLabel("Thả vào đây:"))
        layout.addWidget(self.drop_area)

        central_widget.setLayout(layout)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())