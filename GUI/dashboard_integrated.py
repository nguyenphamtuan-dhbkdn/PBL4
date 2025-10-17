#GUI/dashboard_integrated
import tkinter as tk
from tkinter import scrolledtext
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import queue

from GUI.history_panel import HistoryPanel
from Src.sniffer import start_sniff, stop_sniff
from Src.stats import snapshot, reset_stats
from Src.alert import set_alert_queue


class IDS_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IDS Dashboard")
        self.root.geometry("1100x700")
        self.root.configure(bg="#f2f2f2")

        self.running = False
        self.ids_thread = None

        self.alert_queue = queue.Queue()
        set_alert_queue(self.alert_queue)

        self._build_layout()

        # Bắt đầu polling (chạy song song)
        self.update_stats_loop()
        self.poll_alerts_loop()

    # ======================================================
    #  Giao diện
    # ======================================================
    def _build_layout(self):
        self.container = tk.Frame(self.root, bg="#f2f2f2")
        self.container.pack(fill=tk.BOTH, expand=True)

        # khung dashboard chính
        self.dashboard_frame = tk.Frame(self.container, bg="#f2f2f2")
        self.dashboard_frame.pack(fill=tk.BOTH, expand=True)

        frame_top = tk.Frame(self.dashboard_frame, bg="#f2f2f2")
        frame_top.pack(pady=10)

        self.btn_start = tk.Button(
            frame_top, text="Bật hệ thống IDS", command=self.toggle_ids,
            bg="#4CAF50", fg="white", font=("Arial", 12), width=20
        )
        self.btn_start.pack(side=tk.LEFT, padx=10)

        self.btn_exit = tk.Button(
            frame_top, text="Thoát", command=self.root.destroy,
            bg="#E53935", fg="white", font=("Arial", 12), width=10
        )
        self.btn_exit.pack(side=tk.LEFT, padx=10)

        self.btn_history = tk.Button(
            frame_top, text="📊 Thống kê lịch sử", command=self.open_history,
            bg="#2196F3", fg="white", font=("Arial", 12), width=18
        )
        self.btn_history.pack(side=tk.LEFT, padx=10)

        tk.Label(self.dashboard_frame, text="📜 Cảnh báo IDS", bg="#f2f2f2",
                 font=("Arial", 13, "bold")).pack(anchor="w", padx=15, pady=5)

        self.console = scrolledtext.ScrolledText(
            self.dashboard_frame, height=12, wrap=tk.WORD, font=("Consolas", 10)
        )
        self.console.pack(fill=tk.BOTH, padx=15, pady=5, expand=False)

        frame_chart = tk.Frame(self.dashboard_frame, bg="#f2f2f2")
        frame_chart.pack(fill=tk.BOTH, expand=True)

        self.fig, (self.ax_bar, self.ax_pie) = plt.subplots(1, 2, figsize=(9, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=frame_chart)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    # ======================================================
    #  Cập nhật biểu đồ
    # ======================================================
    def update_stats_loop(self):
        if self.running:
            self.update_charts()
        self.root.after(5000, self.update_stats_loop)

    def update_charts(self):
        data = snapshot()
        self.ax_bar.clear()
        self.ax_pie.clear()

        ip_alerts = data.get("ip_alerts", {})
        if ip_alerts:
            ips = list(ip_alerts.keys())
            attack_types = sorted({atk for d in ip_alerts.values() for atk in d})

            import numpy as np
            x = np.arange(len(ips))
            bar_width = 0.8 / max(1, len(attack_types))

            for i, attack in enumerate(attack_types):
                values = [ip_alerts[ip].get(attack, 0) for ip in ips]
                self.ax_bar.bar(x + i * bar_width, values, bar_width, label=attack)

            self.ax_bar.set_xticks(x + bar_width * len(attack_types) / 2)
            self.ax_bar.set_xticklabels(ips, rotation=45, ha="right")
            self.ax_bar.set_title("Số lượng tấn công theo IP")
            self.ax_bar.set_xlabel("Địa chỉ IP nguồn")
            self.ax_bar.set_ylabel("Số lần vi phạm")
            self.ax_bar.legend()
        else:
            self.ax_bar.text(0.5, 0.5, "Chưa có dữ liệu", ha="center", va="center")

        if data.get("top_sources"):
            labels, values = zip(*data["top_sources"])
            total = data.get("total_packets", 0)
            self.ax_pie.pie(values, labels=labels, autopct="%1.1f%%", startangle=140)
            self.ax_pie.set_title(f"Tỷ lệ IP nguồn\n(Tổng {total} gói tin)")
        else:
            self.ax_pie.text(0.5, 0.5, "Chưa có dữ liệu", ha="center", va="center")

        self.fig.tight_layout(pad=3.0)
        self.fig.subplots_adjust(bottom=0.25)
        self.ax_bar.margins(y=0.1)
        self.canvas.draw()

    # ======================================================
    #  Đọc alert từ hàng đợi
    # ======================================================
    def poll_alerts_loop(self):
        if self.running:
            try:
                while True:
                    src, alert_type, msg, severity, count, extra = self.alert_queue.get_nowait()
                    text = f"[{severity}] {msg}\n"
                    self.console.insert(tk.END, text)
                    self.console.see(tk.END)
            except queue.Empty:
                pass
        self.root.after(1000, self.poll_alerts_loop)

    # ======================================================
    #  Bật / tắt IDS
    # ======================================================
    def toggle_ids(self):
        if not self.running:
            reset_stats()
            self.ax_bar.clear()
            self.ax_pie.clear()
            self.canvas.draw()
            self.console.delete(1.0, tk.END)

            self.running = True
            self.btn_start.config(text="🛑 Dừng IDS", bg="#E53935")
            self.console.insert(tk.END, "[INFO] IDS đang khởi động...\n")
            self.console.see(tk.END)

            self.ids_thread = threading.Thread(target=self.run_ids, daemon=True)
            self.ids_thread.start()

        else:
            self.running = False
            stop_sniff()
            self.console.insert(tk.END, "[STOP] IDS đã dừng.\n")
            self.console.see(tk.END)
            self.btn_start.config(text="Bật hệ thống IDS", bg="#4CAF50")

    def run_ids(self):
        try:
            start_sniff()
        except Exception as e:
            self.console.insert(tk.END, f"[ERROR] {e}\n")
            self.console.see(tk.END)

    # ======================================================
    #  Lịch sử
    # ======================================================
    def open_history(self):
        self.dashboard_frame.pack_forget()
        self.history_panel = HistoryPanel(self.container, on_back=self.close_history)
        self.history_panel.pack(fill="both", expand=True)

    def close_history(self):
        if hasattr(self, "history_panel"):
            self.history_panel.destroy()
            del self.history_panel
        self.dashboard_frame.pack(fill="both", expand=True)


def run_gui():
    root = tk.Tk()
    app = IDS_GUI(root)
    root.mainloop()
