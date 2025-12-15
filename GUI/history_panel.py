# GUI/history_panel.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from datetime import datetime, timedelta
import threading
import csv
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from Data.models import get_distinct_alert_ips, query_alerts
import numpy as np
import matplotlib.dates as mdates

DATE_FMT = "%Y-%m-%d %H:%M"

class HistoryPanel(tk.Frame):
    def __init__(self, parent, on_back=None):
        super().__init__(parent, bg="white")
        self.pack(fill=tk.BOTH, expand=True)
        self.on_back = on_back
        self._build_ui()

    def _build_ui(self):
        # Top controls
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=8, pady=6)

        back_btn = ttk.Button(top, text="⬅ Quay lại Dashboard", command=self._go_back)
        back_btn.grid(row=0, column=0, padx=(0, 10))

        ttk.Label(top, text="From (YYYY-MM-DD HH:MM)").grid(row=0, column=1, sticky="w")
        self.from_entry = ttk.Entry(top, width=20)
        self.from_entry.grid(row=0, column=2, padx=4)
        today = datetime.now()
        self.from_entry.insert(0, today.strftime("%Y-%m-%d 00:00"))

        ttk.Label(top, text="To (YYYY-MM-DD HH:MM)").grid(row=0, column=3, sticky="w")
        self.to_entry = ttk.Entry(top, width=20)
        self.to_entry.grid(row=0, column=4, padx=4)
        # leave blank by default to allow end-of-day behavior
        # self.to_entry.insert(0, (today + timedelta(days=0)).strftime("%Y-%m-%d 23:59"))

        ttk.Label(top, text="IP (All để tất cả)").grid(row=0, column=5, sticky="w", padx=(8, 0))
        self.ip_combo = ttk.Combobox(top, width=20)
        self.ip_combo.grid(row=0, column=6, padx=4)
        self._load_ips()

        self.btn_query = ttk.Button(top, text="Thống kê", command=self.on_query)
        self.btn_query.grid(row=0, column=7, padx=8)

        self.btn_export = ttk.Button(top, text="Export CSV", command=self.on_export)
        self.btn_export.grid(row=0, column=8, padx=4)

        # Middle layout: left alerts, right charts
        mid = ttk.Frame(self)
        mid.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        # Left: alerts list
        left = ttk.Frame(mid)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        ttk.Label(left, text="Alerts (chi tiết)").pack(anchor="w")
        self.alert_box = scrolledtext.ScrolledText(left, height=20, width=60, font=("Consolas", 9))
        self.alert_box.pack(fill=tk.BOTH, expand=True)

        # Right: charts
        right = ttk.Frame(mid)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Frame chứa biểu đồ 1 (Top IPs)
        self.chart_frame_top = ttk.LabelFrame(right, text="Biểu đồ 1: Top IPs theo loại tấn công")
        self.chart_frame_top.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Frame chứa biểu đồ 2 (tần suất theo thời gian)
        self.chart_frame_bottom = ttk.LabelFrame(right, text="Biểu đồ 2: Tần suất tấn công theo thời gian")
        self.chart_frame_bottom.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)


    def _go_back(self):
        """Destroy panel and call callback"""
        if callable(self.on_back):
            try:
                self.on_back()
            except Exception:
                pass
        # destroy self to free resources and stop canvas drawing
        self.destroy()

    def _load_ips(self):
        try:
            ips = get_distinct_alert_ips()
            ips = ["All"] + ips
            self.ip_combo['values'] = ips
            self.ip_combo.set("All")
        except Exception as e:
            print("Load IPs failed:", e)
            self.ip_combo['values'] = ["All"]
            self.ip_combo.set("All")

    def _parse_dt(self, text, allow_empty=False):
        txt = (text or "").strip()
        if txt == "":
            if allow_empty:
                return None
            raise ValueError("Sai định dạng ngày giờ hoặc để trống.")
        try:
            return datetime.strptime(txt, DATE_FMT)
        except Exception as e:
            raise ValueError(f"Sai định dạng ngày giờ, dùng {DATE_FMT}") from e

    def on_query(self):
        """Start DB query in background thread."""
        try:
            start = self._parse_dt(self.from_entry.get().strip(), allow_empty=False)
            end = self._parse_dt(self.to_entry.get().strip(), allow_empty=True)
            if end is None:
                # blank => end of day
                end = start.replace(hour=23, minute=59, second=59, microsecond=0)
            # ensure end >= start
            if end < start:
                raise ValueError("Giờ kết thúc phải lớn hơn hoặc bằng giờ bắt đầu.")
        except Exception as e:
            messagebox.showerror("Lỗi ngày giờ", str(e))
            return

        ip = self.ip_combo.get()
        if ip == "All":
            ip = None

        self.btn_query.config(state=tk.DISABLED)
        threading.Thread(target=self._run_query_thread, args=(start, end, ip), daemon=True).start()

    def _run_query_thread(self, start, end, ip):
        try:
            rows = query_alerts(start, end, src_ip=ip)  # fetch rows (Timestamp from DB expected)
            # 1) show alerts
            self.root_after(lambda: self._show_alerts(rows))

            # 2) aggregate counts by attack type
            counts_by_type = {}
            # build 10-minute bins from start to min(end, start+3h)
            window_end = min(end, start + timedelta(hours=3))
            # create bins inclusive: [start, start+10min, ... , window_end]
            bins = []
            cur = start.replace(second=0, microsecond=0)
            # align start to 10-min boundary
            cur = cur - timedelta(minutes=cur.minute % 10)
            while cur <= window_end:
                bins.append(cur)
                cur += timedelta(minutes=10)
            # map bins to counts, initialize zero
            time_bins = {b: 0 for b in bins}

            for r in rows:
                t = r.get("Timestamp")
                if isinstance(t, str):
                    # try parse with possible fractional seconds
                    try:
                        t = datetime.strptime(t.split(".")[0], "%Y-%m-%d %H:%M:%S")
                    except Exception:
                        continue
                if not isinstance(t, datetime):
                    continue
                atype = r.get("AttackType") or "Unknown"
                counts_by_type[atype] = counts_by_type.get(atype, 0) + 1

                # place into 10-min bin (only if within our bins range)
                # compute bin key by rounding down to nearest 10 min
                key = t.replace(second=0, microsecond=0)
                key = key - timedelta(minutes=key.minute % 10)
                if key in time_bins:
                    time_bins[key] += 1
                # else ignore (outside window_end)

            # reduce time_bins to list of (k,v) with at most 15 points
            ks = sorted(time_bins.keys())
            if len(ks) > 15:
                ks = ks[:15]
            trimmed_bins = {k: time_bins[k] for k in ks}

            self.root_after(lambda: self._draw_charts(counts_by_type, trimmed_bins, ip, start, end))
        except Exception as e:
            self.root_after(lambda: messagebox.showerror("Query lỗi", str(e)))
        finally:
            self.root_after(lambda: self.btn_query.config(state=tk.NORMAL))

    def _show_alerts(self, rows):
        self.alert_box.config(state="normal")
        self.alert_box.delete(1.0, tk.END)
        if not rows:
            self.alert_box.insert(tk.END, "Không có alert nào trong khoảng thời gian.\n")
        else:
            for r in rows:
                ts = r.get("Timestamp")
                # normalize timestamp string
                if isinstance(ts, datetime):
                    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    ts_str = str(ts)
                line = f"{ts_str} | {r.get('SrcIP')} -> {r.get('DstIP')} | {r.get('Protocol')} | {r.get('AttackType')} | {r.get('Severity')} | {r.get('Description')}\n"
                self.alert_box.insert(tk.END, line)
        self.alert_box.config(state="disabled")

    def _draw_charts(self, counts_by_type, time_bins, ip, start, end):
        for w in self.chart_frame_top.winfo_children():
            w.destroy()
        for w in self.chart_frame_bottom.winfo_children():
            w.destroy()

        # === BIỂU ĐỒ 1: TOP IPs STACKED ===
        fig1, ax1 = plt.subplots(figsize=(8, 4), dpi=100)
        if ip:
            types = list(counts_by_type.keys())
            vals = [counts_by_type[t] for t in types]
            ax1.bar(types, vals, color="tab:blue")
            ax1.set_title(f"Thống kê loại tấn công cho IP {ip}")
            ax1.set_ylabel("Số lần (alerts)")
            ax1.set_xlabel("Loại tấn công")
            ax1.set_xticks(range(len(types)))
            ax1.set_xticklabels(types, rotation=45, ha="right")
            fig1.tight_layout(pad=2)
        else:
            rows = query_alerts(start, end, src_ip=None, limit=100000)
            agg = {}  # ip -> {type:count}
            for r in rows:
                s = r['SrcIP'] or 'Unknown'
                at = r['AttackType'] or 'Unknown'
                agg.setdefault(s, {})
                agg[s][at] = agg[s].get(at, 0) + 1
            # chọn top 10 IP
            totals = [(ip_, sum(d.values())) for ip_, d in agg.items()]
            totals.sort(key=lambda x: x[1], reverse=True)
            top_ips = [t[0] for t in totals[:10]]
            types = sorted({at for d in agg.values() for at in d})

            import numpy as np
            x = np.arange(len(top_ips))
            width = 0.7
            bottom = [0] * len(top_ips)
            colors = plt.cm.tab20.colors
            for i, atype in enumerate(types):
                vals = [agg.get(ipx, {}).get(atype, 0) for ipx in top_ips]
                ax1.bar(x, vals, width, bottom=bottom, label=atype, color=colors[i % len(colors)])
                bottom = [bottom[j] + vals[j] for j in range(len(vals))]
            ax1.set_title("Thống kê theo các ip tấn công")
            ax1.set_xticks(x)
            ax1.set_xticklabels(top_ips, rotation=45, ha="right")
            fig1.tight_layout(pad=2)
            ax1.set_ylabel("Số alert")
            if ax1.get_legend_handles_labels()[0]:
                ax1.legend(fontsize=8, loc='upper right')
            else:
                ax1.text(0.5, 0.5, "Không có dữ liệu", ha="center", va="center", fontsize=11, color="gray",
                         transform=ax1.transAxes)

        canvas1 = FigureCanvasTkAgg(fig1, master=self.chart_frame_top)
        canvas1.draw()
        canvas1.get_tk_widget().pack(fill="both", expand=True, padx=5, pady=5)

        # === BIỂU ĐỒ 2: TẦN SUẤT ALERT THEO THỜI GIAN ===
        fig2, ax2 = plt.subplots(figsize=(7, 3), dpi=100)
        rows = query_alerts(start, end, src_ip=ip)
        if rows:
            times = []
            for r in rows:
                t = r["Timestamp"]
                if isinstance(t, str):
                    try:
                        t = datetime.strptime(t, "%Y-%m-%d %H:%M:%S")
                    except:
                        t = datetime.strptime(t.split('.')[0], "%Y-%m-%d %H:%M:%S")
                times.append(t)

            # Nếu khoảng cách nhỏ -> dùng bin 5 phút, ngược lại 15 hoặc 60 phút
            delta = (end - start).total_seconds() / 60
            if delta <= 60:
                bin_minutes = 5
            elif delta <= 6 * 60:
                bin_minutes = 15
            else:
                bin_minutes = 60

            # Chuyển times sang timestamp để tính histogram
            import matplotlib.dates as mdates
            import numpy as np

            timestamps = mdates.date2num(times)
            start_num, end_num = mdates.date2num(start), mdates.date2num(end)
            bins = np.arange(start_num, end_num, bin_minutes / (24 * 60))  # bin theo phút

            counts, edges = np.histogram(timestamps, bins=bins)
            centers = (edges[:-1] + edges[1:]) / 2

            ax2.plot_date(edges[:-1], counts, "-o", color="tab:orange")
            ax2.set_title(f"Tần suất alert theo thời gian (bin: {bin_minutes} phút)")
            ax2.set_ylabel("Số alert")
            ax2.set_xlabel("Thời gian")
            ax2.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
            fig2.autofmt_xdate()
        else:
            ax2.text(0.5, 0.5, "Không có dữ liệu thời gian", ha="center", va="center")

        canvas2 = FigureCanvasTkAgg(fig2, master=self.chart_frame_bottom)
        canvas2.draw()
        canvas2.get_tk_widget().pack(fill="both", expand=True, padx=5, pady=5)

    def root_after(self, fn):
        self.after(1, fn)

    def on_export(self):
        txt = self.alert_box.get(1.0, tk.END).strip().splitlines()
        if not txt:
            messagebox.showinfo("Export", "Không có dữ liệu để export")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not path:
            return
        with open(path, "w", newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(["raw"])
            for line in txt:
                w.writerow([line])
        messagebox.showinfo("Export", f"Đã lưu {path}")
