import tkinter as tk
from tkinter import ttk, Canvas
import psutil
import threading
import time
from collections import deque


class PerformanceAnalyzer:
    """
    🎯 Firewall-Only Performance Monitor
    Shows CPU %, RAM %, Network I/O, Disk I/O of the firewall process ONLY.
    Includes real-time graphs (last 60 seconds).
    """

    def __init__(self, parent, firewall_process):
        self.parent = parent
        self.firewall = firewall_process   # <- your firewall process (psutil.Process)

        # Graph data storage (last 60 seconds)
        self.cpu_history = deque(maxlen=60)
        self.memory_history = deque(maxlen=60)
        self.net_history = deque(maxlen=60)
        self.disk_history = deque(maxlen=60)

        # Network and disk previous readings
        self.prev_io = self.firewall.io_counters()
        self.last_time = time.time()

        # Main frame
        self.frame = ttk.Frame(parent)

        # Create UI
        self._create_gui()

        # Update loop
        self.running = True
        threading.Thread(target=self._update_loop, daemon=True).start()

    # ---------------- GUI ----------------

    def _create_gui(self):
        title = ttk.Label(self.frame, text="🔥 Firewall Performance Monitor",
                          font=("Arial", 16, "bold"))
        title.pack(pady=10)

        # CPU Section
        self.cpu_label = ttk.Label(self.frame, text="CPU: 0%", font=("Arial", 14))
        self.cpu_label.pack()
        self.cpu_canvas = Canvas(self.frame, width=600, height=120, bg="white")
        self.cpu_canvas.pack(pady=5)

        # Memory Section
        self.mem_label = ttk.Label(self.frame, text="Memory: 0%", font=("Arial", 14))
        self.mem_label.pack()
        self.mem_canvas = Canvas(self.frame, width=600, height=120, bg="white")
        self.mem_canvas.pack(pady=5)

        # Network Section
        self.net_label = ttk.Label(self.frame, text="Network: 0 KB/s", font=("Arial", 14))
        self.net_label.pack()
        self.net_canvas = Canvas(self.frame, width=600, height=120, bg="white")
        self.net_canvas.pack(pady=5)

        # Disk Section
        self.disk_label = ttk.Label(self.frame, text="Disk: 0 KB/s", font=("Arial", 14))
        self.disk_label.pack()
        self.disk_canvas = Canvas(self.frame, width=600, height=120, bg="white")
        self.disk_canvas.pack(pady=5)

    # ---------------- Fetch Firewall Stats ----------------

    def _get_firewall_stats(self):
        try:
            cpu = self.firewall.cpu_percent(interval=0.1)
            mem = self.firewall.memory_percent()

            now = self.firewall.io_counters()
            current_time = time.time()
            dt = current_time - self.last_time

            # Bytes per second (network + disk combined)
            read_sec = (now.read_bytes - self.prev_io.read_bytes) / dt
            write_sec = (now.write_bytes - self.prev_io.write_bytes) / dt

            net_sec = (now.other_bytes - getattr(self.prev_io, "other_bytes", 0)) / dt if hasattr(now, "other_bytes") else 0

            self.prev_io = now
            self.last_time = current_time

            return cpu, mem, read_sec, write_sec, net_sec

        except Exception:
            return 0, 0, 0, 0, 0

    # ---------------- Graph Drawing ----------------

    def _draw_graph(self, canvas, data, color):
        canvas.delete("all")
        if len(data) < 2:
            return

        w = canvas.winfo_width()
        h = canvas.winfo_height()

        max_val = max(data) if max(data) > 0 else 1

        points = []
        for i, v in enumerate(data):
            x = (i / len(data)) * w
            y = h - (v / max_val) * h
            points.append((x, y))

        # Draw line
        for i in range(len(points) - 1):
            canvas.create_line(points[i][0], points[i][1],
                               points[i+1][0], points[i+1][1],
                               fill=color, width=2)

    # ---------------- Update Loop ----------------

    def _update_loop(self):
        while self.running:
            cpu, mem, read_sec, write_sec, net_sec = self._get_firewall_stats()

            # Update labels
            self.cpu_label.config(text=f"CPU: {cpu:.1f}%")
            self.mem_label.config(text=f"Memory: {mem:.1f}%")
            self.net_label.config(text=f"Network: {(net_sec/1024):.1f} KB/s")
            self.disk_label.config(text=f"Disk: {(read_sec+write_sec)/1024:.1f} KB/s")

            # Update history for graphs
            self.cpu_history.append(cpu)
            self.memory_history.append(mem)
            self.net_history.append(net_sec / 1024)
            self.disk_history.append((read_sec + write_sec) / 1024)

            # Draw graphs
            self._draw_graph(self.cpu_canvas, self.cpu_history, "#2196F3")
            self._draw_graph(self.mem_canvas, self.memory_history, "#FF9800")
            self._draw_graph(self.net_canvas, self.net_history, "#00BCD4")
            self._draw_graph(self.disk_canvas, self.disk_history, "#9C27B0")

            time.sleep(1)

    # ---------------- Public ----------------

    def get_frame(self):
        return self.frame

    def stop(self):
        self.running = False
