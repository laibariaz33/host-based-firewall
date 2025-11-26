import tkinter as tk
from tkinter import ttk
import threading
import psutil
import time

class PerformanceAnalyzer:
    """
    This class creates a frame that can be embedded into another Tkinter GUI.
    """
    def __init__(self, parent):
        self.parent = parent

        # Frame to hold performance stats
        self.frame = ttk.Frame(self.parent)

        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('default')
        self.style.configure("green.Horizontal.TProgressbar", foreground='#90CAF9', background='#90CAF9', troughcolor='#E3F2FD', thickness=18)
        self.style.configure("yellow.Horizontal.TProgressbar", foreground='#FFB74D', background='#FFB74D', troughcolor='#FFF3E0', thickness=18)
        self.style.configure("red.Horizontal.TProgressbar", foreground='#E57373', background='#E57373', troughcolor='#FFEBEE', thickness=18)
        
        # Title Section
        title_label = ttk.Label(
            self.frame,
            text="Performance Monitor",
            font=("Arial", 12)
        )
        title_label.pack(pady=(15, 20))

        # Main container with compact layout
        main_container = ttk.Frame(self.frame)
        main_container.pack(padx=40, pady=10)

        # === CPU Section ===
        cpu_frame = ttk.Frame(main_container)
        cpu_frame.pack(pady=8)
        
        cpu_label_text = ttk.Label(cpu_frame, text="CPU:", font=("Arial", 10), width=10, anchor="w")
        cpu_label_text.pack(side="left", padx=(0, 10))
        
        self.cpu_label = ttk.Label(cpu_frame, text="0%", font=("Arial", 10), width=6, anchor="e")
        self.cpu_label.pack(side="left")
        
        self.cpu_progress = ttk.Progressbar(
            cpu_frame,
            orient=tk.HORIZONTAL,
            length=250,
            mode='determinate',
            style="green.Horizontal.TProgressbar"
        )
        self.cpu_progress.pack(side="left", padx=(10, 0))

        # === Memory Section ===
        mem_frame = ttk.Frame(main_container)
        mem_frame.pack(pady=8)
        
        mem_label_text = ttk.Label(mem_frame, text="Memory:", font=("Arial", 10), width=10, anchor="w")
        mem_label_text.pack(side="left", padx=(0, 10))
        
        self.mem_label = ttk.Label(mem_frame, text="0%", font=("Arial", 10), width=6, anchor="e")
        self.mem_label.pack(side="left")
        
        self.mem_progress = ttk.Progressbar(
            mem_frame,
            orient=tk.HORIZONTAL,
            length=250,
            mode='determinate',
            style="green.Horizontal.TProgressbar"
        )
        self.mem_progress.pack(side="left", padx=(10, 0))

        # === Disk Section ===
        disk_frame = ttk.Frame(main_container)
        disk_frame.pack(pady=8)
        
        disk_label_text = ttk.Label(disk_frame, text="Disk:", font=("Arial", 10), width=10, anchor="w")
        disk_label_text.pack(side="left", padx=(0, 10))
        
        self.disk_label = ttk.Label(disk_frame, text="0%", font=("Arial", 10), width=6, anchor="e")
        self.disk_label.pack(side="left")
        
        self.disk_progress = ttk.Progressbar(
            disk_frame,
            orient=tk.HORIZONTAL,
            length=250,
            mode='determinate',
            style="green.Horizontal.TProgressbar"
        )
        self.disk_progress.pack(side="left", padx=(10, 0))

        # Start updating stats in background
        self.running = True
        threading.Thread(target=self._update_loop, daemon=True).start()

    def _get_color_style(self, value):
        if value <= 50:
            return "green.Horizontal.TProgressbar"
        elif value <= 80:
            return "yellow.Horizontal.TProgressbar"
        else:
            return "red.Horizontal.TProgressbar"

    def _update_loop(self):
        while self.running:
            try:
                cpu = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory().percent
                disk = psutil.disk_usage('/').percent

                # Update CPU
                self.cpu_label.config(text=f"{cpu:.1f}%")
                self.cpu_progress['value'] = cpu
                self.cpu_progress.config(style=self._get_color_style(cpu))

                # Update Memory
                self.mem_label.config(text=f"{mem:.1f}%")
                self.mem_progress['value'] = mem
                self.mem_progress.config(style=self._get_color_style(mem))

                # Update Disk
                self.disk_label.config(text=f"{disk:.1f}%")
                self.disk_progress['value'] = disk
                self.disk_progress.config(style=self._get_color_style(disk))

            except Exception as e:
                print(f"Error fetching stats: {e}")

            time.sleep(1)

    def stop(self):
        self.running = False

    def get_frame(self):
        return self.frame


# Example usage for testing
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Performance Analyzer")
    root.geometry("500x250")
    
    analyzer = PerformanceAnalyzer(root)
    analyzer.get_frame().pack(fill="both", expand=True)
    
    root.mainloop()