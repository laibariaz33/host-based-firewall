#!/usr/bin/env python3
"""
Demo script to show how the firewall should work
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
from datetime import datetime

class FirewallDemo:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🛡️ Host-Based Firewall Demo")
        self.root.geometry("1000x700")
        
        # Create GUI
        self.create_gui()
        
        # Demo data
        self.demo_packets = [
            ("192.168.1.100", "8.8.8.8", "UDP", 53, "DNS Query"),
            ("192.168.1.100", "google.com", "TCP", 443, "HTTPS"),
            ("192.168.1.100", "10.0.0.1", "TCP", 22, "SSH to Private Network"),
            ("192.168.1.100", "youtube.com", "TCP", 80, "HTTP"),
            ("192.168.1.100", "facebook.com", "TCP", 443, "HTTPS"),
        ]
        
        self.stats = {
            'packets_processed': 0,
            'packets_blocked': 0,
            'packets_allowed': 0,
            'connections_tracked': 0
        }
    
    def create_gui(self):
        """Create the demo GUI"""
        # Title
        title = tk.Label(self.root, text="🛡️ Host-Based Firewall Demo", 
                        font=("Arial", 16, "bold"))
        title.pack(pady=10)
        
        # Control buttons
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)
        
        self.start_btn = tk.Button(button_frame, text="🚀 Start Firewall Demo", 
                                  command=self.start_demo, bg="green", fg="white")
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(button_frame, text="⏹️ Stop Demo", 
                                 command=self.stop_demo, bg="red", fg="white")
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = tk.Button(button_frame, text="🗑️ Clear Logs", 
                                  command=self.clear_logs, bg="orange", fg="white")
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Status
        self.status_label = tk.Label(self.root, text="Status: Stopped", 
                                   font=("Arial", 12, "bold"), fg="red")
        self.status_label.pack(pady=5)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Activity Log tab
        self.create_activity_tab()
        
        # Statistics tab
        self.create_stats_tab()
        
        # Connections tab
        self.create_connections_tab()
    
    def create_activity_tab(self):
        """Create activity log tab"""
        activity_frame = ttk.Frame(self.notebook)
        self.notebook.add(activity_frame, text="📊 Activity Log")
        
        # Activity log
        log_label = tk.Label(activity_frame, text="Real-time Firewall Activity:", 
                           font=("Arial", 12, "bold"))
        log_label.pack(anchor=tk.W, padx=10, pady=5)
        
        self.activity_log = scrolledtext.ScrolledText(activity_frame, height=20, width=80)
        self.activity_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    
    def create_stats_tab(self):
        """Create statistics tab"""
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="📈 Statistics")
        
        # Statistics display
        stats_label = tk.Label(stats_frame, text="Firewall Statistics:", 
                             font=("Arial", 12, "bold"))
        stats_label.pack(anchor=tk.W, padx=10, pady=5)
        
        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=20, width=80)
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    
    def create_connections_tab(self):
        """Create connections tab"""
        conn_frame = ttk.Frame(self.notebook)
        self.notebook.add(conn_frame, text="🔗 Active Connections")
        
        # Connections display
        conn_label = tk.Label(conn_frame, text="Active Network Connections:", 
                            font=("Arial", 12, "bold"))
        conn_label.pack(anchor=tk.W, padx=10, pady=5)
        
        self.connections_text = scrolledtext.ScrolledText(conn_frame, height=20, width=80)
        self.connections_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    
    def start_demo(self):
        """Start the firewall demo"""
        self.status_label.config(text="Status: Running", fg="green")
        self.start_btn.config(state="disabled")
        
        # Start demo in background thread
        self.demo_thread = threading.Thread(target=self.run_demo, daemon=True)
        self.demo_thread.start()
    
    def stop_demo(self):
        """Stop the firewall demo"""
        self.status_label.config(text="Status: Stopped", fg="red")
        self.start_btn.config(state="normal")
    
    def run_demo(self):
        """Run the firewall demo"""
        self.log_activity("🛡️ Firewall started - monitoring network traffic...")
        
        for i, (src_ip, dst_ip, protocol, port, description) in enumerate(self.demo_packets):
            if not self.status_label.cget("text").startswith("Status: Running"):
                break
                
            time.sleep(2)  # Simulate real-time processing
            
            # Simulate packet processing
            self.stats['packets_processed'] += 1
            
            # Simulate rule evaluation
            if "Private Network" in description or "10.0.0.1" in dst_ip:
                # Block private network access
                self.stats['packets_blocked'] += 1
                self.log_activity(f"❌ BLOCKED: {src_ip} → {dst_ip} ({protocol}:{port}) - {description}")
            else:
                # Allow other traffic
                self.stats['packets_allowed'] += 1
                self.log_activity(f"✅ ALLOWED: {src_ip} → {dst_ip} ({protocol}:{port}) - {description}")
            
            # Simulate connection tracking
            if protocol == "TCP":
                self.stats['connections_tracked'] += 1
                self.log_connection(f"🔗 Connection: {src_ip}:{port} → {dst_ip}:{port} ({protocol})")
            
            # Update statistics
            self.update_statistics()
        
        self.log_activity("🛡️ Firewall demo completed")
    
    def log_activity(self, message):
        """Log activity message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.activity_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.activity_log.see(tk.END)
        self.root.update()
    
    def log_connection(self, message):
        """Log connection message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.connections_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.connections_text.see(tk.END)
        self.root.update()
    
    def update_statistics(self):
        """Update statistics display"""
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, "=== FIREWALL STATISTICS ===\n\n")
        self.stats_text.insert(tk.END, f"Packets Processed: {self.stats['packets_processed']}\n")
        self.stats_text.insert(tk.END, f"Packets Allowed: {self.stats['packets_allowed']}\n")
        self.stats_text.insert(tk.END, f"Packets Blocked: {self.stats['packets_blocked']}\n")
        self.stats_text.insert(tk.END, f"Connections Tracked: {self.stats['connections_tracked']}\n")
        self.stats_text.insert(tk.END, f"\nLast updated: {datetime.now().strftime('%H:%M:%S')}\n")
        self.root.update()
    
    def clear_logs(self):
        """Clear all logs"""
        self.activity_log.delete(1.0, tk.END)
        self.connections_text.delete(1.0, tk.END)
        self.stats_text.delete(1.0, tk.END)
        self.stats = {'packets_processed': 0, 'packets_blocked': 0, 'packets_allowed': 0, 'connections_tracked': 0}
    
    def run(self):
        """Run the demo"""
        self.root.mainloop()

if __name__ == "__main__":
    print("🛡️ Starting Host-Based Firewall Demo...")
    print("This shows you exactly how a firewall should work!")
    print("\nWhat you should see:")
    print("1. Real-time packet captures")
    print("2. ALLOWED/BLOCKED decisions")
    print("3. Active connections")
    print("4. Statistics updating")
    print("\nClick 'Start Firewall Demo' to begin!")
    
    demo = FirewallDemo()
    demo.run()
