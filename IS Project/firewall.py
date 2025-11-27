import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import threading
import time
from datetime import datetime


# Import all modules
from packet_capture import PacketCapture, PacketInfo
from rule_engine import RuleEngine, RuleAction, RuleDirection, Protocol, FirewallRule
from stateful_inspection import StatefulInspector, ConnectionState
from rule_management import RuleManager
from logging_monitoring import FirewallLogger, FirewallMonitor, LogLevel, FirewallEvent
from configuration_policy import ConfigurationManager, PolicyManager
from performance_analyzer import PerformanceAnalyzer


# ---------- Enhanced Firewall with All Modules ----------
class EnhancedFirewall:
    def __init__(self, log_callback):
        self.running = False
        self.log_callback = log_callback
        
        # Initialize all modules
        self.packet_capture = PacketCapture(self.log_callback)
        self.rule_engine = RuleEngine(self.log_callback)
        self.stateful_inspector = StatefulInspector(self.log_callback)
        self.rule_manager = RuleManager(self.rule_engine)
        self.logger = FirewallLogger()
        self.monitor = FirewallMonitor(self.logger)
        self.config_manager = ConfigurationManager()
        self.policy_manager = PolicyManager()
        
    

        
        
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'packets_blocked': 0,
            'packets_allowed': 0,
            'connections_tracked': 0,
            'rules_evaluated': 0
        }
    def start(self):
        """Start the enhanced firewall"""
        self.running = True
        self.log_callback("Enhanced Firewall started...")
        
        # Start monitoring
        self.monitor.start_monitoring()

        # Start stateful inspector background tasks (cleanup thread, etc.)
        try:
            if hasattr(self.stateful_inspector, 'start'):
                self.stateful_inspector.start()
        except Exception as e:
            self.log_callback(f"Stateful inspector start error: {e}")
        
        # Apply default action from config
        try:
            cfg = self.config_manager.get_config()
            if str(cfg.default_action).upper() == "DENY":
                self.rule_engine.set_default_action(RuleAction.DENY)
            else:
                self.rule_engine.set_default_action(RuleAction.ALLOW)
        except Exception as e:
            self.log_callback(f"Config default_action error: {e}")

        try:
            # Only load rules from JSON file - no auto-generated rules
            self.log_callback(f"Using rules from JSON file only.")
        except Exception as e:
            self.log_callback(f"Rule setup error: {e}")
                
        # Start packet capture in a separate thread with packet processor
        self.capture_thread = threading.Thread(
            target=self._start_packet_capture_with_processing, 
            daemon=True
        )
        self.capture_thread.start()
        
        # Log startup
        self.logger.log_event(FirewallEvent(
            timestamp=datetime.now(),
            event_type="FIREWALL_STARTED",
            level=LogLevel.INFO,
            message="Enhanced Firewall started successfully"
        ))
    
    def _start_packet_capture_with_processing(self):
        """Start packet capture with integrated processing"""
        try:
            from pydivert import WinDivert
            
            self.log_callback("Starting packet capture with processing...")
            
            # Capture all IPv4 traffic (TCP/UDP/ICMP) so enforcement truly applies
            with WinDivert("ip") as w:
                for packet in w:
                    if not self.running:
                        break
                    
                    # Parse packet
                    packet_info = self.packet_capture._parse_packet(packet)
                    self.packet_capture._update_stats(packet_info)
                    self.packet_capture.captured_packets.append(packet_info)
                    
                    # Process through firewall
                    should_allow, match_info = self.process_packet(packet_info)

                    # Build concise reason string
                    reason = ""
                    if match_info:
                        if match_info.get('decision_source') == 'rule':
                            if match_info.get('rule_name'):
                                reason = f"reason=rule('{match_info['rule_name']}')"
                            else:
                                reason = "reason=rule"
                        elif match_info.get('decision_source') == 'stateful':
                            state = match_info.get('connection_state') or 'UNTRACKED'
                            reason = f"reason=stateful({state})"
                        elif match_info.get('decision_source') == 'default':
                            # Only show if truly default-based
                            reason = f"reason=default({match_info.get('default_action','')})"

                    # Compose standard packet text with ports and direction
                    dir_text = 'OUT' if packet_info.direction == 'OUT' else 'IN'
                    src = f"{packet_info.src_ip}:{packet_info.src_port}" if packet_info.src_port else packet_info.src_ip
                    dst = f"{packet_info.dst_ip}:{packet_info.dst_port}" if packet_info.dst_port else packet_info.dst_ip

                    # Send or drop packet based on decision and log
                    should_allow, match_info = self.process_packet(packet_info)

                    if should_allow:
                        w.send(packet)
                        self.log_callback(f"✅ ALLOWED {packet_info.src_ip} -> {packet_info.dst_ip} {packet_info.protocol} {match_info}")
                    else:
                        # Drop packet
                        self.log_callback(f"❌ BLOCKED {packet_info.src_ip} -> {packet_info.dst_ip} {packet_info.protocol} {match_info}")

                    
        except Exception as e:
            self.log_callback(f"Packet capture error: {e}")

    def _install_baseline_rules(self):
        """Essential allow rules for a usable default-deny posture."""
        existing = [r.name for r in self.rule_engine.get_all_rules()]
        baseline = [
            ("Allow DNS UDP 53", RuleAction.ALLOW, RuleDirection.OUTBOUND, Protocol.UDP, None, None, None, 53, 5,
             "Allow DNS queries"),
            ("Allow HTTPS TCP 443", RuleAction.ALLOW, RuleDirection.OUTBOUND, Protocol.TCP, None, None, None, 443, 6,
             "Allow HTTPS over TCP"),
            ("Allow HTTPS QUIC UDP 443", RuleAction.ALLOW, RuleDirection.OUTBOUND, Protocol.UDP, None, None, None, 443, 7,
             "Allow QUIC/HTTP3 over UDP"),
            ("Allow HTTP TCP 80", RuleAction.ALLOW, RuleDirection.OUTBOUND, Protocol.TCP, None, None, None, 80, 8,
             "Allow HTTP (optional)"),
            ("Allow NTP UDP 123", RuleAction.ALLOW, RuleDirection.OUTBOUND, Protocol.UDP, None, None, None, 123, 9,
             "Allow time sync"),
            ("Allow DHCP", RuleAction.ALLOW, RuleDirection.BOTH, Protocol.UDP, None, None, 68, 67, 10,
             "Allow DHCP lease/renew")
        ]

        for name, action, direction, proto, src_ip, dst_ip, src_port, dst_port, prio, desc in baseline:
            if name in existing:
                continue
            self.rule_engine.add_rule(FirewallRule(
                id=f"baseline_{name.replace(' ', '_').lower()}",
                name=name,
                action=action,
                direction=direction,
                protocol=proto,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                priority=prio,
                description=desc
            ))

    def _install_hardening_rules(self):
        """Inbound deny rules for common risky services."""
        existing = [r.name for r in self.rule_engine.get_all_rules()]
        denies = [
            ("Block Inbound SMB 445", RuleAction.DENY, RuleDirection.INBOUND, Protocol.TCP, None, None, None, 445, 20,
             "Block inbound SMB"),
            ("Block Inbound RDP 3389", RuleAction.DENY, RuleDirection.INBOUND, Protocol.TCP, None, None, None, 3389, 21,
             "Block inbound RDP"),
            ("Block Inbound Telnet 23", RuleAction.DENY, RuleDirection.INBOUND, Protocol.TCP, None, None, None, 23, 22,
             "Block inbound Telnet"),
            ("Block Inbound FTP 21", RuleAction.DENY, RuleDirection.INBOUND, Protocol.TCP, None, None, None, 21, 23,
             "Block inbound FTP"),
            ("Block Inbound WinRM 5985", RuleAction.DENY, RuleDirection.INBOUND, Protocol.TCP, None, None, None, 5985, 24,
             "Block inbound WinRM HTTP"),
            ("Block Inbound WinRM 5986", RuleAction.DENY, RuleDirection.INBOUND, Protocol.TCP, None, None, None, 5986, 25,
             "Block inbound WinRM HTTPS")
        ]
        for name, action, direction, proto, src_ip, dst_ip, src_port, dst_port, prio, desc in denies:
            if name in existing:
                continue
            self.rule_engine.add_rule(FirewallRule(
                id=f"hardening_{name.replace(' ', '_').lower()}",
                name=name,
                action=action,
                direction=direction,
                protocol=proto,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                priority=prio,
                description=desc
            ))
    def _apply_config_rules(self, cfg):
        """Translate configuration settings into enforcement rules."""
        try:
            existing_ids = {r.id for r in self.rule_engine.get_all_rules()}

            # Trusted networks: allow both directions
            for net in getattr(cfg, 'trusted_networks', []) or []:
                rid = f"cfg_allow_trusted_{net.replace('/', '_')}"
                if rid in existing_ids:
                    continue
                self.rule_engine.add_rule(FirewallRule(
                    id=rid,
                    name=f"Allow trusted {net}",
                    action=RuleAction.ALLOW,
                    direction=RuleDirection.BOTH,
                    protocol=Protocol.ANY,
                    src_ip=net,
                    dst_ip=net,
                    priority=15,
                    description="Config: allow trusted network"
                ))

            # Blocked networks: deny both directions
            for net in getattr(cfg, 'blocked_networks', []) or []:
                rid = f"cfg_block_net_{net.replace('/', '_')}"
                if rid in existing_ids:
                    continue
                self.rule_engine.add_rule(FirewallRule(
                    id=rid,
                    name=f"Block network {net}",
                    action=RuleAction.DENY,
                    direction=RuleDirection.BOTH,
                    protocol=Protocol.ANY,
                    src_ip=net,
                    dst_ip=net,
                    priority=14,
                    description="Config: block network"
                ))

            # Allowed ports (outbound allow)
            for port in getattr(cfg, 'allowed_ports', []) or []:
                rid = f"cfg_allow_out_port_{port}"
                if rid in existing_ids:
                    continue
                self.rule_engine.add_rule(FirewallRule(
                    id=rid,
                    name=f"Allow outbound port {port}",
                    action=RuleAction.ALLOW,
                    direction=RuleDirection.OUTBOUND,
                    protocol=Protocol.ANY,
                    dst_port=port,
                    priority=16,
                    description="Config: allowed outbound port"
                ))

            # Blocked ports (deny both directions)
            for port in getattr(cfg, 'blocked_ports', []) or []:
                rid = f"cfg_block_port_{port}"
                if rid in existing_ids:
                    continue
                self.rule_engine.add_rule(FirewallRule(
                    id=rid,
                    name=f"Block port {port}",
                    action=RuleAction.DENY,
                    direction=RuleDirection.BOTH,
                    protocol=Protocol.ANY,
                    dst_port=port,
                    priority=13,
                    description="Config: blocked port"
                ))

        except Exception as e:
            self.log_callback(f"Apply config rules error: {e}")

    def stop(self):
        """Stop the enhanced firewall"""
        self.running = False
        self.packet_capture.stop_capture()
        self.monitor.stop_monitoring()
        self.stateful_inspector.stop()
        self.logger.stop()
        
        # Wait for capture thread to finish
        if hasattr(self, 'capture_thread') and self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)
        
        self.log_callback("Enhanced Firewall stopped.")
        
        # Log shutdown
        self.logger.log_event(FirewallEvent(
            timestamp=datetime.now(),
            event_type="FIREWALL_STOPPED",
            level=LogLevel.INFO,
            message="Enhanced Firewall stopped"
        ))

    def reload_configuration(self) -> bool:
        """Live-reload configuration and policies and re-apply config-driven rules."""
        try:
            # Reload from files
            cfg_ok = self.config_manager.load_configuration()
            pol_ok = self.policy_manager.load_policies()

            # Apply default action immediately
            try:
                cfg = self.config_manager.get_config()
                if str(cfg.default_action).upper() == "DENY":
                    self.rule_engine.set_default_action(RuleAction.DENY)
                else:
                    self.rule_engine.set_default_action(RuleAction.ALLOW)
            except Exception as e:
                self.log_callback(f"Config default_action reload error: {e}")

            # Remove prior config-derived rules (prefix cfg_)
            existing = self.rule_engine.get_all_rules()
            for r in list(existing):
                try:
                    if r.id and r.id.startswith("cfg_"):
                        self.rule_engine.remove_rule(r.id)
                except Exception:
                    pass

            # Re-apply config rules
            try:
                self._apply_config_rules(self.config_manager.get_config())
            except Exception as e:
                self.log_callback(f"Config rules reload error: {e}")

            self.log_callback("Configuration and policies reloaded live.")
            return bool(cfg_ok and pol_ok)
        except Exception as e:
            self.log_callback(f"Reload error: {e}")
            return False

    def process_packet(self, packet_info: PacketInfo) -> tuple[bool, dict]:
        """Process a packet through rules, stateful inspection, and policy."""
        try:
            self.stats['packets_processed'] += 1

            # Stateful inspection
            stateful_allow, connection_state, connection = self.stateful_inspector.inspect_packet(packet_info)
            if connection:
                self.stats['connections_tracked'] += 1

            # Rule engine evaluation
            rule_allow, matching_rule = self.rule_engine.evaluate_packet(packet_info)
            self.stats['rules_evaluated'] += 1

            # Policy evaluation (optional)
            policy_actions = self.policy_manager.evaluate_policies(packet_info)

            # Apply policy actions influence
            policy_forced_allow = any(a.name == 'ALLOW' for a in policy_actions)
            policy_forced_deny = any(a.name == 'DENY' or a.name == 'QUARANTINE' for a in policy_actions)
            policy_alert = any(a.name == 'ALERT' for a in policy_actions)
            policy_log = any(a.name == 'LOG' for a in policy_actions)

            # Final decision precedence: explicit rule > policy forced decision > stateful > default
            if matching_rule:
                final_decision = rule_allow
                decision_source = 'rule'
            elif policy_forced_deny or policy_forced_allow:
                final_decision = not policy_forced_deny
                decision_source = 'policy'
            elif connection_state is not None:
                final_decision = stateful_allow
                decision_source = 'stateful'
            else:
                # Default DENY/ALLOW
                final_decision = (self.rule_engine.default_action == RuleAction.ALLOW)
                decision_source = 'default'

            # Prepare match info for logging
            match_info = {
                'rule_name': getattr(matching_rule, 'name', None),
                'rule_id': getattr(matching_rule, 'id', None),
                'default_action': self.rule_engine.default_action.value if decision_source == 'default' else None,
                'connection_state': connection_state.value if connection_state else None,
                'decision_source': decision_source,
                'policy_actions': [a.value for a in policy_actions] if policy_actions else [],
            }

            # Log packet
            if final_decision:
                self.stats['packets_allowed'] += 1
                reason_text = match_info['rule_name'] or match_info.get('connection_state') or match_info.get('default_action')
                self.logger.log_packet_allowed(packet_info.src_ip, packet_info.dst_ip, packet_info.protocol, reason=reason_text)
            else:
                self.stats['packets_blocked'] += 1
                reason_text = "Rule match" if matching_rule else "Default policy"
                if match_info.get('rule_name') or match_info.get('connection_state'):
                    reason_text += f" ({match_info.get('rule_name') or match_info.get('connection_state')})"
                self.logger.log_packet_blocked(packet_info.src_ip, packet_info.dst_ip, packet_info.protocol, reason=reason_text)

            # Side-effect logs for policy actions
            if policy_alert or policy_log or policy_forced_deny or policy_forced_allow:
                action_text = ','.join([a.value for a in policy_actions])
                self.logger.log_security_event(f"Policy actions [{action_text}] on packet {packet_info.src_ip} -> {packet_info.dst_ip} {packet_info.protocol}")
                if policy_forced_deny or any(a.name == 'QUARANTINE' for a in policy_actions):
                    self.logger.log_security_alert(f"Packet quarantined/denied by policy from {packet_info.src_ip} to {packet_info.dst_ip}")

            return final_decision, match_info

        except Exception as e:
            self.log_callback(f"Error processing packet: {e}")
            self.logger.log_security_alert(f"Packet processing error: {e}")
            return False, {}

    def get_statistics(self):
        """Get firewall statistics"""
        return {
            'firewall_stats': self.stats,
            'capture_stats': self.packet_capture.get_stats(),
            'rule_stats': self.rule_engine.get_rule_statistics(),
            'connection_stats': self.stateful_inspector.get_connection_statistics(),
            'log_stats': self.logger.get_statistics(),
            'monitor_stats': self.monitor.get_metrics()
        }


# ---------- Enhanced GUI Frontend ----------
class EnhancedFirewallGUI:
    def __init__(self, root, role):
        self.root = root
        self.root.title("Enhanced Host-Based Firewall")
        self.root.geometry("1200x800")

        # Initialize firewall first
        self.firewall = EnhancedFirewall(self.log_message)
        self.thread = None
        self.capture_thread = None
        self.metrics_history = []
        
        self.auto_refresh_thread = None
        self.auto_refresh_running = False
        self.refresh_interval = 2  # Default 2 seconds like real firewalls
        self.last_refresh_time = None
        self.monitor_refresh_job = None
        self.logs_refresh_job = None
        self.logs_auto_refresh_paused = False

        # Create notebook for tabs
        self.notebook = ttk.Notebook(root)
        style = ttk.Style()
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        

        # Create tabs
        self._create_dashboard_tab()
        self._create_rules_tab()
        self._create_monitoring_tab()
        self._create_logs_tab()
        self._create_configuration_tab()

        self.performance_analyzer = PerformanceAnalyzer(self.notebook)
        perf_frame = self.performance_analyzer.get_frame()
        self.notebook.add(perf_frame, text="Performance Analyzer")
        self._start_tab_auto_refresh()
        

    def _insert_text(self, widget, text):
        """Temporarily enable widget, insert text, then disable it again."""
        widget.config(state=tk.NORMAL)
        widget.insert(tk.END, text)
        widget.config(state=tk.DISABLED)

    def _clear_text(self, widget):
        """Temporarily enable widget, clear it, then disable it again."""
        widget.config(state=tk.NORMAL)
        widget.delete(1.0, tk.END)
        widget.config(state=tk.DISABLED)

    def _create_dashboard_tab(self):
        """Create main dashboard tab"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")

        # Control buttons
        control_frame = ttk.Frame(dashboard_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=10)

        self.start_btn = ttk.Button(control_frame, text="Start Firewall", command=self.start_firewall)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(control_frame, text="Stop Firewall", command=self.stop_firewall)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.stats_btn = ttk.Button(control_frame, text="Refresh Stats", command=self.refresh_stats)
        self.stats_btn.pack(side=tk.LEFT, padx=5)
        
        self.auto_refresh_btn = ttk.Button(control_frame, text="Enable Auto-Refresh", command=self.toggle_auto_refresh)
        self.auto_refresh_btn.pack(side=tk.LEFT, padx=5)

        # Status display
        status_frame = ttk.LabelFrame(dashboard_frame, text="Status")
        status_frame.pack(fill=tk.X, padx=10, pady=5)

        self.status_label = ttk.Label(status_frame, text="Firewall: Stopped", font=("Arial", 12, "bold"))
        self.status_label.pack(pady=5)
        
        refresh_status_frame = ttk.Frame(status_frame)
        refresh_status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(refresh_status_frame, text="Auto-Refresh: OFF", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        self.refresh_status_label = ttk.Label(refresh_status_frame, text="", font=("Arial", 10, "italic"))
        self.refresh_status_label.pack(side=tk.LEFT, padx=5)
        
        # Refresh interval control
        interval_frame = ttk.Frame(status_frame)
        interval_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(interval_frame, text="Refresh Interval (seconds):").pack(side=tk.LEFT, padx=5)
        self.interval_var = tk.StringVar(value="2")
        interval_spinbox = ttk.Spinbox(interval_frame, from_=1, to=10, textvariable=self.interval_var, width=5)
        interval_spinbox.pack(side=tk.LEFT, padx=5)
        ttk.Button(interval_frame, text="Apply", command=self.apply_refresh_interval).pack(side=tk.LEFT, padx=5)

        # Statistics display
        stats_frame = ttk.LabelFrame(dashboard_frame, text="Statistics")
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=15, width=80, state=tk.DISABLED)
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Activity log
        log_frame = ttk.LabelFrame(dashboard_frame, text="Activity Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, width=80, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _create_rules_tab(self):
        """Create rules management tab"""
        rules_frame = ttk.Frame(self.notebook)
        self.notebook.add(rules_frame, text="Rules")

        # Create rule management GUI
        self.rule_manager_gui = self.firewall.rule_manager.show_gui(rules_frame)

    def _create_monitoring_tab(self):
        """Create monitoring tab"""
        monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitor_frame, text="Monitoring")

        # Real-time metrics
        metrics_frame = ttk.LabelFrame(monitor_frame, text="Real-time Metrics")
        metrics_frame.pack(fill=tk.X, padx=10, pady=5)

        self.metrics_text = scrolledtext.ScrolledText(metrics_frame, height=10, width=80, state=tk.DISABLED)
        self.metrics_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Connection monitoring
        conn_frame = ttk.LabelFrame(monitor_frame, text="Active Connections")
        conn_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.connections_text = scrolledtext.ScrolledText(conn_frame, height=15, width=80, state=tk.DISABLED)
        self.connections_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Refresh button
        ttk.Button(monitor_frame, text="Refresh Monitoring", command=self.refresh_monitoring).pack(pady=5)
        self.hostname_cache = {}

    def _create_logs_tab(self):
        """Create logs tab"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="Logs")

        self.logs_text = scrolledtext.ScrolledText(logs_frame, height=25, width=100, state=tk.DISABLED)
        self.logs_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Log controls
        log_controls = ttk.Frame(logs_frame)
        log_controls.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(log_controls, text="Refresh Logs", command=self.refresh_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_controls, text="Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_controls, text="Export Logs", command=self.export_logs).pack(side=tk.LEFT, padx=5)
        self.logs_pause_btn = ttk.Button(log_controls, text="Pause Auto Refresh", command=self.toggle_logs_auto_refresh)
        self.logs_pause_btn.pack(side=tk.LEFT, padx=5)

    def _create_configuration_tab(self):
        """Create configuration tab"""
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text="Configuration")

        # Configuration management
        from configuration_policy import ConfigurationGUI
        self.config_gui = ConfigurationGUI(config_frame, 
                                         self.firewall.config_manager, 
                                         self.firewall.policy_manager)

        # Live reload controls
        reload_frame = ttk.Frame(config_frame)
        reload_frame.pack(fill=tk.X, padx=10, pady=6)
        ttk.Button(reload_frame, text="Apply Config/Policies (Live)", command=self.reload_firewall_config).pack(side=tk.LEFT, padx=5)
        ttk.Label(reload_frame, text="Applies without restarting the firewall").pack(side=tk.LEFT, padx=5)

    def reload_firewall_config(self):
        """Trigger live reload of firewall configuration and policies."""
        ok = self.firewall.reload_configuration()
        if ok:
            messagebox.showinfo("Reload", "Configuration and policies reloaded successfully.")
        else:
            messagebox.showwarning("Reload", "Reload completed with issues. Check logs for details.")
    def open_performance_analyzer(self):
         """Open the standalone Performance Analyzer window"""
         try:
            show_performance_stats()
         except Exception as e:
            messagebox.showerror("Error", f"Failed to open Performance Analyzer: {e}")



    def log_message(self, message):
        """Log message to activity log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        # Check if log_text widget exists before trying to use it
        if hasattr(self, 'log_text') and self.log_text:
            self._insert_text(self.log_text, f"[{timestamp}] {message}\n")
            self.log_text.see(tk.END)
        else:
            # Fallback to console output during initialization
            print(f"[{timestamp}] {message}")

    def start_firewall(self):
        """Start firewall in a background thread."""
        if self.thread and self.thread.is_alive():
            messagebox.showinfo("Info", "Firewall already running.")
            return

        self.thread = threading.Thread(target=self.firewall.start, daemon=True)
        self.thread.start()
        self.status_label.config(text="Firewall: Running", foreground="green")

    def stop_firewall(self):
        """Stop the firewall safely."""
        self.firewall.stop()
        self.status_label.config(text="Firewall: Stopped", foreground="red")
        self.stop_auto_refresh()

    def toggle_auto_refresh(self):
        """Toggle auto-refresh on/off"""
        if self.auto_refresh_running:
            self.stop_auto_refresh()
        else:
            self.start_auto_refresh()

    def start_auto_refresh(self):
        """Start automatic refresh thread"""
        if self.auto_refresh_running:
            messagebox.showinfo("Info", "Auto-refresh already running.")
            return
        
        self.auto_refresh_running = True
        self.auto_refresh_btn.config(text="Disable Auto-Refresh")
        self.log_message(f"Auto-refresh started (interval: {self.refresh_interval}s)")
        
        self.auto_refresh_thread = threading.Thread(target=self._auto_refresh_loop, daemon=True)
        self.auto_refresh_thread.start()

    def stop_auto_refresh(self):
        """Stop automatic refresh thread"""
        if not self.auto_refresh_running:
            return
        
        self.auto_refresh_running = False
        self.auto_refresh_btn.config(text="Enable Auto-Refresh")
        self.log_message("Auto-refresh stopped")
        
        # Wait for thread to finish
        if self.auto_refresh_thread and self.auto_refresh_thread.is_alive():
            self.auto_refresh_thread.join(timeout=2)

    def apply_refresh_interval(self):
        """Apply new refresh interval"""
        try:
            new_interval = int(self.interval_var.get())
            if new_interval < 1 or new_interval > 10:
                messagebox.showerror("Error", "Interval must be between 1 and 10 seconds")
                return
            self.refresh_interval = new_interval
            self.log_message(f"Refresh interval changed to {self.refresh_interval}s")
            self._restart_tab_auto_refresh()
        except ValueError:
            messagebox.showerror("Error", "Invalid interval value")

    def _start_tab_auto_refresh(self):
        """Start Tk-based refresh loops for monitoring and logs tabs."""
        self._schedule_monitoring_refresh()
        self._schedule_logs_refresh()

    def _restart_tab_auto_refresh(self):
        """Restart the Tk loops when interval or state changes."""
        if self.monitor_refresh_job:
            self.root.after_cancel(self.monitor_refresh_job)
            self.monitor_refresh_job = None
        if self.logs_refresh_job:
            self.root.after_cancel(self.logs_refresh_job)
            self.logs_refresh_job = None
        self._start_tab_auto_refresh()

    def _schedule_monitoring_refresh(self):
        """Refresh monitoring tab automatically when it is visible."""
        try:
            current_tab = self.notebook.tab(self.notebook.select(), "text")
        except tk.TclError:
            current_tab = ""

        if current_tab == "Monitoring":
            try:
                self.refresh_monitoring()
            except Exception as exc:
                self.log_message(f"Monitoring auto-refresh error: {exc}")

        interval_ms = max(1000, int(self.refresh_interval * 1000))
        self.monitor_refresh_job = self.root.after(interval_ms, self._schedule_monitoring_refresh)

    def _schedule_logs_refresh(self):
        """Refresh logs tab automatically when it is visible."""
        try:
            current_tab = self.notebook.tab(self.notebook.select(), "text")
        except tk.TclError:
            current_tab = ""

        if current_tab == "Logs" and not self.logs_auto_refresh_paused:
            try:
                self.refresh_logs()
            except Exception as exc:
                self.log_message(f"Logs auto-refresh error: {exc}")

        interval_ms = max(1000, int(self.refresh_interval * 1000))
        self.logs_refresh_job = self.root.after(interval_ms, self._schedule_logs_refresh)

    def toggle_logs_auto_refresh(self):
        """Allow the user to pause/resume logs auto refresh to read entries."""
        self.logs_auto_refresh_paused = not self.logs_auto_refresh_paused
        if self.logs_auto_refresh_paused:
            self.logs_pause_btn.config(text="Resume Auto Refresh")
            self.log_message("Logs auto refresh paused")
        else:
            self.logs_pause_btn.config(text="Pause Auto Refresh")
            self.log_message("Logs auto refresh resumed")

    def _auto_refresh_loop(self):
        """Background thread that automatically refreshes data"""
        while self.auto_refresh_running:
            try:
                # Refresh all sections
                self.refresh_stats()
                self.refresh_monitoring()
                self.refresh_logs()
                
                # Update last refresh time
                self.last_refresh_time = datetime.now().strftime("%H:%M:%S")
                self.refresh_status_label.config(text=f"Last updated: {self.last_refresh_time}")
                
                # Wait for the specified interval
                time.sleep(self.refresh_interval)
            except Exception as e:
                self.log_message(f"Auto-refresh error: {e}")
                time.sleep(1)  # Wait before retrying

    def refresh_stats(self):
        """Refresh statistics display"""
        try:
            stats = self.firewall.get_statistics()
            
            self._clear_text(self.stats_text)
            self._insert_text(self.stats_text, "=== FIREWALL STATISTICS ===\n\n")
            
            # Firewall stats
            self._insert_text(self.stats_text, "Firewall Statistics:\n")
            for key, value in stats['firewall_stats'].items():
                self._insert_text(self.stats_text, f"  {key}: {value}\n")
            
            # Capture stats
            self._insert_text(self.stats_text, "\nPacket Capture Statistics:\n")
            for key, value in stats['capture_stats'].items():
                self._insert_text(self.stats_text, f"  {key}: {value}\n")
            
            # Rule stats
            self._insert_text(self.stats_text, "\nRule Engine Statistics:\n")
            for key, value in stats['rule_stats'].items():
                self._insert_text(self.stats_text, f"  {key}: {value}\n")
            
            # Connection stats
            self._insert_text(self.stats_text, "\nConnection Statistics:\n")
            for key, value in stats['connection_stats'].items():
                self._insert_text(self.stats_text, f"  {key}: {value}\n")
            
            # Log stats
            self._insert_text(self.stats_text, "\nLogging Statistics:\n")
            for key, value in stats['log_stats'].items():
                self._insert_text(self.stats_text, f"  {key}: {value}\n")
            
            # Monitor stats
            self._insert_text(self.stats_text, "\nMonitoring Statistics:\n")
            for key, value in stats['monitor_stats'].items():
                self._insert_text(self.stats_text, f"  {key}: {value}\n")
            
            # Add timestamp
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._insert_text(self.stats_text, f"\n\nLast updated: {timestamp}\n")
                
        except Exception as e:
            self.log_message(f"Error refreshing stats: {e}")
            # Show error in stats
            self._clear_text(self.stats_text)
            self._insert_text(self.stats_text, f"Error loading statistics: {e}\n")
            self._insert_text(self.stats_text, "Make sure the firewall is running and try again.")

    def refresh_monitoring(self):
        """Refresh monitoring display"""
        try:
            # Get metrics (base)
            metrics = self.firewall.monitor.get_metrics()
            
            # Compute 5s moving averages from stateful inspector
            from datetime import datetime, timedelta
            now = datetime.now()
            connections = self.firewall.stateful_inspector.get_all_connections()
            active_count = len(connections)
            new_in_5s = sum(1 for c in connections if (now - c.first_seen) <= timedelta(seconds=5))
            connections_per_sec_5s = round(new_in_5s / 5, 2)
            
            self._clear_text(self.metrics_text)
            self._insert_text(self.metrics_text, "=== REAL-TIME METRICS ===\n\n")
            
            # Show base metrics except ones we replace with smoothed values
            for key, value in metrics.items():
                if key in ("active_connections", "connections_per_second"):
                    continue
                self._insert_text(self.metrics_text, f"{key}: {value}\n")
            
            # Add smoothed metrics
            self._insert_text(self.metrics_text, f"active_connections: {active_count}\n")
            self._insert_text(self.metrics_text, f"connections_per_second(5s_avg): {connections_per_sec_5s}\n")
            
            # Get connections
            connections = self.firewall.stateful_inspector.get_all_connections()
            # Optionally resolve hostnames for display
            resolve = False
            try:
                resolve = bool(getattr(self.firewall.config_manager.get_config(), 'resolve_hostnames', False))
            except Exception:
                resolve = False
            
            def resolve_ip(ip: str) -> str:
                if not resolve:
                    return ip
                if ip in self.hostname_cache:
                    return f"{self.hostname_cache[ip]} ({ip})"
                try:
                    import socket
                    from concurrent.futures import ThreadPoolExecutor
                    def _lookup():
                        return socket.gethostbyaddr(ip)[0]
                    with ThreadPoolExecutor(max_workers=1) as ex:
                        fut = ex.submit(_lookup)
                        name = fut.result(timeout=0.2)
                    self.hostname_cache[ip] = name
                    return f"{name} ({ip})"
                except Exception:
                    self.hostname_cache[ip] = ip
                    return ip
            
            self._clear_text(self.connections_text)
            self._insert_text(self.connections_text, "=== ACTIVE CONNECTIONS ===\n\n")
            
            if connections:
                for conn in connections[-20:]:  # Show last 20 connections
                    src = f"{resolve_ip(conn.src_ip)}:{conn.src_port}" if conn.src_port else resolve_ip(conn.src_ip)
                    dst = f"{resolve_ip(conn.dst_ip)}:{conn.dst_port}" if conn.dst_port else resolve_ip(conn.dst_ip)
                    self._insert_text(self.connections_text,
                        f"{src} -> {dst} ({conn.protocol}) - {conn.state.value}\n"
                    )
            else:
                # Show some sample connections if none exist
                self._insert_text(self.connections_text, "No active connections found.\n\n")
                self._insert_text(self.connections_text, "To see connections:\n")
                self._insert_text(self.connections_text, "1. Start the firewall\n")
                self._insert_text(self.connections_text, "2. Open web browser and visit websites\n")
                self._insert_text(self.connections_text, "3. Run 'ping google.com' in command prompt\n")
                self._insert_text(self.connections_text, "4. Refresh this page\n\n")
                self._insert_text(self.connections_text, "Sample connections you should see:\n")
                self._insert_text(self.connections_text, "192.168.1.100:1234 -> 8.8.8.8:53 (UDP) - ESTABLISHED\n")
                self._insert_text(self.connections_text, "192.168.1.100:1235 -> google.com:443 (TCP) - ESTABLISHED\n")
                self._insert_text(self.connections_text, "192.168.1.100:1236 -> youtube.com:80 (TCP) - ESTABLISHED\n")
                
        except Exception as e:
            self.log_message(f"Error refreshing monitoring: {e}")
            # Show error in connections
            self._clear_text(self.connections_text)
            self._insert_text(self.connections_text, f"Error loading connections: {e}\n")
            self._insert_text(self.connections_text, "Make sure the firewall is running and try again.")

    def refresh_logs(self):
        """Refresh logs display"""
        try:
            # Get recent events
            events = self.firewall.logger.get_recent_events(100)
            
            self._clear_text(self.logs_text)
            self._insert_text(self.logs_text, "=== RECENT LOG EVENTS ===\n\n")
            
            if events:
                for event in events:
                    timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                    self._insert_text(self.logs_text, f"[{timestamp}] {event.level} - {event.message}\n")
            else:
                # Show activity log content if no events
                self._insert_text(self.logs_text, "No log events found. Showing activity log:\n\n")
                activity_content = self.log_text.get(1.0, tk.END)
                if activity_content.strip():
                    self._insert_text(self.logs_text, activity_content)
                else:
                    self._insert_text(self.logs_text, "No activity logged yet. Start the firewall and generate network traffic.\n")
                
        except Exception as e:
            self.log_message(f"Error refreshing logs: {e}")
            # Show error in logs
            self._clear_text(self.logs_text)
            self._insert_text(self.logs_text, f"Error loading logs: {e}\n")
            self._insert_text(self.logs_text, "Make sure the firewall is running and try again.")

    def clear_logs(self):
        """Clear logs display"""
        self._clear_text(self.logs_text)

    def export_logs(self):
        """Export logs to file"""
        try:
            from tkinter import filedialog
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, 'w') as f:
                    f.write(self.logs_text.get(1.0, tk.END))
                messagebox.showinfo("Success", f"Logs exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Error exporting logs: {e}")

# ---------- Main ----------
if __name__ == "__main__":
    import tkinter as tk
    from auth_system import login
    import sys

    # Main loop to support logout and return to login
    while True:
        # Step 1: Authenticate user
        role = login()
        
        # Check if user cancelled login
        if role is None:
            print("Login cancelled. Exiting...")
            break
        
        print(f"Logged in as: {role.upper()}")

        # Step 2: Initialize GUI
        root = tk.Tk()
        gui = EnhancedFirewallGUI(root, role)

        # Step 3: Start GUI loop
        try:
            root.mainloop()
            # If we reach here, user logged out - loop back to login
            print("Returning to login screen...")
        except KeyboardInterrupt:
            print("Firewall stopped by user.")
            break
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
            break