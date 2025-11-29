import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog
import threading
import time
from datetime import datetime
from collections import deque

# Import all modules
from packet_capture import PacketCapture, PacketInfo
from rule_engine import RuleEngine, RuleAction, RuleDirection, Protocol, FirewallRule
from stateful_inspection import StatefulInspector, ConnectionState
from rule_management import RuleManager
from logging_monitoring import FirewallLogger, FirewallMonitor, LogLevel, FirewallEvent
from configuration_policy import ConfigurationManager, PolicyManager
from performance_analyzer import PerformanceAnalyzer

from collections import defaultdict
from datetime import datetime, timedelta
import re

from collections import defaultdict
from datetime import datetime, timedelta
import re
import threading

class SecurityEnhancer:
    """Enhanced security feature enforcement with dynamic configuration"""
    
    def __init__(self, config_manager, log_callback):
        self.config_manager = config_manager
        self.log_callback = log_callback
        self.config_lock = threading.RLock()
        
        # DoS Protection - Track packet rates per IP
        self.packet_rates = defaultdict(list)  # {ip: [timestamps]}
        self.blocked_ips = {}  # {ip: unblock_time}
        self.dos_cleanup_interval = 60  # seconds
        self.last_cleanup = datetime.now()
        
        # Intrusion Detection - Simple signature database
        self.attack_signatures = {
            'port_scan': {'pattern': 'multiple_ports', 'threshold': 10},
            'sql_injection': {'pattern': r"(\bSELECT\b|\bUNION\b|\bDROP\b)", 'threshold': 1},
            'xss_attempt': {'pattern': r"(<script>|javascript:)", 'threshold': 1},
        }
        self.suspicious_activity = defaultdict(set)  # {ip_port: set of ports}
        self.last_ids_cleanup = datetime.now()
        
    def cleanup_dos_tracking(self):
        """Periodically cleanup old tracking data"""
        now = datetime.now()
        if (now - self.last_cleanup).seconds < self.dos_cleanup_interval:
            return
        
        # Remove old timestamps (older than 1 second)
        cutoff = now - timedelta(seconds=1)
        with self.config_lock:
            for ip in list(self.packet_rates.keys()):
                self.packet_rates[ip] = [t for t in self.packet_rates[ip] if t > cutoff]
                if not self.packet_rates[ip]:
                    del self.packet_rates[ip]
            
            # Remove expired IP blocks
            for ip in list(self.blocked_ips.keys()):
                if now > self.blocked_ips[ip]:
                    del self.blocked_ips[ip]
                    self.log_callback(f"🔓 Unblocked IP: {ip}")
        
        self.last_cleanup = now
    
    def cleanup_ids_tracking(self):
        """Cleanup old IDS tracking data (every 5 minutes)"""
        now = datetime.now()
        if (now - self.last_ids_cleanup).seconds < 300:  # 5 minutes
            return
        
        with self.config_lock:
            # Clear old suspicious activity to prevent memory leak
            self.suspicious_activity.clear()
        
        self.last_ids_cleanup = now
    
    def check_dos_protection(self, packet_info) -> tuple[bool, str]:
        """
        Check if packet should be blocked due to DoS protection
        Returns: (should_block, reason)
        
        FIXED: Now properly reads current config each time
        """
        # READ CONFIG FRESH EACH TIME (FIX #1)
        config = self.config_manager.get_config()
        
        # Feature disabled check (FIX #2: Always check current state)
        if not config.enable_dos_protection:
            return False, ""
        
        src_ip = packet_info.src_ip
        now = datetime.now()
        
        with self.config_lock:
            # Check if IP is already blocked
            if src_ip in self.blocked_ips:
                if now < self.blocked_ips[src_ip]:
                    return True, f"DoS Protection (Blocked until {self.blocked_ips[src_ip].strftime('%H:%M:%S')})"
                else:
                    # Block expired
                    del self.blocked_ips[src_ip]
            
            # Track this packet
            self.packet_rates[src_ip].append(now)
            
            # Clean up old timestamps (older than 1 second)
            cutoff = now - timedelta(seconds=1)
            self.packet_rates[src_ip] = [t for t in self.packet_rates[src_ip] if t > cutoff]
            
            # Calculate packets per second
            packets_per_second = len(self.packet_rates[src_ip])
            
            # FIX #3: Validate threshold before using
            threshold = max(1, config.max_packets_per_second)  # Minimum 1 pkt/s
            
            # Check against threshold
            if packets_per_second > threshold:
                # Block this IP for 60 seconds
                self.blocked_ips[src_ip] = now + timedelta(seconds=60)
                self.log_callback(
                    f"🚨 DoS DETECTED: {src_ip} ({packets_per_second} pkt/s > {threshold} limit)"
                )
                return True, f"DoS Protection ({packets_per_second} pkt/s exceeds limit)"
        
        # Periodic cleanup
        self.cleanup_dos_tracking()
        
        return False, ""
    
    def check_intrusion_detection(self, packet_info) -> tuple[bool, str]:
        """
        Check if packet matches intrusion signatures
        Returns: (should_alert, reason)
        
        FIXED: Now properly reads current config each time
        """
        # READ CONFIG FRESH EACH TIME (FIX #1)
        config = self.config_manager.get_config()
        
        # Feature disabled check (FIX #2: Always check current state)
        if not config.enable_intrusion_detection:
            return False, ""
        
        src_ip = packet_info.src_ip
        
        with self.config_lock:
            # Check for port scanning (accessing many different ports)
            if hasattr(packet_info, 'dst_port') and packet_info.dst_port:
                key = f"{src_ip}_ports"
                
                # Initialize set if needed
                if key not in self.suspicious_activity:
                    self.suspicious_activity[key] = set()
                
                self.suspicious_activity[key].add(packet_info.dst_port)
                
                # FIX #4: Use configurable threshold from attack_signatures
                threshold = self.attack_signatures['port_scan']['threshold']
                if len(self.suspicious_activity[key]) > threshold:
                    self.log_callback(
                        f"🚨 PORT SCAN DETECTED: {src_ip} scanned "
                        f"{len(self.suspicious_activity[key])} ports"
                    )
                    return True, f"Intrusion Detection (Port Scan)"
        
        # Check payload for attack patterns (if available)
        if hasattr(packet_info, 'payload') and packet_info.payload:
            payload_str = str(packet_info.payload)
            
            # SQL Injection detection
            sql_pattern = re.compile(
                r"(\bSELECT\b|\bUNION\b|\bDROP\b|\bINSERT\b|\bDELETE\b)", 
                re.IGNORECASE
            )
            if sql_pattern.search(payload_str):
                self.log_callback(f"🚨 SQL INJECTION ATTEMPT: {src_ip}")
                return True, f"Intrusion Detection (SQL Injection)"
            
            # XSS detection
            xss_pattern = re.compile(
                r"(<script>|javascript:|onerror=|onload=)", 
                re.IGNORECASE
            )
            if xss_pattern.search(payload_str):
                self.log_callback(f"🚨 XSS ATTEMPT: {src_ip}")
                return True, f"Intrusion Detection (XSS)"
        
        # Periodic cleanup
        self.cleanup_ids_tracking()
        
        return False, ""
    
    def should_apply_stateful_inspection(self) -> bool:
        """
        Check if stateful inspection should be applied
        FIXED: Always read fresh config
        """
        config = self.config_manager.get_config()
        return config.enable_stateful_inspection
    
    def reset_dos_blocks(self):
        """Clear all DoS blocks (for testing/admin)"""
        with self.config_lock:
            cleared = len(self.blocked_ips)
            self.blocked_ips.clear()
            self.packet_rates.clear()
        self.log_callback(f"🔓 Cleared {cleared} DoS blocks")
        return cleared
    
    def reset_ids_tracking(self):
        """Clear all IDS tracking (for testing/admin)"""
        with self.config_lock:
            cleared = len(self.suspicious_activity)
            self.suspicious_activity.clear()
        self.log_callback(f"🔄 Cleared {cleared} IDS tracking entries")
        return cleared
    
    def get_statistics(self) -> dict:
        """Get security statistics"""
        with self.config_lock:
            return {
                'dos_blocked_ips': len(self.blocked_ips),
                'dos_tracked_ips': len(self.packet_rates),
                'ids_suspicious_ips': len(self.suspicious_activity),
                'settings': {
                    'stateful_inspection': self.should_apply_stateful_inspection(),
                    'intrusion_detection': self.config_manager.get_config().enable_intrusion_detection,
                    'dos_protection': self.config_manager.get_config().enable_dos_protection,
                    'max_packets_per_second': self.config_manager.get_config().max_packets_per_second
                }
            }


class EnhancedFirewall:
    def __init__(self, log_callback):
        self.running = False
        self.log_callback = log_callback
        self.log_level_priority = {
            LogLevel.DEBUG: 10,
            LogLevel.INFO: 20,
            LogLevel.WARNING: 30,
            LogLevel.ERROR: 40,
            LogLevel.CRITICAL: 50,
        }
        
        # Initialize all modules
        self.packet_capture = PacketCapture(self.log_callback)
        self.rule_engine = RuleEngine(self.log_callback)
        self.stateful_inspector = StatefulInspector(self.log_callback)
        self.rule_manager = RuleManager(self.rule_engine)
        self.config_manager = ConfigurationManager()
        cfg = self.config_manager.get_config()
        self.logger = FirewallLogger(min_level=cfg.log_level)
        self.monitor = FirewallMonitor(self.logger)
        self.policy_manager = PolicyManager()
        
        # Packet log buffer for real-time display
        self.packet_log_buffer = deque(maxlen=1000)
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'packets_blocked': 0,
            'packets_allowed': 0,
            'connections_tracked': 0,
            'rules_evaluated': 0
        }
        self.security_enhancer = SecurityEnhancer(self.config_manager, self.log_callback)
    
    def start(self):
        """Start the enhanced firewall"""
        self.running = True
        self.log_callback("🔥 Firewall Engine Started")
        
        # Start monitoring
        self.monitor.start_monitoring()

        # Start stateful inspector
        try:
            if hasattr(self.stateful_inspector, 'start'):
                self.stateful_inspector.start()
        except Exception as e:
            self.log_callback(f"⚠️ Stateful inspector error: {e}")
        
        # Apply default action from config
        try:
            cfg = self.config_manager.get_config()
            if str(cfg.default_action).upper() == "DENY":
                self.rule_engine.set_default_action(RuleAction.DENY)
                self.log_callback("🛡️ Default Policy: DENY (Secure)")
            else:
                self.rule_engine.set_default_action(RuleAction.ALLOW)
                self.log_callback("⚠️ Default Policy: ALLOW (Permissive)")
        except Exception as e:
            self.log_callback(f"⚠️ Config error: {e}")

        # Show loaded rules
        rule_count = len(self.rule_engine.get_all_rules())
        enabled_count = len(self.rule_engine.get_enabled_rules())
        self.log_callback(f"📋 Active Rules: {enabled_count}/{rule_count}")
        
        # Start packet capture
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
            message="Firewall started successfully"
        ))
    
    def _start_packet_capture_with_processing(self):
        """Start packet capture with integrated processing"""
        try:
            from pydivert import WinDivert
            
            self.log_callback("🔍 Packet Inspection Active")
            
            # Capture all IPv4 traffic
            with WinDivert("ip") as w:
                for packet in w:
                    if not self.running:
                        break
                    
                    try:
                        # Parse packet (ONCE)
                        packet_info = self.packet_capture._parse_packet(packet)
                        self.packet_capture._update_stats(packet_info)
                        
                        # Process through firewall (SINGLE CALL)
                        should_allow, match_info = self.process_packet(packet_info)

                        # Format packet details
                        src = f"{packet_info.src_ip}:{packet_info.src_port}" if packet_info.src_port else packet_info.src_ip
                        dst = f"{packet_info.dst_ip}:{packet_info.dst_port}" if packet_info.dst_port else packet_info.dst_ip
                        proto = packet_info.protocol
                        
                        # Create log entry
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        rule_name = match_info.get('rule_name', 'Default Policy')
                        
                        if should_allow:
                            # Send packet immediately
                            w.send(packet)
                            
                            # Only log blocked or explicitly allowed by rule (not default allow)
                            if match_info.get('decision_source') == 'rule' and match_info.get('rule_name'):
                                log_entry = f"[{timestamp}] ✅ ALLOW | {proto:4} | {src:21} → {dst:21} | Rule: {rule_name}"
                                self._append_packet_log(log_entry, LogLevel.INFO)
                        else:
                            # Packet is dropped (not sent)
                            log_entry = f"[{timestamp}] 🚫 BLOCK | {proto:4} | {src:21} → {dst:21} | Rule: {rule_name}"
                            self._append_packet_log(log_entry, LogLevel.WARNING)
                            self.log_callback(f"BLOCKED: {src} → {dst} by '{rule_name}'")
                    
                    except Exception as e:
                        # Log packet-specific errors but continue processing
                        if "parameter is incorrect" not in str(e).lower():
                            self.log_callback(f"⚠️ Packet error: {e}")
                        continue
                    
        except Exception as e:
            self.log_callback(f"❌ Capture error: {e}")
            self.running = False

    def stop(self):
        """Stop the enhanced firewall"""
        self.running = False
        self.packet_capture.stop_capture()
        self.monitor.stop_monitoring()
        self.stateful_inspector.stop()
        self.logger.stop()
        
        # Wait for capture thread
        if hasattr(self, 'capture_thread') and self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)
        
        self.log_callback("🔥 Firewall Stopped")
        
        # Log shutdown
        self.logger.log_event(FirewallEvent(
            timestamp=datetime.now(),
            event_type="FIREWALL_STOPPED",
            level=LogLevel.INFO,
            message="Firewall stopped"
        ))

    def _append_packet_log(self, text: str, level: str):
        """Store packet log entries with level metadata for filtering"""
        entry = {
            'text': text,
            'level': level if level in self.log_level_priority else LogLevel.INFO
        }
        self.packet_log_buffer.append(entry)

    def _is_debug_enabled(self) -> bool:
        """Check if debug-level diagnostics should be emitted."""
        current_level = self.logger.get_log_level()
        min_priority = self.log_level_priority.get(current_level, self.log_level_priority[LogLevel.INFO])
        return min_priority <= self.log_level_priority[LogLevel.DEBUG]

    def _emit_debug_packet_details(self, packet_info, match_info, policy_actions, decision, decision_source):
        if not self._is_debug_enabled():
            return

        timestamp = datetime.now().strftime("%H:%M:%S")
        src = f"{packet_info.src_ip}:{packet_info.src_port}" if getattr(packet_info, 'src_port', None) else packet_info.src_ip
        dst = f"{packet_info.dst_ip}:{packet_info.dst_port}" if getattr(packet_info, 'dst_port', None) else packet_info.dst_ip
        policy_str = ', '.join(policy_actions) if policy_actions else 'none'
        decision_str = 'ALLOW' if decision else 'BLOCK'
        rule_name = match_info.get('rule_name') or 'default'
        state = match_info.get('connection_state') or 'none'

        # Header (print only once)
        header = (
            f"{'TIME':<10} | {'STATE':<10} | {'POLICY':<20} | {'ACTION':<6} | {'PROTO':<6} | "
            f"{'SOURCE':<23} | {'DESTINATION':<23} | {'RULE':<25}"
        )

        if not hasattr(self, "_header_logged"):
            self._append_packet_log(header, LogLevel.DEBUG)
            self._append_packet_log("-" * len(header), LogLevel.DEBUG)
            self._header_logged = True

        # Packet log row
        debug_text = (
            f"{timestamp:<10} | {state:<10} | {policy_str:<20} | {decision_str:<6} | {packet_info.protocol:<6} | "
            f"{src:<23} | {dst:<23} | {rule_name:<25}"
        )

        self._append_packet_log(debug_text, LogLevel.DEBUG)

        # Structured logging
        self.logger.log_event(FirewallEvent(
            timestamp=datetime.now(),
            event_type="PACKET_DEBUG",
            level=LogLevel.DEBUG,
            message=f"decision={decision_str}; rule={rule_name}; policy={policy_str}; state={state}",
            source_ip=packet_info.src_ip,
            dest_ip=packet_info.dst_ip,
            protocol=packet_info.protocol,
            action=decision_str,
            rule_id=match_info.get('rule_id'),
            additional_data={
                'policy_actions': policy_actions,
                'connection_state': state,
                'decision_source': decision_source
            }
        ))


    def reload_configuration(self) -> bool:
        """Live-reload configuration and policies"""
        try:
            cfg_ok = self.config_manager.load_configuration()
            pol_ok = self.policy_manager.load_policies()

            # Apply default action
            try:
                cfg = self.config_manager.get_config()
                if str(cfg.default_action).upper() == "DENY":
                    self.rule_engine.set_default_action(RuleAction.DENY)
                else:
                    self.rule_engine.set_default_action(RuleAction.ALLOW)
                self.logger.set_log_level(cfg.log_level)
            except Exception as e:
                self.log_callback(f"⚠️ Config reload error: {e}")

            self.log_callback("🔄 Configuration Reloaded")
            return bool(cfg_ok and pol_ok)
        except Exception as e:
            self.log_callback(f"❌ Reload error: {e}")
            return False
    # ============================================================================
# NETWORK FILTERING FIX - Add this to EnhancedFirewall class
# Location: Add after line ~540 in the main file (after DoS/IDS checks)
# ============================================================================

    def _check_network_policy(self, packet_info: PacketInfo) -> tuple[bool, str]:
        """
        Check packet against trusted/blocked network lists
        Returns: (should_allow, reason)
        
        Priority:
        1. Blocked networks (explicit deny) - highest priority
        2. Trusted networks (explicit allow) - medium priority  
        3. None matched - continue to rule evaluation
        """
        try:
            config = self.config_manager.get_config()
            src_ip = packet_info.src_ip
            dst_ip = packet_info.dst_ip
            
            # Check if source IP is in BLOCKED networks (highest priority)
            if config.blocked_networks:
                for blocked_net in config.blocked_networks:
                    if self._ip_matches_network(src_ip, blocked_net):
                        return False, f"Blocked Network ({blocked_net})"
            
            # Check if destination IP is in BLOCKED networks
            if config.blocked_networks:
                for blocked_net in config.blocked_networks:
                    if self._ip_matches_network(dst_ip, blocked_net):
                        return False, f"Blocked Network ({blocked_net})"
            
            # Check if source IP is in TRUSTED networks (medium priority)
            if config.trusted_networks:
                for trusted_net in config.trusted_networks:
                    if self._ip_matches_network(src_ip, trusted_net):
                        return True, f"Trusted Network ({trusted_net})"
            
            # Check if destination IP is in TRUSTED networks
            if config.trusted_networks:
                for trusted_net in config.trusted_networks:
                    if self._ip_matches_network(dst_ip, trusted_net):
                        return True, f"Trusted Network ({trusted_net})"
            
            # No network policy matched - continue to next stage
            return None, ""
            
        except Exception as e:
            self.log_callback(f"⚠️ Network policy error: {e}")
            return None, ""

    def _ip_matches_network(self, ip: str, network: str) -> bool:
        """
        Check if IP matches network pattern
        Supports:
        - Exact match: 192.168.1.100
        - CIDR notation: 192.168.1.0/24
        - Wildcard: 192.168.1.*
        """
        try:
            # Exact match
            if ip == network:
                return True
            
            # Wildcard match (e.g., 192.168.1.*)
            if '*' in network:
                pattern = network.replace('.', r'\.').replace('*', r'\d+')
                import re
                return bool(re.match(f"^{pattern}$", ip))
            
            # CIDR notation (e.g., 192.168.1.0/24)
            if '/' in network:
                return self._ip_in_cidr(ip, network)
            
            return False
            
        except Exception as e:
            print(f"IP match error: {e}")
            return False

    def _ip_in_cidr(self, ip: str, cidr: str) -> bool:
        """Check if IP is in CIDR range"""
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except Exception:
            return False

    def process_packet(self, packet_info: PacketInfo) -> tuple[bool, dict]:
        """Process a packet through all security layers"""
        packet_counted = False
        try:
            self.stats['packets_processed'] += 1
            packet_counted = True

            # ====== LAYER 1: DoS Protection ======
            dos_block, dos_reason = self.security_enhancer.check_dos_protection(packet_info)
            if dos_block:
                self.stats['packets_blocked'] += 1
                self.logger.log_packet_blocked(
                    packet_info.src_ip, 
                    packet_info.dst_ip, 
                    packet_info.protocol, 
                    reason=dos_reason
                )
                return False, {'rule_name': dos_reason, 'decision_source': 'dos_protection'}

            # ====== LAYER 2: Intrusion Detection ======
            ids_alert, ids_reason = self.security_enhancer.check_intrusion_detection(packet_info)
            if ids_alert:
                self.logger.log_event(FirewallEvent(
                    timestamp=datetime.now(),
                    event_type="INTRUSION_DETECTED",
                    level=LogLevel.WARNING,
                    message=f"{ids_reason} from {packet_info.src_ip}"
                ))

            # ====== LAYER 3: Network Policy (NEW!) ======
            network_decision, network_reason = self._check_network_policy(packet_info)
            if network_decision is not None:  # Explicit allow/deny from network policy
                if network_decision:
                    self.stats['packets_allowed'] += 1
                    self.logger.log_packet_allowed(
                        packet_info.src_ip, 
                        packet_info.dst_ip, 
                        packet_info.protocol, 
                        reason=network_reason
                    )
                else:
                    self.stats['packets_blocked'] += 1
                    self.logger.log_packet_blocked(
                        packet_info.src_ip, 
                        packet_info.dst_ip, 
                        packet_info.protocol, 
                        reason=network_reason
                    )
                
                match_info = {
                    'rule_name': network_reason,
                    'decision_source': 'network_policy'
                }
                
                self._emit_debug_packet_details(
                    packet_info,
                    match_info,
                    [],
                    network_decision,
                    'network_policy'
                )
                
                return network_decision, match_info

            # ====== LAYER 4: Stateful Inspection ======
            stateful_allow = True
            connection_state = None
            connection = None
            
            if self.security_enhancer.should_apply_stateful_inspection():
                stateful_allow, connection_state, connection = self.stateful_inspector.inspect_packet(packet_info)
                if connection:
                    self.stats['connections_tracked'] += 1

            # ====== LAYER 5: Rule Engine ======
            rule_allow, matching_rule = self.rule_engine.evaluate_packet(packet_info)
            self.stats['rules_evaluated'] += 1

            # ====== LAYER 6: Policy Manager ======
            policy_actions = self.policy_manager.evaluate_policies(packet_info)
            policy_forced_allow = any(a.name == 'ALLOW' for a in policy_actions)
            policy_forced_deny = any(a.name == 'DENY' or a.name == 'QUARANTINE' for a in policy_actions)

            # ====== DECISION PRECEDENCE ======
            # Order: explicit rule > policy > stateful > default
            if matching_rule:
                final_decision = rule_allow
                decision_source = 'rule'
            elif policy_forced_deny or policy_forced_allow:
                final_decision = not policy_forced_deny
                decision_source = 'policy'
            elif connection_state is not None and self.security_enhancer.should_apply_stateful_inspection():
                final_decision = stateful_allow
                decision_source = 'stateful'
            else:
                final_decision = (self.rule_engine.default_action == RuleAction.ALLOW)
                decision_source = 'default'

            # Prepare match info
            match_info = {
                'rule_name': getattr(matching_rule, 'name', None),
                'rule_id': getattr(matching_rule, 'id', None),
                'default_action': self.rule_engine.default_action.value if decision_source == 'default' else None,
                'connection_state': connection_state.value if connection_state else None,
                'decision_source': decision_source,
                'policy_actions': [a.value for a in policy_actions] if policy_actions else [],
            }

            # Update stats
            if final_decision:
                self.stats['packets_allowed'] += 1
                reason = match_info['rule_name'] or match_info.get('connection_state') or match_info.get('default_action')
                self.logger.log_packet_allowed(packet_info.src_ip, packet_info.dst_ip, packet_info.protocol, reason=reason)
            else:
                self.stats['packets_blocked'] += 1
                reason = match_info.get('rule_name') or "Default Policy"
                self.logger.log_packet_blocked(packet_info.src_ip, packet_info.dst_ip, packet_info.protocol, reason=reason)

            self._emit_debug_packet_details(
                packet_info,
                match_info,
                match_info.get('policy_actions', []),
                final_decision,
                decision_source
            )

            return final_decision, match_info

        except Exception as e:
            self.log_callback(f"❌ Processing error: {e}")
            if packet_counted:
                self.stats['packets_blocked'] += 1
            else:
                self.stats['packets_processed'] += 1
                self.stats['packets_blocked'] += 1
            try:
                self.logger.log_packet_blocked(
                    getattr(packet_info, 'src_ip', 'unknown'),
                    getattr(packet_info, 'dst_ip', 'unknown'),
                    getattr(packet_info, 'protocol', 'unknown'),
                    reason="Processing Error"
                )
            except Exception:
                pass
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
        self.packet_refresh_thread = None
        self.auto_refresh_thread = None
        self.auto_refresh_running = False
        self.packet_refresh_paused = False
        self.stats_refresh_paused = False
        self.refresh_interval = 2
        self.stats_refresh_interval = 1000  # milliseconds (1 second)
        self.stats_refresh_job = None
        
        # Search variables
        self.search_var = tk.StringVar()
        self.log_level_priority = {
            LogLevel.DEBUG: 10,
            LogLevel.INFO: 20,
            LogLevel.WARNING: 30,
            LogLevel.ERROR: 40,
            LogLevel.CRITICAL: 50,
        }

        # Create notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self._create_dashboard_tab()
        self._create_rules_tab()
        self._create_packets_tab()  # NEW: Dedicated packets tab
        self._create_monitoring_tab()
        
        self._create_configuration_tab()

        self.performance_analyzer = PerformanceAnalyzer(self.notebook)
        perf_frame = self.performance_analyzer.get_frame()
        self.notebook.add(perf_frame, text="Performance")
        
        # Start auto-refresh for statistics
        self._start_stats_auto_refresh()

    def _insert_text(self, widget, text):
        """Temporarily enable widget, insert text, then disable it again"""
        widget.config(state=tk.NORMAL)
        widget.insert(tk.END, text)
        widget.config(state=tk.DISABLED)

    def _clear_text(self, widget):
        """Temporarily enable widget, clear it, then disable it again"""
        widget.config(state=tk.NORMAL)
        widget.delete(1.0, tk.END)
        widget.config(state=tk.DISABLED)

    def _create_dashboard_tab(self):
        """Create main dashboard tab"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="📊 Dashboard")

        # Control buttons
        control_frame = ttk.Frame(dashboard_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=10)

        self.start_btn = ttk.Button(control_frame, text="▶ Start Firewall", command=self.start_firewall, width=15)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(control_frame, text="⏹ Stop Firewall", command=self.stop_firewall, width=15)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.stats_btn = ttk.Button(control_frame, text="🔄 Refresh", command=self.refresh_stats, width=15)
        self.stats_btn.pack(side=tk.LEFT, padx=5)
        
        self.stats_pause_btn = ttk.Button(control_frame, text="⏸ Pause Auto-Refresh", command=self.toggle_stats_refresh, width=18)
        self.stats_pause_btn.pack(side=tk.LEFT, padx=5)

        # Status display
        status_frame = ttk.LabelFrame(dashboard_frame, text="⚡ Status")
        status_frame.pack(fill=tk.X, padx=10, pady=5)

        self.status_label = ttk.Label(status_frame, text="Firewall: Stopped", font=("Arial", 12, "bold"), foreground="red")
        self.status_label.pack(pady=10)

        # Statistics display
        stats_frame = ttk.LabelFrame(dashboard_frame, text="📈 Statistics")
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=15, width=80, state=tk.DISABLED, font=("Consolas", 9))
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Activity log
        log_frame = ttk.LabelFrame(dashboard_frame, text="📋 Activity Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, width=80, state=tk.DISABLED, font=("Consolas", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _create_packets_tab(self):
        """Create dedicated packets tab with search"""
        packets_frame = ttk.Frame(self.notebook)
        self.notebook.add(packets_frame, text="📋 Logs")

        # Search bar
        search_frame = ttk.Frame(packets_frame)
        search_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(search_frame, text="🔍 Search:").pack(side=tk.LEFT, padx=5)
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=40)
        search_entry.pack(side=tk.LEFT, padx=5)
        search_entry.bind('<KeyRelease>', self._search_packets)
        
        ttk.Button(search_frame, text="Clear", command=self._clear_search).pack(side=tk.LEFT, padx=5)
        ttk.Button(search_frame, text="Export", command=self.export_packets).pack(side=tk.LEFT, padx=5)
        
        # Filter options
        filter_frame = ttk.Frame(packets_frame)
        filter_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="All", command=lambda: self._filter_packets("all")).pack(side=tk.LEFT, padx=2)
        ttk.Button(filter_frame, text="Blocked", command=lambda: self._filter_packets("blocked")).pack(side=tk.LEFT, padx=2)
        ttk.Button(filter_frame, text="Allowed", command=lambda: self._filter_packets("allowed")).pack(side=tk.LEFT, padx=2)
        ttk.Button(filter_frame, text="TCP", command=lambda: self._filter_packets("tcp")).pack(side=tk.LEFT, padx=2)
        ttk.Button(filter_frame, text="UDP", command=lambda: self._filter_packets("udp")).pack(side=tk.LEFT, padx=2)

        # Packets display
        self.packets_text = scrolledtext.ScrolledText(packets_frame, height=30, width=120, state=tk.DISABLED, 
                                                       font=("Consolas", 9), wrap=tk.NONE)
        self.packets_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Auto-scroll checkbox
        auto_scroll_frame = ttk.Frame(packets_frame)
        auto_scroll_frame.pack(fill=tk.X, padx=10, pady=5)
        self.auto_scroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(auto_scroll_frame, text="Auto-scroll", variable=self.auto_scroll_var).pack(side=tk.LEFT)
        self.pause_btn = ttk.Button(auto_scroll_frame, text="⏸ Pause", command=self.toggle_packet_refresh)
        self.pause_btn.pack(side=tk.LEFT, padx=10)

        
        # Start packet refresh thread
        self._start_packet_refresh()
    def toggle_packet_refresh(self):
        """Toggle pause/resume of packet display"""
        self.packet_refresh_paused = not self.packet_refresh_paused
        if self.packet_refresh_paused:
            self.pause_btn.config(text="▶ Resume")
            self.log_message("📋 Packet display paused")
        else:
            self.pause_btn.config(text="⏸ Pause")
            self.log_message("📋 Packet display resumed")

    def _start_packet_refresh(self):
        """Start thread to refresh packet display"""
        def refresh_loop():
            while True:
                try:
                    if self.firewall.running:
                        self.refresh_packets()
                    time.sleep(0.5)  # Refresh every 500ms
                except Exception as e:
                    print(f"Packet refresh error: {e}")
                    time.sleep(1)
        
        self.packet_refresh_thread = threading.Thread(target=refresh_loop, daemon=True)
        self.packet_refresh_thread.start()

    def refresh_packets(self):
        """Refresh packet display from buffer"""
        try:
            # Check if paused - ADD THESE 2 LINES HERE
            if self.packet_refresh_paused:
                return
            
            # Get recent packets from buffer
            packets = [self._normalize_packet_entry(p) for p in list(self.firewall.packet_log_buffer)]
            current_level = self.firewall.logger.get_log_level()
            packets = [p for p in packets if self._should_display_packet(p['level'], current_level)]
            
            if not packets:
                return
            
            # Update display
            self._clear_text(self.packets_text)
            self._insert_text(self.packets_text, "═" * 120 + "\n")
            self._insert_text(self.packets_text, f"{'TIME':^10} {'ACTION':^8} {'PROTO':^6} {'SOURCE':^23} {'DESTINATION':^23} {'RULE':^30}\n")
            self._insert_text(self.packets_text, "═" * 120 + "\n")
            
            for packet in packets[-500:]:  # Show last 500
                self._insert_text(self.packets_text, packet['text'] + "\n")
            
            # Auto-scroll if enabled
            if self.auto_scroll_var.get():
                self.packets_text.see(tk.END)
                
        except Exception as e:
            pass  # Silently continue

    def _search_packets(self, event=None):
        """Search packets in real-time"""
        search_term = self.search_var.get().lower()
        if not search_term:
            self.refresh_packets()
            return
        
        packets = [self._normalize_packet_entry(p) for p in list(self.firewall.packet_log_buffer)]
        current_level = self.firewall.logger.get_log_level()
        filtered = [
            p for p in packets 
            if self._should_display_packet(p['level'], current_level) 
            and search_term in p['text'].lower()
        ]
        
        self._clear_text(self.packets_text)
        self._insert_text(self.packets_text, f"🔍 Search results for: '{search_term}' ({len(filtered)} matches)\n\n")
        for packet in filtered[-500:]:
            self._insert_text(self.packets_text, packet['text'] + "\n")

    def _clear_search(self):
        """Clear search"""
        self.search_var.set("")
        self.refresh_packets()

    def _filter_packets(self, filter_type):
        """Filter packets by type"""
        packets = [self._normalize_packet_entry(p) for p in list(self.firewall.packet_log_buffer)]
        current_level = self.firewall.logger.get_log_level()
        packets = [p for p in packets if self._should_display_packet(p['level'], current_level)]
        
        if filter_type == "all":
            filtered = packets
        elif filter_type == "blocked":
            filtered = [p for p in packets if "🚫 BLOCK" in p['text']]
        elif filter_type == "allowed":
            filtered = [p for p in packets if "✅ ALLOW" in p['text']]
        elif filter_type == "tcp":
            filtered = [p for p in packets if "TCP" in p['text']]
        elif filter_type == "udp":
            filtered = [p for p in packets if "UDP" in p['text']]
        else:
            filtered = packets
        
        self._clear_text(self.packets_text)
        self._insert_text(self.packets_text, f"📊 Filter: {filter_type.upper()} ({len(filtered)} packets)\n\n")
        for packet in filtered[-500:]:
            self._insert_text(self.packets_text, packet['text'] + "\n")

    def export_packets(self):
        """Export packets to file"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")]
            )
            if filename:
                packets = [self._normalize_packet_entry(p) for p in list(self.firewall.packet_log_buffer)]
                current_level = self.firewall.logger.get_log_level()
                with open(filename, 'w') as f:
                    for packet in packets:
                        if self._should_display_packet(packet['level'], current_level):
                            f.write(packet['text'] + "\n")
                messagebox.showinfo("Success", f"Exported {len(packets)} packets to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Export error: {e}")

    def _create_rules_tab(self):
        """Create rules management tab"""
        rules_frame = ttk.Frame(self.notebook)
        self.notebook.add(rules_frame, text="🛡️ Rules")
        self.rule_manager_gui = self.firewall.rule_manager.show_gui(rules_frame)

    def _create_monitoring_tab(self):
        """Create monitoring tab"""
        monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitor_frame, text="📡 Monitoring")

        metrics_frame = ttk.LabelFrame(monitor_frame, text="Real-time Metrics")
        metrics_frame.pack(fill=tk.X, padx=10, pady=5)

        self.metrics_text = scrolledtext.ScrolledText(metrics_frame, height=10, width=80, state=tk.DISABLED, font=("Consolas", 9))
        self.metrics_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        conn_frame = ttk.LabelFrame(monitor_frame, text="Active Connections")
        conn_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.connections_text = scrolledtext.ScrolledText(conn_frame, height=15, width=80, state=tk.DISABLED, font=("Consolas", 9))
        self.connections_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        ttk.Button(monitor_frame, text="🔄 Refresh Monitoring", command=self.refresh_monitoring).pack(pady=5)

   

    def _create_configuration_tab(self):
        """Create configuration tab"""
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text="⚙️ Configuration")

        from configuration_policy import ConfigurationGUI
        self.config_gui = ConfigurationGUI(
            config_frame,
            self.firewall.config_manager,
            self.firewall.policy_manager,
            on_save_callback=self._on_configuration_saved
        )

        reload_frame = ttk.Frame(config_frame)
        reload_frame.pack(fill=tk.X, padx=10, pady=6)
        ttk.Button(reload_frame, text="🔄 Apply Config (Live)", command=self.reload_firewall_config).pack(side=tk.LEFT, padx=5)

    def reload_firewall_config(self):
        """Trigger live reload of firewall configuration"""
        ok = self.firewall.reload_configuration()
        if ok:
            messagebox.showinfo("Reload", "Configuration reloaded successfully.")
        else:
            messagebox.showwarning("Reload", "Reload completed with issues.")

    def _on_configuration_saved(self):
        """Auto-apply configuration after saving"""
        ok = self.firewall.reload_configuration()
        if ok:
            self.log_message("🔁 Configuration saved and applied live.")
        else:
            self.log_message("⚠️ Configuration saved, but live reload had issues.")

    def _normalize_packet_entry(self, entry):
        """Ensure packet entries have text+level structure"""
        if isinstance(entry, dict):
            return entry
        return {'text': entry, 'level': LogLevel.INFO}

    def _should_display_packet(self, packet_level: str, min_level: str) -> bool:
        """Apply same level filtering used by logger to UI buffer"""
        packet_priority = self.log_level_priority.get(packet_level, self.log_level_priority[LogLevel.INFO])
        min_priority = self.log_level_priority.get(min_level, self.log_level_priority[LogLevel.INFO])
        return packet_priority >= min_priority

    def log_message(self, message):
        """Log message to activity log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        if hasattr(self, 'log_text') and self.log_text:
            self._insert_text(self.log_text, f"[{timestamp}] {message}\n")
            self.log_text.see(tk.END)
        else:
            print(f"[{timestamp}] {message}")

    def start_firewall(self):
        """Start firewall in a background thread"""
        if self.thread and self.thread.is_alive():
            messagebox.showinfo("Info", "Firewall already running.")
            return

        self.thread = threading.Thread(target=self.firewall.start, daemon=True)
        self.thread.start()
        self.status_label.config(text="Firewall: Running", foreground="green")

    def stop_firewall(self):
        """Stop the firewall safely"""
        self.firewall.stop()
        self.status_label.config(text="Firewall: Stopped", foreground="red")

    def toggle_stats_refresh(self):
        """Toggle pause/resume of statistics auto-refresh"""
        self.stats_refresh_paused = not self.stats_refresh_paused
        if self.stats_refresh_paused:
            # Cancel the scheduled refresh
            if self.stats_refresh_job:
                self.root.after_cancel(self.stats_refresh_job)
                self.stats_refresh_job = None
            self.stats_pause_btn.config(text="▶ Resume Auto-Refresh")
            self.log_message("📊 Statistics auto-refresh paused")
        else:
            self.stats_pause_btn.config(text="⏸ Pause Auto-Refresh")
            self.log_message("📊 Statistics auto-refresh resumed")
            # Resume auto-refresh
            self._start_stats_auto_refresh()
    
    def _start_stats_auto_refresh(self):
        """Start auto-refresh for statistics using tkinter's after method"""
        # Cancel any existing refresh job
        if self.stats_refresh_job:
            self.root.after_cancel(self.stats_refresh_job)
            self.stats_refresh_job = None
        
        # Only schedule if not paused
        if not self.stats_refresh_paused:
            self.refresh_stats()
            # Schedule next refresh
            self.stats_refresh_job = self.root.after(self.stats_refresh_interval, self._start_stats_auto_refresh)
    
    def refresh_stats(self):
        """Refresh statistics display"""
        try:
            stats = self.firewall.get_statistics()
            
            self._clear_text(self.stats_text)
            self._insert_text(self.stats_text, "═══════════════════════════════════════════════\n")
            self._insert_text(self.stats_text, "           FIREWALL STATISTICS\n")
            self._insert_text(self.stats_text, "═══════════════════════════════════════════════\n\n")
            
            self._insert_text(self.stats_text, "Packet Statistics:\n")
            self._insert_text(self.stats_text, f"  Total Processed:  {stats['firewall_stats']['packets_processed']:,}\n")
            self._insert_text(self.stats_text, f"  Allowed:          {stats['firewall_stats']['packets_allowed']:,}\n")
            self._insert_text(self.stats_text, f"  Blocked:          {stats['firewall_stats']['packets_blocked']:,}\n")
            self._insert_text(self.stats_text, f"  Connections:      {stats['firewall_stats']['connections_tracked']:,}\n\n")
            
            self._insert_text(self.stats_text, "Rule Engine:\n")
            self._insert_text(self.stats_text, f"  Total Rules:      {stats['rule_stats']['total_rules']}\n")
            self._insert_text(self.stats_text, f"  Enabled Rules:    {stats['rule_stats']['enabled_rules']}\n")
            self._insert_text(self.stats_text, f"  Default Action:   {stats['rule_stats']['default_action']}\n\n")
            
            self._insert_text(self.stats_text, "Connections:\n")
            self._insert_text(self.stats_text, f"  Active:           {stats['connection_stats']['total_connections']}\n\n")
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._insert_text(self.stats_text, f"Last updated: {timestamp}\n")
                
        except Exception as e:
            self.log_message(f"Error refreshing stats: {e}")

    def refresh_monitoring(self):
        """Refresh monitoring display"""
        try:
            metrics = self.firewall.monitor.get_metrics()
            
            self._clear_text(self.metrics_text)
            self._insert_text(self.metrics_text, "═══ REAL-TIME METRICS ═══\n\n")
            
            for key, value in metrics.items():
                self._insert_text(self.metrics_text, f"{key}: {value}\n")
            
            connections = self.firewall.stateful_inspector.get_all_connections()
            
            self._clear_text(self.connections_text)
            self._insert_text(self.connections_text, "═══ ACTIVE CONNECTIONS ═══\n\n")
            
            if connections:
                for conn in connections[-50:]:
                    src = f"{conn.src_ip}:{conn.src_port}" if conn.src_port else conn.src_ip
                    dst = f"{conn.dst_ip}:{conn.dst_port}" if conn.dst_port else conn.dst_ip
                    self._insert_text(self.connections_text,
                        f"{src:25} → {dst:25} {conn.protocol:4} [{conn.state.value}]\n"
                    )
            else:
                self._insert_text(self.connections_text, "No active connections.\n")
                
        except Exception as e:
            self.log_message(f"Error refreshing monitoring: {e}")



if __name__ == "__main__":
    from auth_system import login
    
    while True:
        role = login()
        if role is None:
            break
        
        root = tk.Tk()
        gui = EnhancedFirewallGUI(root, role)
        
        try:
            root.mainloop()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
            break

