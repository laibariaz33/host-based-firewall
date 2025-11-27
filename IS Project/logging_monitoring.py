"""
Logging & Monitoring Module
Comprehensive logging and monitoring system for firewall events
"""

import logging
import logging.handlers
import json
import os
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import csv
import psutil

# Log levels
class LogLevel:
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

@dataclass
class FirewallEvent:
    """Represents a firewall event"""
    timestamp: datetime
    event_type: str
    level: str
    message: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None
    action: Optional[str] = None
    rule_id: Optional[str] = None
    connection_id: Optional[str] = None
    packet_size: Optional[int] = None
    additional_data: Optional[Dict[str, Any]] = None

class FirewallLogger:
    """Enhanced logging system for firewall events"""

    LEVEL_PRIORITY = {
        LogLevel.DEBUG: 10,
        LogLevel.INFO: 20,
        LogLevel.WARNING: 30,
        LogLevel.ERROR: 40,
        LogLevel.CRITICAL: 50,
    }
    
    def __init__(
        self, 
        log_dir: str = "logs", 
        max_file_size: int = 10*1024*1024, 
        max_files: int = 5,
        min_level: str = LogLevel.INFO
    ):
        self.log_dir = log_dir
        self.max_file_size = max_file_size
        self.max_files = max_files
        self.loggers = {}
        self.event_queue = deque(maxlen=10000)
        self.stats = {
            'total_events': 0,
            'events_by_level': defaultdict(int),
            'events_by_type': defaultdict(int),
            'blocked_packets': 0,
            'allowed_packets': 0
        }
        self.min_level = self._normalize_level(min_level)
        # Create log directory
        os.makedirs(log_dir, exist_ok=True)
        
        # Setup loggers
        self._setup_loggers()
        
        # Start background thread for log processing
        self.running = True
        self.log_thread = threading.Thread(target=self._process_logs, daemon=True)
        self.log_thread.start()
    
    def _setup_loggers(self):
        """Setup different loggers for different event types"""
        self.loggers['firewall'] = self._create_logger('firewall', 'firewall.log')
        self.loggers['security'] = self._create_logger('security', 'security.log')
        self.loggers['performance'] = self._create_logger('performance', 'performance.log')
        self.loggers['error'] = self._create_logger('error', 'error.log')
    
    def _create_logger(self, name: str, filename: str) -> logging.Logger:
        """Create a logger with file handler"""
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        file_path = os.path.join(self.log_dir, filename)
        handler = logging.handlers.RotatingFileHandler(
            file_path, maxBytes=self.max_file_size, backupCount=self.max_files
        )
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger
    
    # --- General log writing ---
    def write_log(self, message: str, level: str = LogLevel.INFO):
        """Directly write a log message"""
        event = FirewallEvent(
            timestamp=datetime.now(),
            event_type="GENERAL",
            level=level,
            message=message
        )
        self.log_event(event)

    # --- Log events ---
    def log_event(self, event: FirewallEvent):
        """Log a firewall event"""
        self.event_queue.append(event)
        self._update_stats(event)

    def log_packet_blocked(self, src_ip: str, dst_ip: str, protocol: str, 
                      reason: str = "Rule match", rule_id: str = None):
        """Log a blocked packet"""
        if not reason:
            reason = "Rule match"
        event = FirewallEvent(
            timestamp=datetime.now(),
            event_type="PACKET_BLOCKED",
            level=LogLevel.WARNING,
            message=f"Packet blocked: {src_ip} -> {dst_ip} ({protocol}) - {reason}",
            source_ip=src_ip,
            dest_ip=dst_ip,
            protocol=protocol,
            action="BLOCKED",
            rule_id=rule_id
        )
        self.log_event(event)

    def log_packet_allowed(self, src_ip, dst_ip, protocol, rule_id=None, reason=None):
        """Log allowed packet"""
        msg = f"Packet allowed: {src_ip} -> {dst_ip} ({protocol})"
        if reason:
            msg += f" - reason={reason}"
        event = FirewallEvent(
            timestamp=datetime.now(),
            event_type="PACKET_ALLOWED",
            level=LogLevel.INFO,
            message=msg,
            source_ip=src_ip,
            dest_ip=dst_ip,
            protocol=protocol,
            action="ALLOWED",
            rule_id=rule_id
        )
        self.log_event(event)


    def log_connection_established(self, src_ip: str, dst_ip: str, protocol: str, 
                                 src_port: int, dst_port: int, connection_id: str):
        event = FirewallEvent(
            timestamp=datetime.now(),
            event_type="CONNECTION_ESTABLISHED",
            level=LogLevel.INFO,
            message=f"Connection established: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol})",
            source_ip=src_ip,
            dest_ip=dst_ip,
            protocol=protocol,
            port=dst_port,
            connection_id=connection_id
        )
        self.log_event(event)
    
    def log_connection_closed(self, connection_id: str, duration: float):
        event = FirewallEvent(
            timestamp=datetime.now(),
            event_type="CONNECTION_CLOSED",
            level=LogLevel.INFO,
            message=f"Connection closed: {connection_id} (duration: {duration:.2f}s)",
            connection_id=connection_id,
            additional_data={'duration': duration}
        )
        self.log_event(event)
    
    def log_rule_added(self, rule_name: str, rule_id: str):
        event = FirewallEvent(
            timestamp=datetime.now(),
            event_type="RULE_ADDED",
            level=LogLevel.INFO,
            message=f"Rule added: {rule_name}",
            rule_id=rule_id
        )
        self.log_event(event)
    
    def log_rule_removed(self, rule_name: str, rule_id: str):
        event = FirewallEvent(
            timestamp=datetime.now(),
            event_type="RULE_REMOVED",
            level=LogLevel.INFO,
            message=f"Rule removed: {rule_name}",
            rule_id=rule_id
        )
        self.log_event(event)
    
    def log_security_alert(self, message: str, severity: str = "HIGH", 
                          src_ip: str = None, additional_data: Dict = None):
        event = FirewallEvent(
            timestamp=datetime.now(),
            event_type="SECURITY_ALERT",
            level=LogLevel.CRITICAL if severity == "CRITICAL" else LogLevel.WARNING,
            message=f"SECURITY ALERT: {message}",
            source_ip=src_ip,
            additional_data=additional_data
        )
        self.log_event(event)
    
    def log_performance_metric(self, metric_name: str, value: float, unit: str = ""):
        event = FirewallEvent(
            timestamp=datetime.now(),
            event_type="PERFORMANCE_METRIC",
            level=LogLevel.INFO,
            message=f"Performance: {metric_name} = {value} {unit}",
            additional_data={'metric_name': metric_name, 'value': value, 'unit': unit}
        )
        self.log_event(event)
    
    # --- Background processing ---
    def _process_logs(self):
        while self.running:
            try:
                if self.event_queue:
                    event = self.event_queue.popleft()
                    self._write_event(event)
                else:
                    time.sleep(0.1)
            except Exception as e:
                print(f"Log processing error: {e}")
                time.sleep(1)
    
    def _write_event(self, event: FirewallEvent):
        try:
            if not self._should_log(event.level):
                return
            logger_name = 'firewall'
            if event.event_type == "SECURITY_ALERT":
                logger_name = 'security'
            elif event.event_type == "PERFORMANCE_METRIC":
                logger_name = 'performance'
            elif event.level in [LogLevel.ERROR, LogLevel.CRITICAL]:
                logger_name = 'error'
            
            logger = self.loggers[logger_name]
            log_message = self._format_log_message(event)
            
            if event.level == LogLevel.DEBUG:
                logger.debug(log_message)
            elif event.level == LogLevel.INFO:
                logger.info(log_message)
            elif event.level == LogLevel.WARNING:
                logger.warning(log_message)
            elif event.level == LogLevel.ERROR:
                logger.error(log_message)
            elif event.level == LogLevel.CRITICAL:
                logger.critical(log_message)
        except Exception as e:
            print(f"Error writing log: {e}")
    
    def _normalize_level(self, level: str) -> str:
        level = (level or LogLevel.INFO).upper()
        return level if level in self.LEVEL_PRIORITY else LogLevel.INFO

    def _should_log(self, level: str) -> bool:
        event_priority = self.LEVEL_PRIORITY.get(level, self.LEVEL_PRIORITY[LogLevel.INFO])
        min_priority = self.LEVEL_PRIORITY.get(self.min_level, self.LEVEL_PRIORITY[LogLevel.INFO])
        return event_priority >= min_priority

    def set_log_level(self, level: str):
        """Update minimum log level at runtime"""
        normalized = self._normalize_level(level)
        self.min_level = normalized

    def get_log_level(self) -> str:
        """Return current minimum log level"""
        return self.min_level

    def _format_log_message(self, event: FirewallEvent) -> str:
        parts = [event.message]
        if event.source_ip: parts.append(f"src={event.source_ip}")
        if event.dest_ip: parts.append(f"dst={event.dest_ip}")
        if event.protocol: parts.append(f"proto={event.protocol}")
        if event.port: parts.append(f"port={event.port}")
        if event.rule_id: parts.append(f"rule={event.rule_id}")
        if event.connection_id: parts.append(f"conn={event.connection_id}")
        if event.packet_size: parts.append(f"size={event.packet_size}")
        return " | ".join(parts)
    
    def _update_stats(self, event: FirewallEvent):
        self.stats['total_events'] += 1
        self.stats['events_by_level'][event.level] += 1
        self.stats['events_by_type'][event.event_type] += 1
        if event.action == "BLOCKED":
            self.stats['blocked_packets'] += 1
        elif event.action == "ALLOWED":
            self.stats['allowed_packets'] += 1
    
    def get_recent_events(self, count: int = 100) -> List[FirewallEvent]:
        """Get recent events"""
        return list(self.event_queue)[-count:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get logging statistics"""
        return dict(self.stats)
    
    def export_events_csv(self, filename: str, hours: int = 24):
        """Export events to CSV file"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'timestamp', 'event_type', 'level', 'message', 'source_ip',
                    'dest_ip', 'protocol', 'port', 'action', 'rule_id', 'connection_id'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                # Read from log files
                for logger_name, logger in self.loggers.items():
                    log_file = os.path.join(self.log_dir, f"{logger_name}.log")
                    if os.path.exists(log_file):
                        with open(log_file, 'r', encoding='utf-8') as f:
                            for line in f:
                                # Parse log line and write to CSV
                                # This is a simplified version - in practice, you'd need proper log parsing
                                pass
        except Exception as e:
            print(f"Error exporting events: {e}")
    
    def stop(self):
        """Stop the logger"""
        self.running = False
        if self.log_thread and self.log_thread.is_alive():
            self.log_thread.join(timeout=5)

class FirewallMonitor:
    """Real-time monitoring system"""
    
    def __init__(self, logger: FirewallLogger):
        self.logger = logger
        self.monitoring = False
        self.monitor_thread = None
        self.metrics = {
            'packets_per_second': 0,
            'connections_per_second': 0,
            'blocked_per_second': 0,
            'cpu_usage': 0,
            'memory_usage': 0,
            'active_connections': 0
        }
        self.callbacks = []
    
    def start_monitoring(self, interval: float = 1.0):
        """Start monitoring with specified interval"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop, args=(interval,), daemon=True
        )
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
    
    def _monitor_loop(self, interval: float):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                self._collect_metrics()
                self._notify_callbacks()
                time.sleep(interval)
            except Exception as e:
                self.logger.log_security_alert(f"Monitoring error: {e}")
                time.sleep(interval)
    
    def _collect_metrics(self):
        """Collect system and firewall metrics"""
        # This is a simplified version - in practice, you'd collect real metrics
        import psutil
        
        # System metrics
        self.metrics['cpu_usage'] = psutil.cpu_percent()
        self.metrics['memory_usage'] = psutil.virtual_memory().percent
        
        # Firewall metrics (simplified)
        stats = self.logger.get_statistics()
        self.metrics['packets_per_second'] = stats.get('total_events', 0)
        self.metrics['blocked_per_second'] = stats.get('blocked_packets', 0)
    
    def add_callback(self, callback: Callable):
        """Add monitoring callback"""
        self.callbacks.append(callback)
    
    def _notify_callbacks(self):
        """Notify all callbacks with current metrics"""
        for callback in self.callbacks:
            try:
                callback(self.metrics.copy())
            except Exception as e:
                print(f"Callback error: {e}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics"""
        return self.metrics.copy()
    
    def get_health_status(self) -> str:
        """Get overall health status"""
        if self.metrics['cpu_usage'] > 90:
            return "CRITICAL"
        elif self.metrics['cpu_usage'] > 70:
            return "WARNING"
        elif self.metrics['memory_usage'] > 90:
            return "CRITICAL"
        elif self.metrics['memory_usage'] > 70:
            return "WARNING"
        else:
            return "HEALTHY"
