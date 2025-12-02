"""
Logging & Monitoring Module
Comprehensive logging and monitoring system for firewall events
Updated: accurate per-interval monitoring + safer logging/statistics handling
"""

import logging
import logging.handlers
import json
import os
import threading
import time
import re
import csv
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
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
        max_file_size: int = 10 * 1024 * 1024,
        max_files: int = 5,
        min_level: str = LogLevel.INFO,
        history_size: int = 20000,
    ):
        self.log_dir = log_dir
        self.max_file_size = max_file_size
        self.max_files = max_files
        self.loggers = {}
        self.event_queue = deque()
        self.queue_lock = threading.Lock()
        self.event_history = deque(maxlen=history_size)  # recent events kept in memory
        self.history_lock = threading.Lock()

        # Stats protected by lock
        self.stats = {
            "total_events": 0,
            "events_by_level": defaultdict(int),
            "events_by_type": defaultdict(int),
            "blocked_packets": 0,
            "allowed_packets": 0,
        }
        self.stats_lock = threading.Lock()

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
        self.loggers["firewall"] = self._create_logger("firewall", "firewall.log")
        self.loggers["security"] = self._create_logger("security", "security.log")
        self.loggers["performance"] = self._create_logger("performance", "performance.log")
        self.loggers["error"] = self._create_logger("error", "error.log")

    def _create_logger(self, name: str, filename: str) -> logging.Logger:
        """Create a logger with file handler"""
        logger = logging.getLogger(f"firewall_module.{name}")
        logger.setLevel(logging.DEBUG)
        # Remove existing handlers to avoid duplicate logs in interactive sessions
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
        file_path = os.path.join(self.log_dir, filename)
        handler = logging.handlers.RotatingFileHandler(
            file_path, maxBytes=self.max_file_size, backupCount=self.max_files
        )
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        # Also avoid propagation to root logger
        logger.propagate = False
        return logger

    # --- General log writing ---
    def write_log(self, message: str, level: str = LogLevel.INFO):
        """Directly write a log message"""
        event = FirewallEvent(timestamp=datetime.now(), event_type="GENERAL", level=level, message=message)
        self.log_event(event)

    # --- Log events ---
    def log_event(self, event: FirewallEvent):
        """Enqueue a firewall event and update stats"""
        with self.queue_lock:
            self.event_queue.append(event)
        self._update_stats(event)

    def log_packet_blocked(self, src_ip: str, dst_ip: str, protocol: str, reason: str = "Rule match", rule_id: str = None):
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
            rule_id=rule_id,
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
            rule_id=rule_id,
        )
        self.log_event(event)

    def log_connection_established(self, src_ip: str, dst_ip: str, protocol: str, src_port: int, dst_port: int, connection_id: str):
        event = FirewallEvent(
            timestamp=datetime.now(),
            event_type="CONNECTION_ESTABLISHED",
            level=LogLevel.INFO,
            message=f"Connection established: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol})",
            source_ip=src_ip,
            dest_ip=dst_ip,
            protocol=protocol,
            port=dst_port,
            connection_id=connection_id,
        )
        self.log_event(event)

    def log_connection_closed(self, connection_id: str, duration: float):
        event = FirewallEvent(
            timestamp=datetime.now(),
            event_type="CONNECTION_CLOSED",
            level=LogLevel.INFO,
            message=f"Connection closed: {connection_id} (duration: {duration:.2f}s)",
            connection_id=connection_id,
            additional_data={"duration": duration},
        )
        self.log_event(event)

    def log_rule_added(self, rule_name: str, rule_id: str):
        event = FirewallEvent(
            timestamp=datetime.now(),
            event_type="RULE_ADDED",
            level=LogLevel.INFO,
            message=f"Rule added: {rule_name}",
            rule_id=rule_id,
        )
        self.log_event(event)

    def log_rule_removed(self, rule_name: str, rule_id: str):
        event = FirewallEvent(
            timestamp=datetime.now(),
            event_type="RULE_REMOVED",
            level=LogLevel.INFO,
            message=f"Rule removed: {rule_name}",
            rule_id=rule_id,
        )
        self.log_event(event)

    def log_security_alert(self, message: str, severity: str = "HIGH", src_ip: str = None, additional_data: Dict = None):
        event = FirewallEvent(
            timestamp=datetime.now(),
            event_type="SECURITY_ALERT",
            level=LogLevel.CRITICAL if severity == "CRITICAL" else LogLevel.WARNING,
            message=f"SECURITY ALERT: {message}",
            source_ip=src_ip,
            additional_data=additional_data,
        )
        self.log_event(event)

    def log_performance_metric(self, metric_name: str, value: float, unit: str = ""):
        event = FirewallEvent(
            timestamp=datetime.now(),
            event_type="PERFORMANCE_METRIC",
            level=LogLevel.INFO,
            message=f"Performance: {metric_name} = {value} {unit}",
            additional_data={"metric_name": metric_name, "value": value, "unit": unit},
        )
        self.log_event(event)

    # --- Background processing ---
    def _process_logs(self):
        while self.running:
            try:
                event = None
                with self.queue_lock:
                    if self.event_queue:
                        event = self.event_queue.popleft()
                if event is None:
                    # nothing to do
                    time.sleep(0.1)
                    continue
                self._write_event(event)
                # append to in-memory history for quick exports / recent view
                with self.history_lock:
                    self.event_history.append(event)
            except Exception as e:
                # we avoid crashing the thread; print to stderr minimally
                print(f"[FirewallLogger] Log processing error: {e}")
                time.sleep(1)

    def _write_event(self, event: FirewallEvent):
        try:
            if not self._should_log(event.level):
                return
            logger_name = "firewall"
            if event.event_type == "SECURITY_ALERT":
                logger_name = "security"
            elif event.event_type == "PERFORMANCE_METRIC":
                logger_name = "performance"
            elif event.level in [LogLevel.ERROR, LogLevel.CRITICAL]:
                logger_name = "error"

            logger = self.loggers.get(logger_name) or self.loggers["firewall"]
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
            print(f"[FirewallLogger] Error writing log: {e}")

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
        if event.source_ip:
            parts.append(f"src={event.source_ip}")
        if event.dest_ip:
            parts.append(f"dst={event.dest_ip}")
        if event.protocol:
            parts.append(f"proto={event.protocol}")
        if event.port:
            parts.append(f"port={event.port}")
        if event.rule_id:
            parts.append(f"rule={event.rule_id}")
        if event.connection_id:
            parts.append(f"conn={event.connection_id}")
        if event.packet_size:
            parts.append(f"size={event.packet_size}")
        # additional_data included as JSON for easier parsing if present
        if event.additional_data:
            try:
                parts.append("data=" + json.dumps(event.additional_data, default=str))
            except Exception:
                parts.append(f"data={event.additional_data}")
        return " | ".join(parts)

    def _update_stats(self, event: FirewallEvent):
        with self.stats_lock:
            self.stats["total_events"] += 1
            self.stats["events_by_level"][event.level] += 1
            self.stats["events_by_type"][event.event_type] += 1
            if event.action == "BLOCKED":
                self.stats["blocked_packets"] += 1
            elif event.action == "ALLOWED":
                self.stats["allowed_packets"] += 1

    def get_recent_events(self, count: int = 100) -> List[FirewallEvent]:
        """Get recent events (from in-memory history)"""
        with self.history_lock:
            return list(self.event_history)[-count:]

    def get_statistics(self) -> Dict[str, Any]:
        """Get logging statistics (thread-safe snapshot)"""
        with self.stats_lock:
            # Convert defaultdicts to normal dicts for serialization/readability
            snapshot = {
                "total_events": self.stats["total_events"],
                "events_by_level": dict(self.stats["events_by_level"]),
                "events_by_type": dict(self.stats["events_by_type"]),
                "blocked_packets": self.stats["blocked_packets"],
                "allowed_packets": self.stats["allowed_packets"],
            }
        return snapshot

    def export_events_csv(self, filename: str, hours: int = 24):
        """Export events from in-memory history to CSV file within the given timeframe"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            # Use fields that map to FirewallEvent attributes
            fieldnames = [
                "timestamp",
                "event_type",
                "level",
                "message",
                "source_ip",
                "dest_ip",
                "protocol",
                "port",
                "action",
                "rule_id",
                "connection_id",
                "packet_size",
                "additional_data",
            ]
            with open(filename, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                with self.history_lock:
                    for ev in self.event_history:
                        if ev.timestamp < cutoff_time:
                            continue
                        writer.writerow(
                            {
                                "timestamp": ev.timestamp.isoformat(),
                                "event_type": ev.event_type,
                                "level": ev.level,
                                "message": ev.message,
                                "source_ip": ev.source_ip,
                                "dest_ip": ev.dest_ip,
                                "protocol": ev.protocol,
                                "port": ev.port,
                                "action": ev.action,
                                "rule_id": ev.rule_id,
                                "connection_id": ev.connection_id,
                                "packet_size": ev.packet_size,
                                "additional_data": json.dumps(ev.additional_data, default=str) if ev.additional_data else "",
                            }
                        )
        except Exception as e:
            print(f"[FirewallLogger] Error exporting events to CSV: {e}")

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

        # metrics are per-interval (not cumulative)
        self.metrics = {
            "packets_per_second": 0.0,
            "connections_per_second": 0.0,
            "blocked_per_second": 0.0,
            "allowed_per_second": 0.0,
            "cpu_usage": 0.0,
            "memory_usage": 0.0,
            "active_connections": 0,
        }

        # callbacks to push metrics to UI or other systems
        self.callbacks: List[Callable[[Dict[str, Any]], None]] = []

        # previous cumulative counters (from logger.stats snapshot)
        self._prev_total_events = 0
        self._prev_blocked = 0
        self._prev_allowed = 0
        self._prev_active_connections = 0.0

        # lock for metric updates
        self._metrics_lock = threading.Lock()

    def start_monitoring(self, interval: float = 1.0):
        """Start monitoring with specified interval (seconds)"""
        if self.monitoring:
            return
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, args=(interval,), daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)

    def _monitor_loop(self, interval: float):
        """Main monitoring loop"""
        # Initialize previous counters to current values to avoid spikes on first tick
        stats_snapshot = self.logger.get_statistics()
        self._prev_total_events = stats_snapshot.get("total_events", 0)
        self._prev_blocked = stats_snapshot.get("blocked_packets", 0)
        self._prev_allowed = stats_snapshot.get("allowed_packets", 0)
        # initialize active connections
        try:
            conns = psutil.net_connections(kind="inet")
            active = sum(1 for c in conns if getattr(c, "status", "").upper() == "ESTABLISHED")
            self._prev_active_connections = float(active)
        except Exception:
            self._prev_active_connections = 0.0

        while self.monitoring:
            start_time = time.time()
            try:
                self._collect_metrics(interval)
                self._notify_callbacks()
            except Exception as e:
                # Log an alert but don't crash the monitor loop
                try:
                    self.logger.log_security_alert(f"Monitoring error: {e}")
                except Exception:
                    print(f"[FirewallMonitor] Monitoring error (and failed to log): {e}")
            # sleep accounting for time spent collecting
            elapsed = time.time() - start_time
            to_sleep = max(0.0, interval - elapsed)
            time.sleep(to_sleep)

    def _collect_metrics(self, interval: float):
        """Collect system and firewall metrics and compute per-second rates"""
        # System metrics
        cpu = psutil.cpu_percent(interval=None)  # non-blocking measure
        mem = psutil.virtual_memory().percent

        # Firewall stats snapshot
        stats = self.logger.get_statistics()
        current_total = stats.get("total_events", 0)
        current_blocked = stats.get("blocked_packets", 0)
        current_allowed = stats.get("allowed_packets", 0)

        # Difference in counts since last tick
        delta_events = current_total - self._prev_total_events
        delta_blocked = current_blocked - self._prev_blocked
        delta_allowed = current_allowed - self._prev_allowed

        # Active connections via psutil (count ESTABLISHED)
        try:
            conns = psutil.net_connections(kind="inet")
            active_conn_count = sum(1 for c in conns if getattr(c, "status", "").upper() == "ESTABLISHED")
        except Exception:
            active_conn_count = 0

        # Compute per-second rates (divide by interval; ensure non-negative)
        with self._metrics_lock:
            self.metrics["cpu_usage"] = float(cpu)
            self.metrics["memory_usage"] = float(mem)
            # Use float rates for fractional intervals if needed
            self.metrics["packets_per_second"] = max(0.0, float(delta_events) / max(1e-6, interval))
            self.metrics["blocked_per_second"] = max(0.0, float(delta_blocked) / max(1e-6, interval))
            self.metrics["allowed_per_second"] = max(0.0, float(delta_allowed) / max(1e-6, interval))
            # connections per second approximated by rise in active established connections
            conn_delta = float(active_conn_count) - float(self._prev_active_connections)
            self.metrics["connections_per_second"] = max(0.0, conn_delta / max(1e-6, interval))
            self.metrics["active_connections"] = int(active_conn_count)

        # Update previous counters for next interval
        self._prev_total_events = current_total
        self._prev_blocked = current_blocked
        self._prev_allowed = current_allowed
        self._prev_active_connections = float(active_conn_count)

    def add_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """Add monitoring callback; callback receives a snapshot dict of metrics"""
        self.callbacks.append(callback)

    def _notify_callbacks(self):
        """Notify all callbacks with current metrics (copy to avoid mutation issues)"""
        snapshot = self.get_metrics()
        for callback in list(self.callbacks):
            try:
                callback(snapshot)
            except Exception as e:
                print(f"[FirewallMonitor] Callback error: {e}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics snapshot"""
        with self._metrics_lock:
            return dict(self.metrics)

    def get_health_status(self) -> str:
        """Get overall health status (based on CPU/memory thresholds)"""
        cpu = self.metrics.get("cpu_usage", 0.0)
        mem = self.metrics.get("memory_usage", 0.0)
        if cpu > 90 or mem > 90:
            return "CRITICAL"
        if cpu > 70 or mem > 70:
            return "WARNING"
        return "HEALTHY"
