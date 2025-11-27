"""
Stateful Inspection Module
Track connection states and perform stateful packet inspection
"""

import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timedelta
import threading

class ConnectionState(Enum):
    NEW = "NEW"
    ESTABLISHED = "ESTABLISHED"
    RELATED = "RELATED"
    INVALID = "INVALID"
    UNTRACKED = "UNTRACKED"

class TCPState(Enum):
    SYN_SENT = "SYN_SENT"
    SYN_RECEIVED = "SYN_RECEIVED"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT_1 = "FIN_WAIT_1"
    FIN_WAIT_2 = "FIN_WAIT_2"
    CLOSE_WAIT = "CLOSE_WAIT"
    CLOSING = "CLOSING"
    LAST_ACK = "LAST_ACK"
    TIME_WAIT = "TIME_WAIT"
    CLOSED = "CLOSED"

@dataclass
class Connection:
    """Represents a network connection"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    state: ConnectionState
    tcp_state: Optional[TCPState] = None
    first_seen: datetime = None
    last_seen: datetime = None
    packet_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    is_inbound: bool = True
    
    def __post_init__(self):
        if self.first_seen is None:
            self.first_seen = datetime.now()
        if self.last_seen is None:
            self.last_seen = datetime.now()

class StatefulInspector:
    """Stateful packet inspection engine"""
    
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.connections: Dict[str, Connection] = {}
        self.connection_timeout = 300  # 5 minutes
        self.cleanup_interval = 60  # 1 minute
        self.running = False
        self.cleanup_thread = None
        self.last_cleanup_log = datetime.now()
        
        # Start cleanup thread
        self._start_cleanup_thread()
    
    def _start_cleanup_thread(self):
        """Start background thread for connection cleanup"""
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_connections, daemon=True)
        self.cleanup_thread.start()
    
    def _cleanup_connections(self):
        """Clean up expired connections"""
        while self.running:
            try:
                current_time = datetime.now()
                expired_connections = []
                
                for conn_id, connection in self.connections.items():
                    if (current_time - connection.last_seen).seconds > self.connection_timeout:
                        expired_connections.append(conn_id)
                
                # Remove expired connections
                expired_count = 0
                for conn_id in expired_connections:
                    del self.connections[conn_id]
                    expired_count += 1
                
                # Only log summary every 5 minutes or if significant cleanup
                if expired_count > 0:
                    time_since_log = (current_time - self.last_cleanup_log).seconds
                    if expired_count >= 10 or time_since_log >= 300:  # 5 minutes
                        if self.log_callback:
                            self.log_callback(f"🧹 Cleaned {expired_count} expired connection(s)")
                        self.last_cleanup_log = current_time
                
                time.sleep(self.cleanup_interval)
            except Exception as e:
                if self.log_callback:
                    self.log_callback(f"❌ Cleanup error: {e}")
                time.sleep(self.cleanup_interval)
    
    def _get_connection_id(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> str:
        """Generate unique connection ID"""
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
    
    def _get_reverse_connection_id(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> str:
        """Get reverse connection ID for bidirectional tracking"""
        return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
    
    def inspect_packet(self, packet_info) -> Tuple[bool, ConnectionState, Optional[Connection]]:
        """
        Perform stateful inspection on packet
        Returns: (should_allow, connection_state, connection_object)
        """
        if not hasattr(packet_info, 'src_ip'):
            return True, ConnectionState.UNTRACKED, None
        
        # Only track TCP and UDP connections
        if packet_info.protocol not in ['TCP', 'UDP']:
            return True, ConnectionState.UNTRACKED, None
        
        conn_id = self._get_connection_id(
            packet_info.src_ip, packet_info.dst_ip,
            packet_info.src_port, packet_info.dst_port,
            packet_info.protocol
        )
        
        # Check for reverse connection
        reverse_conn_id = self._get_reverse_connection_id(
            packet_info.src_ip, packet_info.dst_ip,
            packet_info.src_port, packet_info.dst_port,
            packet_info.protocol
        )
        
        connection = None
        connection_state = ConnectionState.NEW
        
        # Check if connection exists
        if conn_id in self.connections:
            connection = self.connections[conn_id]
            connection_state = connection.state
        elif reverse_conn_id in self.connections:
            connection = self.connections[reverse_conn_id]
            connection_state = ConnectionState.ESTABLISHED
        
        # Update or create connection
        if connection:
            self._update_connection(connection, packet_info)
        else:
            connection = self._create_connection(packet_info)
            self.connections[conn_id] = connection
            connection_state = ConnectionState.NEW
        
        # Determine state based on protocol
        if packet_info.protocol == 'TCP':
            connection_state = self._determine_tcp_state(connection, packet_info)
        elif packet_info.protocol == 'UDP':
            connection_state = self._determine_udp_state(connection, packet_info)
        
        # Update connection state
        connection.state = connection_state
        
        # For stateful inspection, allow established connections and new outbound connections
        should_allow = True
        if packet_info.protocol == 'TCP':
            should_allow = (connection_state in [ConnectionState.NEW, ConnectionState.ESTABLISHED] and 
                          packet_info.direction == "OUT") or connection_state == ConnectionState.ESTABLISHED
        elif packet_info.protocol == 'UDP':
            should_allow = packet_info.direction == "OUT" or connection_state == ConnectionState.ESTABLISHED
        
        return should_allow, connection_state, connection
    
    def _create_connection(self, packet_info) -> Connection:
        """Create new connection object"""
        return Connection(
            src_ip=packet_info.src_ip,
            dst_ip=packet_info.dst_ip,
            src_port=packet_info.src_port,
            dst_port=packet_info.dst_port,
            protocol=packet_info.protocol,
            state=ConnectionState.NEW,
            is_inbound=packet_info.direction == "IN"
        )
    
    def _update_connection(self, connection: Connection, packet_info):
        """Update existing connection"""
        connection.last_seen = datetime.now()
        connection.packet_count += 1
        
        if packet_info.direction == "IN":
            connection.bytes_received += packet_info.packet_size
        else:
            connection.bytes_sent += packet_info.packet_size
    
    def _determine_tcp_state(self, connection: Connection, packet_info) -> ConnectionState:
        """Determine TCP connection state based on flags"""
        if not hasattr(packet_info, 'tcp_flags') or not packet_info.tcp_flags:
            return connection.state
        
        flags = packet_info.tcp_flags.split(',')
        
        # TCP state machine
        if 'SYN' in flags and 'ACK' not in flags:
            if connection.state == ConnectionState.NEW:
                return ConnectionState.ESTABLISHED
        elif 'SYN' in flags and 'ACK' in flags:
            return ConnectionState.ESTABLISHED
        elif 'FIN' in flags or 'RST' in flags:
            return ConnectionState.INVALID
        elif 'ACK' in flags and connection.state == ConnectionState.ESTABLISHED:
            return ConnectionState.ESTABLISHED
        
        return connection.state
    
    def _determine_udp_state(self, connection: Connection, packet_info) -> ConnectionState:
        """Determine UDP connection state"""
        if connection.state == ConnectionState.NEW:
            return ConnectionState.ESTABLISHED
        return ConnectionState.ESTABLISHED
    
    def get_connection(self, conn_id: str) -> Optional[Connection]:
        """Get connection by ID"""
        return self.connections.get(conn_id)
    
    def get_all_connections(self) -> List[Connection]:
        """Get all active connections"""
        return list(self.connections.values())
    
    def get_connections_by_state(self, state: ConnectionState) -> List[Connection]:
        """Get connections by state"""
        return [conn for conn in self.connections.values() if conn.state == state]
    
    def get_connections_by_ip(self, ip: str) -> List[Connection]:
        """Get connections involving specific IP"""
        return [conn for conn in self.connections.values() 
                if conn.src_ip == ip or conn.dst_ip == ip]
    
    def close_connection(self, conn_id: str) -> bool:
        """Manually close a connection"""
        if conn_id in self.connections:
            del self.connections[conn_id]
            return True
        return False
    
    def get_connection_statistics(self) -> Dict[str, any]:
        """Get connection statistics"""
        total_connections = len(self.connections)
        state_counts = {}
        
        for state in ConnectionState:
            state_counts[state.value] = len(self.get_connections_by_state(state))
        
        # Calculate average connection duration
        total_duration = 0
        for conn in self.connections.values():
            duration = (datetime.now() - conn.first_seen).total_seconds()
            total_duration += duration
        
        avg_duration = total_duration / total_connections if total_connections > 0 else 0
        
        return {
            'total_connections': total_connections,
            'state_counts': state_counts,
            'average_duration_seconds': round(avg_duration, 2),
            'oldest_connection': min([conn.first_seen for conn in self.connections.values()]) if self.connections else None,
            'newest_connection': max([conn.first_seen for conn in self.connections.values()]) if self.connections else None
        }
    
    def stop(self):
        """Stop the stateful inspector"""
        self.running = False
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=5)