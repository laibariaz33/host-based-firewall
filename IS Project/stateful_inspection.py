"""
Stateful Inspection Module - FIXED VERSION
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
        self.local_ips = self._get_local_ips()
        
        # Track NEW connections to avoid duplicate logging
        self.logged_new_connections = set()
        
    def _get_local_ips(self) -> set:
        """Get local machine IPs to determine direction"""
        try:
            import socket
            import psutil
            
            local_ips = set()
            
            # Get hostname IPs
            hostname = socket.gethostname()
            try:
                local_ips.add(socket.gethostbyname(hostname))
            except:
                pass
            
            # Get all network interface IPs
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:  # IPv4
                        local_ips.add(addr.address)
            
            # Add localhost
            local_ips.add('127.0.0.1')
            
            if self.log_callback:
                self.log_callback(f"🔍 Local IPs detected: {', '.join(sorted(local_ips))}")
            
            return local_ips
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"⚠️ Could not detect local IPs: {e}")
            return {'127.0.0.1'}
    
    def start(self):
        """Start the stateful inspector"""
        if not self.running:
            self.running = True
            self._start_cleanup_thread()
            if self.log_callback:
                self.log_callback("🔍 Stateful Inspector Started")
    
    def _start_cleanup_thread(self):
        """Start background thread for connection cleanup"""
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            return
            
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_connections, daemon=True)
        self.cleanup_thread.start()
    
    def _cleanup_connections(self):
        """Clean up expired connections"""
        while self.running:
            try:
                current_time = datetime.now()
                expired_connections = []
                
                for conn_id, connection in list(self.connections.items()):
                    if (current_time - connection.last_seen).seconds > self.connection_timeout:
                        expired_connections.append(conn_id)
                
                # Remove expired connections
                expired_count = 0
                for conn_id in expired_connections:
                    if conn_id in self.connections:
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
    
    def _determine_direction(self, packet_info) -> str:
        """
        Determine packet direction based on source IP
        OUT = from local machine to remote
        IN = from remote to local machine
        """
        if packet_info.src_ip in self.local_ips:
            return "OUT"
        elif packet_info.dst_ip in self.local_ips:
            return "IN"
        else:
            # If neither is local, check common patterns
            # Packets from private IPs to public are usually OUT
            if self._is_private_ip(packet_info.src_ip) and not self._is_private_ip(packet_info.dst_ip):
                return "OUT"
            # Default to IN for safety (more restrictive)
            return "IN"
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            parts = [int(p) for p in ip.split('.')]
            
            # 10.0.0.0/8
            if parts[0] == 10:
                return True
            
            # 172.16.0.0/12
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            
            # 192.168.0.0/16
            if parts[0] == 192 and parts[1] == 168:
                return True
            
            # 127.0.0.0/8 (localhost)
            if parts[0] == 127:
                return True
            
            return False
        except:
            return False
    
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
        
        # Ensure ports exist
        if not hasattr(packet_info, 'src_port') or not hasattr(packet_info, 'dst_port'):
            return True, ConnectionState.UNTRACKED, None
        
        if packet_info.src_port is None or packet_info.dst_port is None:
            return True, ConnectionState.UNTRACKED, None
        
        # Determine direction
        direction = self._determine_direction(packet_info)
        
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
        is_new_connection = False
        is_reverse_traffic = False
        
        # Check if connection exists (forward direction)
        if conn_id in self.connections:
            connection = self.connections[conn_id]
            connection_state = connection.state
            
        # Check if this is return traffic (reverse direction)
        elif reverse_conn_id in self.connections:
            connection = self.connections[reverse_conn_id]
            connection_state = ConnectionState.ESTABLISHED
            is_reverse_traffic = True
        
        # Update or create connection
        if connection:
            self._update_connection(connection, packet_info)
        else:
            # New connection
            connection = self._create_connection(packet_info, direction)
            self.connections[conn_id] = connection
            connection_state = ConnectionState.NEW
            is_new_connection = True
        
        # Determine state based on protocol and flags
        if packet_info.protocol == 'TCP':
            connection_state = self._determine_tcp_state(connection, packet_info, is_new_connection)
        elif packet_info.protocol == 'UDP':
            connection_state = self._determine_udp_state(connection, is_new_connection)
        
        # Update connection state
        old_state = connection.state
        connection.state = connection_state
        
        # ✅ LOG STATE TRANSITIONS
        if is_new_connection and conn_id not in self.logged_new_connections:
            if self.log_callback:
                self.log_callback(
                    f"🔵 NEW Connection: {packet_info.src_ip}:{packet_info.src_port} → "
                    f"{packet_info.dst_ip}:{packet_info.dst_port} ({packet_info.protocol}) [{direction}]"
                )
            self.logged_new_connections.add(conn_id)
        elif old_state != connection_state and connection_state == ConnectionState.ESTABLISHED:
            if self.log_callback:
                self.log_callback(
                    f"🟢 ESTABLISHED: {packet_info.src_ip}:{packet_info.src_port} → "
                    f"{packet_info.dst_ip}:{packet_info.dst_port} ({packet_info.protocol})"
                )
        
        # Determine if packet should be allowed
        should_allow = self._should_allow_packet(connection_state, direction, is_reverse_traffic)
        
        return should_allow, connection_state, connection
    
    def _should_allow_packet(self, state: ConnectionState, direction: str, is_reverse: bool) -> bool:
        """
        Determine if packet should be allowed based on state and direction
        
        Rules:
        - NEW + OUT: Allow (user initiated)
        - NEW + IN: Deny (unsolicited inbound)
        - ESTABLISHED: Allow (both directions)
        - RELATED: Allow
        - INVALID: Deny
        """
        if state == ConnectionState.ESTABLISHED:
            return True
        
        if state == ConnectionState.RELATED:
            return True
        
        if state == ConnectionState.NEW:
            # Allow outbound NEW connections (user initiated)
            if direction == "OUT":
                return True
            # Deny inbound NEW connections (unsolicited)
            else:
                return False
        
        if state == ConnectionState.INVALID:
            return False
        
        # Default: allow
        return True
    
    def _create_connection(self, packet_info, direction: str) -> Connection:
        """Create new connection object"""
        return Connection(
            src_ip=packet_info.src_ip,
            dst_ip=packet_info.dst_ip,
            src_port=packet_info.src_port,
            dst_port=packet_info.dst_port,
            protocol=packet_info.protocol,
            state=ConnectionState.NEW,
            is_inbound=(direction == "IN")
        )
    
    def _update_connection(self, connection: Connection, packet_info):
        """Update existing connection"""
        connection.last_seen = datetime.now()
        connection.packet_count += 1
        
        # Update bytes
        packet_size = getattr(packet_info, 'packet_size', 0)
        if packet_size:
            if packet_info.src_ip == connection.src_ip:
                connection.bytes_sent += packet_size
            else:
                connection.bytes_received += packet_size
    
    def _determine_tcp_state(self, connection: Connection, packet_info, is_new: bool) -> ConnectionState:
        """Determine TCP connection state based on flags"""
        if not hasattr(packet_info, 'tcp_flags') or not packet_info.tcp_flags:
            # No flags available, use basic state tracking
            if is_new:
                return ConnectionState.NEW
            return ConnectionState.ESTABLISHED
        
        flags = packet_info.tcp_flags
        if isinstance(flags, str):
            flags = flags.split(',')
        
        # TCP state machine
        # SYN only = NEW connection attempt
        if 'SYN' in flags and 'ACK' not in flags:
            connection.tcp_state = TCPState.SYN_SENT
            return ConnectionState.NEW
        
        # SYN+ACK = Server response (connection being established)
        elif 'SYN' in flags and 'ACK' in flags:
            connection.tcp_state = TCPState.SYN_RECEIVED
            return ConnectionState.ESTABLISHED
        
        # ACK only (after handshake) = Established connection
        elif 'ACK' in flags and 'SYN' not in flags:
            if connection.state == ConnectionState.NEW or connection.tcp_state in [TCPState.SYN_SENT, TCPState.SYN_RECEIVED]:
                connection.tcp_state = TCPState.ESTABLISHED
                return ConnectionState.ESTABLISHED
            else:
                return ConnectionState.ESTABLISHED
        
        # FIN or RST = Connection closing/closed
        elif 'FIN' in flags or 'RST' in flags:
            connection.tcp_state = TCPState.CLOSED
            return ConnectionState.INVALID
        
        # Default: maintain current state or mark as established if we have packets
        if connection.packet_count > 2:
            return ConnectionState.ESTABLISHED
        
        return connection.state if connection.state != ConnectionState.NEW else ConnectionState.ESTABLISHED
    
    def _determine_udp_state(self, connection: Connection, is_new: bool) -> ConnectionState:
        """Determine UDP connection state"""
        # UDP is connectionless, so after first packet we consider it established
        if is_new:
            return ConnectionState.NEW
        
        # After seeing packets in both directions or multiple packets, consider established
        if connection.packet_count >= 1:
            return ConnectionState.ESTABLISHED
        
        return ConnectionState.NEW
    
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
        
        if self.log_callback:
            self.log_callback("🔍 Stateful Inspector Stopped")