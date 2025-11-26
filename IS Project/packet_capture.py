"""
Packet Capture Module
Enhanced packet capture with detailed parsing and metadata extraction
"""

import time
from datetime import datetime
from typing import Dict, Any, Optional
from dataclasses import dataclass
from pydivert import WinDivert, Packet


@dataclass
class PacketInfo:
    """Structured packet information"""
    timestamp: datetime
    direction: str  # 'IN' or 'OUT'
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_size: int
    tcp_flags: Optional[str] = None
    payload_preview: Optional[bytes] = None
    raw_packet: Optional[bytes] = None


class PacketCapture:
    """Enhanced packet capture with detailed parsing"""

    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.running = False
        self.captured_packets = []
        self.stats = {
            'total_packets': 0,
            'inbound_packets': 0,
            'outbound_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0
        }

    def start_capture(self, filter_expression="true", packet_processor=None):
        """Start packet capture with optional filter"""
        self.running = True
        if self.log_callback:
            self.log_callback("✅ Packet capture started...")

        self.packet_processor = packet_processor

        try:
            with WinDivert(filter_expression) as w:
                for packet in w:
                    if not self.running:
                        break

                    packet_info = self._parse_packet(packet)
                    self._update_stats(packet_info)
                    self.captured_packets.append(packet_info)

                    # Pass through processor (firewall rules)
                    if self.packet_processor:
                        try:
                            allow = self.packet_processor(packet_info)
                            if allow:
                                w.send(packet)
                            else:
                                if self.log_callback:
                                    self.log_callback(f"❌ Blocked: {packet_info.src_ip} → {packet_info.dst_ip}")
                        except Exception as e:
                            if self.log_callback:
                                self.log_callback(f"Processing error: {e}")
                            w.send(packet)  # allow by default
                    else:
                        w.send(packet)  # allow all

                    if self.log_callback:
                        self._log_packet(packet_info)

        except KeyboardInterrupt:
            self.stop_capture()
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"⚠️ Capture error: {e}")
                self.log_callback("💡 Try running as Administrator if permission denied.")

    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        if self.log_callback:
            self.log_callback("🛑 Packet capture stopped.")

    def _parse_packet(self, packet: Packet) -> PacketInfo:
        """Parse packet and extract detailed information"""
        timestamp = datetime.now()
        direction = "IN" if packet.is_inbound else "OUT"

        src_ip = packet.src_addr
        dst_ip = packet.dst_addr

        # --- robust port extraction ---
        src_port = 0
        dst_port = 0
        try:
            # pydivert sometimes gives protocol as int or tuple
            proto_val = packet.protocol[0] if isinstance(packet.protocol, tuple) else packet.protocol

            # When parsed TCP/UDP layer objects exist, use them
            if hasattr(packet, 'tcp') and packet.tcp is not None:
                # pydivert's tcp.src_port might be int or attribute-like
                try:
                    src_port = int(packet.tcp.src_port)
                    dst_port = int(packet.tcp.dst_port)
                except Exception:
                    # fallback if attribute names differ
                    src_port = int(getattr(packet.tcp, 'sport', 0) or 0)
                    dst_port = int(getattr(packet.tcp, 'dport', 0) or 0)

            elif hasattr(packet, 'udp') and packet.udp is not None:
                try:
                    src_port = int(packet.udp.src_port)
                    dst_port = int(packet.udp.dst_port)
                except Exception:
                    src_port = int(getattr(packet.udp, 'sport', 0) or 0)
                    dst_port = int(getattr(packet.udp, 'dport', 0) or 0)

            # final fallback: sometimes packet.payload contains L4 header at offset; avoid parsing here
        except Exception:
            src_port = src_port or 0
            dst_port = dst_port or 0


        # Protocol mapping
        protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH'}
        if isinstance(packet.protocol, tuple):
         protocol_num = packet.protocol[0]
        else:
            protocol_num = packet.protocol
        protocol_name = protocol_map.get(protocol_num, f'Protocol-{protocol_num}')


        tcp_flags = None
        try:
            if packet.protocol == 6 and packet.tcp:
                flags = []
                if packet.tcp.fin: flags.append('FIN')
                if packet.tcp.syn: flags.append('SYN')
                if packet.tcp.rst: flags.append('RST')
                if packet.tcp.psh: flags.append('PSH')
                if packet.tcp.ack: flags.append('ACK')
                if packet.tcp.urg: flags.append('URG')
                tcp_flags = ','.join(flags) if flags else None
        except Exception:
            pass

        payload_preview = packet.payload[:16] if packet.payload else None

        return PacketInfo(
            timestamp=timestamp,
            direction=direction,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol_name,
            packet_size=len(packet.raw),
            tcp_flags=tcp_flags,
            payload_preview=payload_preview,
            raw_packet=packet.raw
        )

    def _update_stats(self, packet_info: PacketInfo):
        """Update capture statistics"""
        self.stats['total_packets'] += 1
        if packet_info.direction == 'IN':
            self.stats['inbound_packets'] += 1
        else:
            self.stats['outbound_packets'] += 1

        if packet_info.protocol == 'TCP':
            self.stats['tcp_packets'] += 1
        elif packet_info.protocol == 'UDP':
            self.stats['udp_packets'] += 1
        elif packet_info.protocol == 'ICMP':
            self.stats['icmp_packets'] += 1

    def _log_packet(self, packet_info: PacketInfo):
        """Log packet information"""
        port_info = f":{packet_info.src_port} → :{packet_info.dst_port}" if packet_info.src_port and packet_info.dst_port else ""
        tcp_info = f" [{packet_info.tcp_flags}]" if packet_info.tcp_flags else ""

        msg = (f"[{packet_info.timestamp.strftime('%H:%M:%S')}] "
               f"{packet_info.direction} {packet_info.src_ip}{port_info} → "
               f"{packet_info.dst_ip} | {packet_info.protocol} "
               f"({packet_info.packet_size} bytes){tcp_info}")

        if self.log_callback:
            self.log_callback(msg)

    def get_stats(self) -> Dict[str, Any]:
        """Get capture statistics"""
        return self.stats.copy()

    def get_recent_packets(self, count: int = 100) -> list:
        """Get recent captured packets"""
        return self.captured_packets[-count:]

    def clear_captured_packets(self):
        """Clear captured packets buffer"""
        self.captured_packets.clear()
        self.stats = {k: 0 for k in self.stats}
