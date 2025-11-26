"""
Rule Engine Module
Advanced filtering rules with multiple criteria support, persistence, and hit counter
"""

import ipaddress
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import json
import os

class RuleAction(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    LOG = "LOG"

class RuleDirection(Enum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    BOTH = "BOTH"

class Protocol(Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ANY = "ANY"

@dataclass
class FirewallRule:
    """Firewall rule definition with hit counter"""
    name: str
    action: RuleAction
    direction: RuleDirection
    protocol: Protocol
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    enabled: bool = True
    priority: int = 100
    id: Optional[str] = None
    created_at: datetime = None
    description: str = ""
    hit_count: int = 0  # Track how many times this rule was matched
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
    
    def increment_hit_count(self):
        """Increment the hit counter when rule matches"""
        self.hit_count += 1

class RuleEngine:
    """Advanced rule engine for packet filtering with persistence"""
    
    def __init__(self, log_callback=None, rules_file="firewall_rules.json"):
        self.log_callback = log_callback
        self.rules: List[FirewallRule] = []
        self.rule_counter = 0
        self.default_action = RuleAction.DENY  # Safer default
        self.rules_file = rules_file
        
        # Try to load rules from file first
        if not self.load_rules_from_file():
            # If no saved rules, load defaults
            self._load_default_rules()
            # Save the defaults for next time
            self.save_rules_to_file()
    
    def _load_default_rules(self):
        """Load default firewall rules"""
        default_rules = [
            FirewallRule(
                id="default_deny_private",
                name="Deny Private Network Access",
                action=RuleAction.DENY,
                direction=RuleDirection.OUTBOUND,
                protocol=Protocol.ANY,
                dst_ip="10.0.0.0/8",
                description="Block access to private networks",
                priority=10
            ),
            FirewallRule(
                id="block_rdp",
                name="Block RDP Inbound",
                action=RuleAction.DENY,
                direction=RuleDirection.INBOUND,
                protocol=Protocol.TCP,
                dst_port=3389,
                description="Block remote desktop attacks",
                priority=15
            ),
            FirewallRule(
                id="allow_lan",
                name="Allow LAN traffic",
                action=RuleAction.ALLOW,
                direction=RuleDirection.BOTH,
                protocol=Protocol.ANY,
                src_ip="192.168.0.0/16",
                dst_ip="192.168.0.0/16",
                description="Allow all traffic inside local network",
                priority=20
            ),
            FirewallRule(
                id="default_allow_dns",
                name="Allow DNS Queries",
                action=RuleAction.ALLOW,
                direction=RuleDirection.OUTBOUND,
                protocol=Protocol.UDP,
                dst_port=53,
                description="Allow DNS queries",
                priority=30
            ),
            FirewallRule(
                id="default_allow_http",
                name="Allow HTTP",
                action=RuleAction.ALLOW,
                direction=RuleDirection.OUTBOUND,
                protocol=Protocol.TCP,
                dst_port=80,
                description="Allow HTTP traffic",
                priority=40
            ),
            FirewallRule(
                id="default_allow_https",
                name="Allow HTTPS",
                action=RuleAction.ALLOW,
                direction=RuleDirection.OUTBOUND,
                protocol=Protocol.TCP,
                dst_port=443,
                description="Allow HTTPS traffic",
                priority=45
            ),
            FirewallRule(
                id="default_allow_http_in",
                name="Allow HTTP Inbound",
                action=RuleAction.ALLOW,
                direction=RuleDirection.INBOUND,
                protocol=Protocol.TCP,
                src_port=80,
                description="Allow incoming HTTP responses",
                priority=50
            ),
            FirewallRule(
                id="default_allow_https_in",
                name="Allow HTTPS Inbound",
                action=RuleAction.ALLOW,
                direction=RuleDirection.INBOUND,
                protocol=Protocol.TCP,
                src_port=443,
                description="Allow incoming HTTPS responses",
                priority=55
            ),
            FirewallRule(
                id="allow_vpn_udp",
                name="Allow VPN UDP",
                action=RuleAction.ALLOW,
                direction=RuleDirection.BOTH,
                protocol=Protocol.UDP,
                dst_port=1194,
                description="Allow VPN UDP traffic",
                priority=60
            ),
            FirewallRule(
                id="allow_vpn_tcp",
                name="Allow VPN TCP",
                action=RuleAction.ALLOW,
                direction=RuleDirection.BOTH,
                protocol=Protocol.TCP,
                dst_port=443,
                description="Allow VPN TCP traffic",
                priority=61
            ),
            FirewallRule(
                id="allow_icmp",
                name="Allow ICMP",
                action=RuleAction.ALLOW,
                direction=RuleDirection.BOTH,
                protocol=Protocol.ICMP,
                description="Allow ping requests/replies",
                priority=70
            ),
            FirewallRule(
                id="log_unknown_tcp",
                name="Log Unknown TCP Traffic",
                action=RuleAction.LOG,
                direction=RuleDirection.OUTBOUND,
                protocol=Protocol.TCP,
                description="Log outbound TCP traffic not matching allow rules",
                priority=100
            )
        ]
        
        for rule in default_rules:
            self.add_rule(rule)
    
    def save_rules_to_file(self) -> bool:
        """Save all rules to a JSON file for persistence"""
        try:
            rules_data = []
            for rule in self.rules:
                rule_dict = {
                    'id': rule.id,
                    'name': rule.name,
                    'action': rule.action.value,
                    'direction': rule.direction.value,
                    'protocol': rule.protocol.value,
                    'src_ip': rule.src_ip,
                    'dst_ip': rule.dst_ip,
                    'src_port': rule.src_port,
                    'dst_port': rule.dst_port,
                    'enabled': rule.enabled,
                    'priority': rule.priority,
                    'description': rule.description,
                    'hit_count': rule.hit_count,
                    'created_at': rule.created_at.isoformat() if rule.created_at else None
                }
                rules_data.append(rule_dict)
            
            with open(self.rules_file, 'w') as f:
                json.dump(rules_data, f, indent=2)
            
            if self.log_callback:
                self.log_callback(f"💾 Saved {len(rules_data)} rules to {self.rules_file}")
            return True
            
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"❌ Error saving rules: {e}")
            return False
    
    def load_rules_from_file(self) -> bool:
        """Load rules from JSON file"""
        try:
            if not os.path.exists(self.rules_file):
                return False
            
            with open(self.rules_file, 'r') as f:
                rules_data = json.load(f)
            
            # Clear existing rules
            self.rules.clear()
            
            # Load each rule
            for rule_data in rules_data:
                # Convert string enum values back to enum objects
                rule_data['action'] = RuleAction(rule_data['action'])
                rule_data['direction'] = RuleDirection(rule_data['direction'])
                rule_data['protocol'] = Protocol(rule_data['protocol'])
                
                # Convert created_at string to datetime
                if rule_data.get('created_at'):
                    rule_data['created_at'] = datetime.fromisoformat(rule_data['created_at'])
                
                rule = FirewallRule(**rule_data)
                self.rules.append(rule)
            
            # Sort by priority
            self.rules.sort(key=lambda x: x.priority)
            
            # Update rule counter
            if self.rules:
                max_id = max([int(r.id.split('_')[-1]) for r in self.rules if r.id.startswith('rule_')], default=0)
                self.rule_counter = max_id + 1
            
            if self.log_callback:
                self.log_callback(f"📂 Loaded {len(self.rules)} rules from {self.rules_file}")
            return True
            
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"❌ Error loading rules: {e}")
            return False

    def _normalize_string(self, s: str) -> str:
        """
        Normalize string by removing all whitespace and converting to lowercase.
        This ensures 'Port 80', 'port80', and 'PORT  80' are all treated as identical.
        """
        if s is None:
            return ''
        return ''.join(s.split()).lower()

    def add_rule(self, rule: FirewallRule) -> tuple[bool, bool]:
        """
        Add a new rule to the firewall.
        
        Returns:
            tuple[bool, bool]: (success, is_duplicate)
                - (True, False): Rule added successfully
                - (False, True): Duplicate found, rule rejected (NOT added/updated)
                - (False, False): Validation failed
        """
        try:
            # Normalize the new rule name for comparison
            normalized_new_name = self._normalize_string(rule.name)
            
            # Check if a rule with the same name already exists (case-insensitive, whitespace-insensitive)
            for existing in self.rules:
                normalized_existing_name = self._normalize_string(existing.name)
                
                if normalized_existing_name == normalized_new_name:
                    # Duplicate name found - REJECT it completely
                    if self.log_callback:
                        self.log_callback(
                            f"⚠️ Duplicate rule rejected: A rule with name '{existing.name}' already exists"
                        )
                    return False, True  # Failed due to duplicate name

            # If no duplicates, assign id and add normally
            if not rule.id:
                rule.id = f"rule_{self.rule_counter}"
                self.rule_counter += 1

            if self._validate_rule(rule):
                self.rules.append(rule)
                self.rules.sort(key=lambda x: x.priority)

                if self.log_callback:
                    self.log_callback(f"✅ Added new rule: {rule.name} ({rule.action.value})")
                return True, False  # Success, not duplicate

            return False, False  # Validation failed

        except Exception as e:
            if self.log_callback:
                self.log_callback(f"❌ Error adding rule: {e}")
            return False, False
    
    def remove_rule(self, rule_id: str) -> bool:
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                removed_rule = self.rules.pop(i)
                if self.log_callback:
                    self.log_callback(f"Removed rule: {removed_rule.name}")
                return True
        return False
    
    def update_rule(self, rule_id: str, **kwargs) -> bool:
        for rule in self.rules:
            if rule.id == rule_id:
                for key, value in kwargs.items():
                    if hasattr(rule, key):
                        setattr(rule, key, value)
                if self.log_callback:
                    self.log_callback(f"Updated rule: {rule.name}")
                return True
        return False
    
    def get_rule(self, rule_id: str) -> Optional[FirewallRule]:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None
    
    def get_all_rules(self) -> List[FirewallRule]:
        return self.rules.copy()
    
    def get_enabled_rules(self) -> List[FirewallRule]:
        return [rule for rule in self.rules if rule.enabled]
    
    def evaluate_packet(self, packet_info) -> tuple[bool, Optional[FirewallRule]]:
        """Evaluate packet and increment hit counter for matched rule"""
        if not hasattr(packet_info, 'src_ip'):
            return True, None
        
        enabled_rules = sorted([r for r in self.rules if r.enabled], key=lambda x: x.priority)
        
        for rule in enabled_rules:
            if self._rule_matches_packet(rule, packet_info):
                # Increment hit counter for matched rule
                rule.increment_hit_count()
                
                if rule.action == RuleAction.LOG:
                    if self.log_callback:
                        self.log_callback(f"Rule match: {rule.name} -> LOGGED (Hits: {rule.hit_count})")
                    return self.default_action == RuleAction.ALLOW, rule
                
                action_allowed = rule.action == RuleAction.ALLOW
                if self.log_callback:
                    self.log_callback(f"Rule match: {rule.name} -> {rule.action.value} (Hits: {rule.hit_count})")
                return action_allowed, rule
        
        return self.default_action == RuleAction.ALLOW, None
    
    def _rule_matches_packet(self, rule: FirewallRule, packet_info) -> bool:
        try:
            if rule.direction != RuleDirection.BOTH:
                packet_direction = RuleDirection.INBOUND if packet_info.direction == "IN" else RuleDirection.OUTBOUND
                if rule.direction != packet_direction:
                    return False
            
            if rule.protocol != Protocol.ANY:
                if rule.protocol.value != packet_info.protocol:
                    return False
            
            if rule.src_ip and not self._ip_matches(rule.src_ip, packet_info.src_ip):
                return False
            if rule.dst_ip and not self._ip_matches(rule.dst_ip, packet_info.dst_ip):
                return False
            
            if rule.src_port and hasattr(packet_info, 'src_port'):
                if packet_info.src_port != rule.src_port:
                    return False
            if rule.dst_port and hasattr(packet_info, 'dst_port'):
                if packet_info.dst_port != rule.dst_port:
                    return False
            
            return True
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"Error matching rule: {e}")
            return False
    
    def _ip_matches(self, rule_ip: str, packet_ip: str) -> bool:
        try:
            if '/' in rule_ip:
                network = ipaddress.ip_network(rule_ip, strict=False)
                return ipaddress.ip_address(packet_ip) in network
            return rule_ip == packet_ip
        except:
            return False
    
    def set_default_action(self, action: RuleAction):
        self.default_action = action
        if self.log_callback:
            self.log_callback(f"Default action set to: {action.value}")
    
    def get_rule_statistics(self) -> Dict[str, Any]:
        enabled_count = len([r for r in self.rules if r.enabled])
        disabled_count = len([r for r in self.rules if not r.enabled])
        
        action_counts = {}
        for rule in self.rules:
            action = rule.action.value
            action_counts[action] = action_counts.get(action, 0) + 1
        
        # Calculate total hits
        total_hits = sum(rule.hit_count for rule in self.rules)
        
        return {
            'total_rules': len(self.rules),
            'enabled_rules': enabled_count,
            'disabled_rules': disabled_count,
            'action_counts': action_counts,
            'default_action': self.default_action.value,
            'total_hits': total_hits
        }
    
    def _validate_rule(self, rule: FirewallRule) -> bool:
        try:
            if rule.src_ip and not self._is_valid_ip_or_cidr(rule.src_ip):
                return False
            if rule.dst_ip and not self._is_valid_ip_or_cidr(rule.dst_ip):
                return False
            if rule.src_port and not (1 <= rule.src_port <= 65535):
                return False
            if rule.dst_port and not (1 <= rule.dst_port <= 65535):
                return False
            return True
        except:
            return False
    
    def _is_valid_ip_or_cidr(self, ip_str: str) -> bool:
        """Validate IP address or CIDR notation"""
        try:
            if '/' in ip_str:
                ipaddress.ip_network(ip_str, strict=False)
            else:
                ipaddress.ip_address(ip_str)
            return True
        except:
            return False

if __name__ == "__main__":
    # Create an instance of RuleEngine and print loaded rules
    engine = RuleEngine(log_callback=print)
    print("Loaded rules:", [r.name for r in engine.rules])