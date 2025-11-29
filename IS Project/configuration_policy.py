"""
Configuration & Policy Module - CORRECTED VERSION
Configuration management and policy enforcement system
"""

import json
import os
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import threading

# Optional YAML import
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class PolicyType(Enum):
    SECURITY = "SECURITY"
    NETWORK = "NETWORK"
    PERFORMANCE = "PERFORMANCE"
    COMPLIANCE = "COMPLIANCE"


class PolicyAction(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    LOG = "LOG"
    ALERT = "ALERT"
    QUARANTINE = "QUARANTINE"


@dataclass
class Policy:
    """Represents a security policy"""
    id: str
    name: str
    policy_type: PolicyType
    description: str
    rules: List[Dict[str, Any]]
    conditions: List[Dict[str, Any]]
    actions: List[PolicyAction]
    priority: int
    enabled: bool
    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime] = None


@dataclass
class FirewallConfig:
    """Firewall configuration settings with validation"""
    
    def __init__(self):
        # General settings
        self.firewall_enabled = True
        self.default_action = "ALLOW"
        self.log_level = "INFO"
        self.max_connections = 1000
        self.connection_timeout = 300
        
        # Security settings
        self.enable_stateful_inspection = True
        self.enable_intrusion_detection = True
        self.enable_dos_protection = True
        self._max_packets_per_second = 10000
        
        # Logging settings
        self.log_packets = True
        self.log_connections = True
        self.log_security_events = True
        self.log_retention_days = 30
        
        # Performance settings
        self.packet_buffer_size = 1000
        self.rule_evaluation_timeout = 0.1
        self.cleanup_interval = 60
        
        # Network settings
        self.trusted_networks = []
        self.blocked_networks = []
        self.allowed_ports = [80, 443, 53]
        self.blocked_ports = []
        
        # Feature flags
        self.enable_demo_rules = False
    
    @property
    def max_packets_per_second(self):
        """Get max packets per second with validation"""
        return self._max_packets_per_second
    
    @max_packets_per_second.setter
    def max_packets_per_second(self, value):
        """Set max packets per second with validation"""
        try:
            val = int(value)
            if val < 1:
                raise ValueError("Must be at least 1")
            if val > 1000000:
                raise ValueError("Maximum is 1,000,000")
            self._max_packets_per_second = val
        except (ValueError, TypeError) as e:
            print(f"Warning: Invalid max_packets_per_second value: {value}, using 10000")
            self._max_packets_per_second = 10000


class ConfigurationManager:
    """Manages firewall configuration with thread-safe updates"""
    
    def __init__(self, config_file: str = "firewall_config.json"):
        base_dir = os.path.dirname(__file__) if __file__ else '.'
        self.config_file = os.path.join(base_dir, config_file)
        self.config = FirewallConfig()
        self.config_lock = threading.RLock()
        self.load_configuration()
    
    def get_config(self) -> FirewallConfig:
        """Get current configuration (thread-safe)"""
        with self.config_lock:
            return self.config
    
    def update_config(self, **kwargs) -> bool:
        """Update configuration settings (thread-safe)"""
        try:
            with self.config_lock:
                for key, value in kwargs.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)
                return self.save_configuration()
        except Exception as e:
            print(f"Error updating configuration: {e}")
            return False
    
    def save_configuration(self) -> bool:
        """Save configuration to file (FIXED - removed GUI code)"""
        try:
            with self.config_lock:
                config_dict = asdict(self.config)
                with open(self.config_file, 'w') as f:
                    json.dump(config_dict, f, indent=2, default=str)
                return True
        except Exception as e:
            print(f"Error saving configuration: {e}")
            return False

    def load_configuration(self) -> bool:
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                
                with self.config_lock:
                    for key, value in config_data.items():
                        if hasattr(self.config, key):
                            setattr(self.config, key, value)
                
                return True
            else:
                # Create default configuration
                self.save_configuration()
                return True
        except Exception as e:
            print(f"Error loading configuration: {e}")
            return False
    
    def reset_to_defaults(self) -> bool:
        """Reset configuration to defaults"""
        try:
            self.config = FirewallConfig()
            return self.save_configuration()
        except Exception as e:
            print(f"Error resetting configuration: {e}")
            return False
    
    def export_configuration(self, filename: str) -> bool:
        """Export configuration to file"""
        try:
            config_dict = asdict(self.config)
            with open(filename, 'w') as f:
                json.dump(config_dict, f, indent=2, default=str)
            return True
        except Exception as e:
            print(f"Error exporting configuration: {e}")
            return False
    
    def import_configuration(self, filename: str) -> bool:
        """Import configuration from file"""
        try:
            with open(filename, 'r') as f:
                config_data = json.load(f)
            
            if self._validate_config(config_data):
                for key, value in config_data.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)
                return self.save_configuration()
            return False
        except Exception as e:
            print(f"Error importing configuration: {e}")
            return False
    
    def _validate_config(self, config_data: Dict[str, Any]) -> bool:
        """Validate configuration data"""
        required_fields = ['firewall_enabled', 'default_action', 'log_level']
        return all(field in config_data for field in required_fields)


class PolicyManager:
    """Manages security policies"""
    
    def __init__(self, policy_file: str = "policies.json"):
        base_dir = os.path.dirname(__file__) if __file__ else '.'
        self.policy_file = os.path.join(base_dir, policy_file)
        self.policies: List[Policy] = []
        self.policy_lock = threading.RLock()
        self.load_policies()
    
    def load_policies(self) -> bool:
        """Load policies from file"""
        try:
            if os.path.exists(self.policy_file):
                with open(self.policy_file, 'r') as f:
                    policies_data = json.load(f)
                
                self.policies = []
                for policy_data in policies_data:
                    policy = Policy(
                        id=policy_data['id'],
                        name=policy_data['name'],
                        policy_type=PolicyType(policy_data['policy_type']),
                        description=policy_data['description'],
                        rules=policy_data['rules'],
                        conditions=policy_data['conditions'],
                        actions=[PolicyAction(action) for action in policy_data['actions']],
                        priority=policy_data['priority'],
                        enabled=policy_data['enabled'],
                        created_at=datetime.fromisoformat(policy_data['created_at']),
                        updated_at=datetime.fromisoformat(policy_data['updated_at']),
                        expires_at=datetime.fromisoformat(policy_data['expires_at']) if policy_data.get('expires_at') else None
                    )
                    self.policies.append(policy)
                
                return True
            else:
                self._create_default_policies()
                return True
        except Exception as e:
            print(f"Error loading policies: {e}")
            return False
    
    def save_policies(self) -> bool:
        """Save policies to file"""
        try:
            with self.policy_lock:
                policies_data = []
                for policy in self.policies:
                    policy_dict = asdict(policy)
                    policy_dict['policy_type'] = policy.policy_type.value
                    policy_dict['actions'] = [action.value for action in policy.actions]
                    policy_dict['created_at'] = policy.created_at.isoformat()
                    policy_dict['updated_at'] = policy.updated_at.isoformat()
                    if policy.expires_at:
                        policy_dict['expires_at'] = policy.expires_at.isoformat()
                    policies_data.append(policy_dict)
                
                with open(self.policy_file, 'w') as f:
                    json.dump(policies_data, f, indent=2)
                return True
        except Exception as e:
            print(f"Error saving policies: {e}")
            return False
    
    def _create_default_policies(self):
        """Create default security policies"""
        default_policies = [
            Policy(
                id="default_security",
                name="Default Security Policy",
                policy_type=PolicyType.SECURITY,
                description="Basic security policy for common threats",
                rules=[
                    {"type": "block", "pattern": "malicious_ip", "action": "DENY"},
                    {"type": "rate_limit", "threshold": 100, "action": "ALERT"}
                ],
                conditions=[
                    {"field": "source_ip", "operator": "in", "value": "blacklist"},
                    {"field": "packet_rate", "operator": ">", "value": 100}
                ],
                actions=[PolicyAction.DENY, PolicyAction.ALERT],
                priority=100,
                enabled=True,
                created_at=datetime.now(),
                updated_at=datetime.now()
            ),
            Policy(
                id="network_compliance",
                name="Network Compliance Policy",
                policy_type=PolicyType.COMPLIANCE,
                description="Ensure network traffic compliance",
                rules=[
                    {"type": "port_restriction", "allowed_ports": [80, 443, 22, 21]},
                    {"type": "protocol_restriction", "allowed_protocols": ["TCP", "UDP"]}
                ],
                conditions=[
                    {"field": "destination_port", "operator": "not_in", "value": [80, 443, 22, 21]},
                    {"field": "protocol", "operator": "not_in", "value": ["TCP", "UDP"]}
                ],
                actions=[PolicyAction.DENY, PolicyAction.LOG],
                priority=200,
                enabled=True,
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
        ]
        
        for policy in default_policies:
            self.policies.append(policy)
        
        self.save_policies()
    
    def add_policy(self, policy: Policy) -> bool:
        """Add a new policy"""
        try:
            with self.policy_lock:
                self.policies.append(policy)
                return self.save_policies()
        except Exception as e:
            print(f"Error adding policy: {e}")
            return False
    
    def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy by ID"""
        try:
            with self.policy_lock:
                self.policies = [p for p in self.policies if p.id != policy_id]
                return self.save_policies()
        except Exception as e:
            print(f"Error removing policy: {e}")
            return False
    
    def update_policy(self, policy_id: str, **kwargs) -> bool:
        """Update an existing policy"""
        try:
            with self.policy_lock:
                for policy in self.policies:
                    if policy.id == policy_id:
                        for key, value in kwargs.items():
                            if hasattr(policy, key):
                                setattr(policy, key, value)
                        policy.updated_at = datetime.now()
                        return self.save_policies()
                return False
        except Exception as e:
            print(f"Error updating policy: {e}")
            return False
    
    def get_policy(self, policy_id: str) -> Optional[Policy]:
        """Get policy by ID"""
        for policy in self.policies:
            if policy.id == policy_id:
                return policy
        return None
    
    def get_policies_by_type(self, policy_type: PolicyType) -> List[Policy]:
        """Get policies by type"""
        return [p for p in self.policies if p.policy_type == policy_type]
    
    def get_enabled_policies(self) -> List[Policy]:
        """Get enabled policies"""
        return [p for p in self.policies if p.enabled]
    
    def evaluate_policies(self, packet_info) -> List[PolicyAction]:
        """Evaluate packet against all policies"""
        actions = []
        
        for policy in self.get_enabled_policies():
            if self._policy_matches(policy, packet_info):
                actions.extend(policy.actions)
        
        return actions
    
    def _policy_matches(self, policy: Policy, packet_info) -> bool:
        """Check if policy matches packet"""
        try:
            for condition in policy.conditions:
                if not self._condition_matches(condition, packet_info):
                    return False
            return True
        except Exception as e:
            print(f"Error evaluating policy: {e}")
            return False
    
    def _condition_matches(self, condition: Dict[str, Any], packet_info) -> bool:
        """Check if condition matches packet"""
        field = condition.get('field')
        operator = condition.get('operator')
        value = condition.get('value')
        
        if not hasattr(packet_info, field):
            return False
        
        packet_value = getattr(packet_info, field)
        
        if operator == 'equals':
            return packet_value == value
        elif operator == 'not_equals':
            return packet_value != value
        elif operator == 'in':
            return packet_value in value
        elif operator == 'not_in':
            return packet_value not in value
        elif operator == '>':
            return packet_value > value
        elif operator == '<':
            return packet_value < value
        elif operator == '>=':
            return packet_value >= value
        elif operator == '<=':
            return packet_value <= value
        
        return False


class ConfigurationGUI:
    """GUI for configuration management"""
    
    def __init__(
        self, 
        parent, 
        config_manager: ConfigurationManager, 
        policy_manager: PolicyManager,
        on_save_callback=None
    ):
        self.parent = parent
        self.config_manager = config_manager
        self.policy_manager = policy_manager
        self.on_save_callback = on_save_callback
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self._create_general_tab()
        self._create_security_tab()
        self._create_network_tab()
        self._create_policies_tab()

        # Save/Reload controls
        controls = ttk.Frame(parent)
        controls.pack(fill=tk.X, padx=10, pady=8)
        ttk.Button(controls, text="Save Configuration", command=self._on_save).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls, text="Reload From File", command=self._on_reload).pack(side=tk.LEFT, padx=5)
    
    def _create_general_tab(self):
        """Create general configuration tab"""
        general_frame = ttk.Frame(self.notebook)
        self.notebook.add(general_frame, text="General")
        
        ttk.Label(general_frame, text="General Settings").pack(anchor=tk.W, padx=10, pady=5)
        
        # Firewall enabled
        self.firewall_enabled_var = tk.BooleanVar(value=self.config_manager.get_config().firewall_enabled)
        ttk.Checkbutton(general_frame, text="Enable Firewall", variable=self.firewall_enabled_var).pack(anchor=tk.W, padx=20)
        
        # Default action
        ttk.Label(general_frame, text="Default Action:").pack(anchor=tk.W, padx=20, pady=(10, 0))
        self.default_action_var = tk.StringVar(value=self.config_manager.get_config().default_action)
        ttk.Combobox(general_frame, textvariable=self.default_action_var, 
                    values=["ALLOW", "DENY"]).pack(anchor=tk.W, padx=40)
        
        # Log level
        ttk.Label(general_frame, text="Log Level:").pack(anchor=tk.W, padx=20, pady=(10, 0))
        self.log_level_var = tk.StringVar(value=self.config_manager.get_config().log_level)
        ttk.Combobox(general_frame, textvariable=self.log_level_var,
                    values=["INFO", "WARNING", "ERROR", "CRITICAL"]).pack(anchor=tk.W, padx=40)

    def _create_security_tab(self):
        """Create security configuration tab"""
        security_frame = ttk.Frame(self.notebook)
        self.notebook.add(security_frame, text="Security")
        
        ttk.Label(security_frame, text="Security Settings").pack(anchor=tk.W, padx=10, pady=5)
        
        # Stateful inspection
        self.stateful_var = tk.BooleanVar(value=self.config_manager.get_config().enable_stateful_inspection)
        ttk.Checkbutton(security_frame, text="Enable Stateful Inspection", 
                       variable=self.stateful_var).pack(anchor=tk.W, padx=20)
        
        # Intrusion detection
        self.intrusion_var = tk.BooleanVar(value=self.config_manager.get_config().enable_intrusion_detection)
        ttk.Checkbutton(security_frame, text="Enable Intrusion Detection", 
                       variable=self.intrusion_var).pack(anchor=tk.W, padx=20)
        
        # DoS protection
        self.dos_var = tk.BooleanVar(value=self.config_manager.get_config().enable_dos_protection)
        ttk.Checkbutton(security_frame, text="Enable DoS Protection", 
                       variable=self.dos_var).pack(anchor=tk.W, padx=20)
    
    def _create_network_tab(self):
        """Create network configuration tab - FIXED VERSION"""
        network_frame = ttk.Frame(self.notebook)
        self.notebook.add(network_frame, text="Network")

        ttk.Label(network_frame, text="Network Settings", font=("Arial", 10, "bold")).pack(anchor=tk.W, padx=10, pady=10)

        # Trusted networks
        ttk.Label(network_frame, text="Trusted Networks (one per line):").pack(anchor=tk.W, padx=20, pady=(10, 0))
        ttk.Label(network_frame, text="Examples: 192.168.1.0/24 or 192.168.1.* or 192.168.1.100", 
                 font=("Arial", 8), foreground="gray").pack(anchor=tk.W, padx=40)
        
        self.trusted_networks_text = tk.Text(network_frame, height=5, width=50)
        self.trusted_networks_text.pack(anchor=tk.W, padx=40, pady=5)
        self.trusted_networks_text.insert(tk.END, '\n'.join(self.config_manager.get_config().trusted_networks))

        # Blocked networks
        ttk.Label(network_frame, text="Blocked Networks (one per line):").pack(anchor=tk.W, padx=20, pady=(15, 0))
        ttk.Label(network_frame, text="Examples: 10.0.0.0/8 or 192.168.1.50 or 172.16.*", 
                 font=("Arial", 8), foreground="gray").pack(anchor=tk.W, padx=40)
        
        self.blocked_networks_text = tk.Text(network_frame, height=5, width=50)
        self.blocked_networks_text.pack(anchor=tk.W, padx=40, pady=5)
        self.blocked_networks_text.insert(tk.END, '\n'.join(self.config_manager.get_config().blocked_networks))

        # Info label
        info_text = "ℹ️ Note: Blocked networks take priority over trusted networks."
        ttk.Label(network_frame, text=info_text, font=("Arial", 8), foreground="blue").pack(anchor=tk.W, padx=20, pady=10)

    def _create_policies_tab(self):
        """Create policies management tab"""
        policies_frame = ttk.Frame(self.notebook)
        self.notebook.add(policies_frame, text="Policies")
        
        ttk.Label(policies_frame, text="Security Policies").pack(anchor=tk.W, padx=10, pady=5)
        
        # Create policies treeview
        columns = ('Name', 'Type', 'Enabled', 'Priority', 'Actions')
        self.policies_tree = ttk.Treeview(policies_frame, columns=columns, show='headings', height=10)
        
        for col in columns:
            self.policies_tree.heading(col, text=col)
            self.policies_tree.column(col, width=150)
        
        self.policies_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Policy buttons
        button_frame = ttk.Frame(policies_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(button_frame, text="Add Policy", command=self._add_policy).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Edit Policy", command=self._edit_policy).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete Policy", command=self._delete_policy).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Refresh", command=self._refresh_policies).pack(side=tk.LEFT, padx=5)
        
        # Load policies
        self._refresh_policies()
    
    def _refresh_policies(self):
        """Refresh policies list"""
        for item in self.policies_tree.get_children():
            self.policies_tree.delete(item)
        
        for policy in self.policy_manager.policies:
            actions_str = ', '.join([action.value for action in policy.actions])
            self.policies_tree.insert('', 'end', iid=policy.id, values=(
                policy.name,
                policy.policy_type.value,
                'Yes' if policy.enabled else 'No',
                policy.priority,
                actions_str
            ))
    
    def _add_policy(self):
        """Add new policy - placeholder for full implementation"""
        messagebox.showinfo("Add Policy", "Use the policy editor to add new policies.")
    
    def _edit_policy(self):
        """Edit policy - placeholder for full implementation"""
        selection = self.policies_tree.selection()
        if not selection:
            messagebox.showwarning("Policies", "Please select a policy to edit.")
            return
        messagebox.showinfo("Edit Policy", "Use the policy editor to modify policies.")
    
    def _delete_policy(self):
        """Delete selected policy"""
        selection = self.policies_tree.selection()
        if not selection:
            messagebox.showwarning("Policies", "Please select a policy to delete.")
            return
        
        policy_id = selection[0]
        policy = self.policy_manager.get_policy(policy_id)
        
        if not policy:
            messagebox.showerror("Policies", "Selected policy could not be found.")
            return

        if not messagebox.askyesno("Delete Policy", f"Are you sure you want to delete '{policy.name}'?"):
            return

        if self.policy_manager.remove_policy(policy_id):
            self._refresh_policies()
            messagebox.showinfo("Policies", "Policy deleted.")
        else:
            messagebox.showerror("Policies", "Failed to delete policy.")
    
    def save_configuration(self):
        """Save all configuration changes - FIXED VERSION"""
        try:
            # Get network lists from text widgets
            trusted_networks = [
                line.strip() 
                for line in self.trusted_networks_text.get('1.0', tk.END).strip().split('\n') 
                if line.strip()
            ]
            blocked_networks = [
                line.strip() 
                for line in self.blocked_networks_text.get('1.0', tk.END).strip().split('\n') 
                if line.strip()
            ]
            
            # Update configuration
            success = self.config_manager.update_config(
                firewall_enabled=self.firewall_enabled_var.get(),
                default_action=self.default_action_var.get(),
                log_level=self.log_level_var.get(),
                enable_stateful_inspection=self.stateful_var.get(),
                enable_intrusion_detection=self.intrusion_var.get(),
                enable_dos_protection=self.dos_var.get(),
                trusted_networks=trusted_networks,
                blocked_networks=blocked_networks
            )
            
            if success:
                print(f"✅ Configuration saved to: {self.config_manager.config_file}")
                return True
            else:
                print("❌ Failed to save configuration")
                return False
                
        except Exception as e:
            print(f"❌ Error saving configuration: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _on_save(self):
        """Handle Save Configuration button"""
        try:
            success = self.save_configuration()
            
            if success:
                messagebox.showinfo("Configuration", 
                    "Configuration saved successfully!\n\n" +
                    "Click 'Apply Config (Live)' to reload settings without restarting.")
                if self.on_save_callback:
                    try:
                        self.on_save_callback()
                    except Exception as callback_error:
                        messagebox.showwarning("Configuration", 
                            f"Config saved but live reload failed:\n{callback_error}")
            else:
                messagebox.showerror("Configuration", 
                    "Failed to save configuration.\nCheck console for details.")
                
        except Exception as e:
            messagebox.showerror("Configuration Error", f"Error saving:\n{e}")

    def _on_reload(self):
        """Reload configuration from file and refresh fields"""
        try:
            if self.config_manager.load_configuration():
                cfg = self.config_manager.get_config()
                
                # Update all GUI fields
                self.firewall_enabled_var.set(cfg.firewall_enabled)
                self.default_action_var.set(cfg.default_action)
                self.log_level_var.set(cfg.log_level)
                self.stateful_var.set(cfg.enable_stateful_inspection)
                self.intrusion_var.set(cfg.enable_intrusion_detection)
                self.dos_var.set(cfg.enable_dos_protection)
                
                # Update network lists
                self.trusted_networks_text.delete('1.0', tk.END)
                self.trusted_networks_text.insert(tk.END, '\n'.join(cfg.trusted_networks))
                
                self.blocked_networks_text.delete('1.0', tk.END)
                self.blocked_networks_text.insert(tk.END, '\n'.join(cfg.blocked_networks))
                
                messagebox.showinfo("Configuration", "Configuration reloaded from file.")
            else:
                messagebox.showerror("Configuration", "Failed to reload configuration.")
                
        except Exception as e:
            print(f"Error reloading configuration: {e}")
            messagebox.showerror("Configuration", f"Error reloading:\n{e}")