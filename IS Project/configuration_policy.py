"""
Configuration & Policy Module
Configuration management and policy enforcement system
"""

import json
import os
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from typing import Dict, List, Any, Optional, Union

# Optional YAML import
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import threading

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
    """Firewall configuration settings"""
    # General settings
    firewall_enabled: bool = True
    default_action: str = "ALLOW"
    log_level: str = "INFO"
    max_connections: int = 1000
    connection_timeout: int = 300
    
    # Security settings
    enable_stateful_inspection: bool = True
    enable_intrusion_detection: bool = True
    enable_dos_protection: bool = True
    max_packets_per_second: int = 10000
    
    # Logging settings
    log_packets: bool = True
    log_connections: bool = True
    log_security_events: bool = True
    log_retention_days: int = 30
    
    # Performance settings
    packet_buffer_size: int = 1000
    rule_evaluation_timeout: float = 0.1
    cleanup_interval: int = 60
    
    # Network settings
    trusted_networks: List[str] = None
    blocked_networks: List[str] = None
    allowed_ports: List[int] = None
    blocked_ports: List[int] = None
    # Feature flags
    enable_demo_rules: bool = False
    
    def __post_init__(self):
        if self.trusted_networks is None:
            self.trusted_networks = []
        if self.blocked_networks is None:
            self.blocked_networks = []
        if self.allowed_ports is None:
            self.allowed_ports = [80, 443, 53]
        if self.blocked_ports is None:
            self.blocked_ports = []

class ConfigurationManager:
    """Manages firewall configuration"""
    
    def __init__(self, config_file: str = "firewall_config.json"):
        base_dir = os.path.dirname(__file__)
        self.config_file = os.path.join(base_dir, config_file)
        self.config = FirewallConfig()
        self.policies: List[Policy] = []
        # Use re-entrant lock to avoid deadlock when save is called from update
        self.config_lock = threading.RLock()
        
        # Load configuration
        self.load_configuration()
    
    def load_configuration(self) -> bool:
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                
                # Update configuration
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
    
    def save_configuration(self) -> bool:
        """Save configuration to file"""
        try:
            with self.config_lock:
                config_dict = asdict(self.config)
                with open(self.config_file, 'w') as f:
                    json.dump(config_dict, f, indent=2, default=str)
                return True
        except Exception as e:
            print(f"Error saving configuration: {e}")
            return False
    
    def get_config(self) -> FirewallConfig:
        """Get current configuration"""
        with self.config_lock:
            return self.config
    
    def update_config(self, **kwargs) -> bool:
        """Update configuration settings"""
        try:
            with self.config_lock:
                for key, value in kwargs.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)
                return self.save_configuration()
        except Exception as e:
            print(f"Error updating configuration: {e}")
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
            
            # Validate configuration
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
        base_dir = os.path.dirname(__file__)
        self.policy_file = os.path.join(base_dir, policy_file)
        self.policies: List[Policy] = []
        # Use re-entrant lock to avoid deadlock when save is called from within an update
        self.policy_lock = threading.RLock()
        
        # Load policies
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
                # Create default policies
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
    
    def __init__(self, parent, config_manager: ConfigurationManager, policy_manager: PolicyManager):
        self.parent = parent
        self.config_manager = config_manager
        self.policy_manager = policy_manager
        
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
        
        # General settings
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
                    values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]).pack(anchor=tk.W, padx=40)
    
    def _create_security_tab(self):
        """Create security configuration tab"""
        security_frame = ttk.Frame(self.notebook)
        self.notebook.add(security_frame, text="Security")
        
        # Security settings
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
        """Create network configuration tab"""
        network_frame = ttk.Frame(self.notebook)
        self.notebook.add(network_frame, text="Network")
        
        # Network settings
        ttk.Label(network_frame, text="Network Settings").pack(anchor=tk.W, padx=10, pady=5)
        
        # Trusted networks
        ttk.Label(network_frame, text="Trusted Networks:").pack(anchor=tk.W, padx=20, pady=(10, 0))
        self.trusted_networks_text = tk.Text(network_frame, height=3, width=50)
        self.trusted_networks_text.pack(anchor=tk.W, padx=40)
        self.trusted_networks_text.insert(tk.END, '\n'.join(self.config_manager.get_config().trusted_networks))
        
        # Blocked networks
        ttk.Label(network_frame, text="Blocked Networks:").pack(anchor=tk.W, padx=20, pady=(10, 0))
        self.blocked_networks_text = tk.Text(network_frame, height=3, width=50)
        self.blocked_networks_text.pack(anchor=tk.W, padx=40)
        self.blocked_networks_text.insert(tk.END, '\n'.join(self.config_manager.get_config().blocked_networks))
    
    def _create_policies_tab(self):
        """Create policies management tab"""
        policies_frame = ttk.Frame(self.notebook)
        self.notebook.add(policies_frame, text="Policies")
        
        # Policies list
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
        """Add new policy"""
        def open_add_dialog():
            dialog = tk.Toplevel(self.parent)
            dialog.title("Add Policy")
            dialog.transient(self.parent)
            dialog.resizable(False, False)
            dialog.grab_set()

            # Fields (grid layout)
            frm = ttk.LabelFrame(dialog, text="Policy Details")
            frm.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

            # Name
            ttk.Label(frm, text="Name:").grid(row=0, column=0, sticky=tk.W, padx=6, pady=6)
            name_var = tk.StringVar()
            ttk.Entry(frm, textvariable=name_var, width=42).grid(row=0, column=1, sticky=tk.EW, padx=6, pady=6)

            # Type
            ttk.Label(frm, text="Type:").grid(row=1, column=0, sticky=tk.W, padx=6, pady=6)
            type_var = tk.StringVar(value=PolicyType.SECURITY.value)
            ttk.Combobox(frm, textvariable=type_var, values=[t.value for t in PolicyType], state='readonly').grid(row=1, column=1, sticky=tk.EW, padx=6, pady=6)

            # Enabled
            ttk.Label(frm, text="Enabled:").grid(row=2, column=0, sticky=tk.W, padx=6, pady=6)
            enabled_var = tk.BooleanVar(value=True)
            ttk.Checkbutton(frm, variable=enabled_var, text="Enabled").grid(row=2, column=1, sticky=tk.W, padx=6, pady=6)

            # Priority
            ttk.Label(frm, text="Priority:").grid(row=3, column=0, sticky=tk.W, padx=6, pady=6)
            priority_var = tk.StringVar(value="100")
            ttk.Entry(frm, textvariable=priority_var, width=12).grid(row=3, column=1, sticky=tk.W, padx=6, pady=6)

            # Actions
            ttk.Label(frm, text="Actions (comma):").grid(row=4, column=0, sticky=tk.W, padx=6, pady=6)
            actions_var = tk.StringVar(value="DENY,ALERT")
            ttk.Entry(frm, textvariable=actions_var, width=42).grid(row=4, column=1, sticky=tk.EW, padx=6, pady=6)

            # Description
            ttk.Label(frm, text="Description:").grid(row=5, column=0, sticky=tk.NW, padx=6, pady=6)
            desc_text = tk.Text(frm, height=3, width=50)
            desc_text.grid(row=5, column=1, sticky=tk.EW, padx=6, pady=6)

            # Rules
            ttk.Label(frm, text="Rules (JSON list):").grid(row=6, column=0, sticky=tk.NW, padx=6, pady=6)
            rules_text = tk.Text(frm, height=4, width=50)
            rules_text.grid(row=6, column=1, sticky=tk.EW, padx=6, pady=6)

            # Conditions
            ttk.Label(frm, text="Conditions (JSON list):").grid(row=7, column=0, sticky=tk.NW, padx=6, pady=6)
            conds_text = tk.Text(frm, height=4, width=50)
            conds_text.grid(row=7, column=1, sticky=tk.EW, padx=6, pady=6)

            frm.columnconfigure(1, weight=1)

            # Buttons
            btns = ttk.Frame(dialog)
            btns.pack(fill=tk.X, padx=12, pady=10)
            def on_cancel():
                dialog.destroy()
            def on_save():
                try:
                    name = name_var.get().strip()
                    if not name:
                        messagebox.showerror("Validation", "Name is required.")
                        return
                    try:
                        priority = int(priority_var.get().strip())
                    except ValueError:
                        messagebox.showerror("Validation", "Priority must be an integer.")
                        return

                    # Parse actions
                    actions_raw = [a.strip().upper() for a in actions_var.get().split(',') if a.strip()]
                    actions = []
                    for a in actions_raw:
                        if a not in [pa.value for pa in PolicyAction]:
                            messagebox.showerror("Validation", f"Invalid action: {a}")
                            return
                        actions.append(PolicyAction(a))

                    # Parse JSON fields
                    def parse_json_from(text_widget, field_name):
                        raw = text_widget.get('1.0', tk.END).strip()
                        if not raw:
                            return []
                        try:
                            data = json.loads(raw)
                        except Exception as e:
                            messagebox.showerror("Validation", f"{field_name} must be valid JSON list.\n{e}")
                            return None
                        if not isinstance(data, list):
                            messagebox.showerror("Validation", f"{field_name} must be a JSON list.")
                            return None
                        return data

                    rules = parse_json_from(rules_text, "Rules")
                    if rules is None:
                        return
                    conditions = parse_json_from(conds_text, "Conditions")
                    if conditions is None:
                        return

                    description = desc_text.get('1.0', tk.END).strip()

                    policy_id = f"{name.lower().replace(' ', '_')}_{int(datetime.now().timestamp())}"
                    policy = Policy(
                        id=policy_id,
                        name=name,
                        policy_type=PolicyType(type_var.get()),
                        description=description,
                        rules=rules,
                        conditions=conditions,
                        actions=actions,
                        priority=priority,
                        enabled=enabled_var.get(),
                        created_at=datetime.now(),
                        updated_at=datetime.now()
                    )

                    if self.policy_manager.add_policy(policy):
                        self._refresh_policies()
                        messagebox.showinfo("Policies", "Policy added successfully.")
                        dialog.destroy()
                    else:
                        messagebox.showerror("Policies", "Failed to add policy. Check console for details.")
                except Exception as e:
                    messagebox.showerror("Policies", f"Error adding policy:\n{e}")

            ttk.Button(btns, text="Cancel", command=on_cancel).pack(side=tk.RIGHT, padx=6)
            ttk.Button(btns, text="Save", command=on_save).pack(side=tk.RIGHT, padx=6)

        self.parent.after(0, open_add_dialog)
    
    def _edit_policy(self):
        """Edit selected policy"""
        selection = self.policies_tree.selection()
        if not selection:
            messagebox.showwarning("Policies", "Please select a policy to edit.")
            return
        policy_id = selection[0]
        policy = self.policy_manager.get_policy(policy_id)
        if not policy:
            messagebox.showerror("Policies", "Selected policy could not be found.")
            return

        def open_edit_dialog():
            dialog = tk.Toplevel(self.parent)
            dialog.title("Edit Policy")
            dialog.transient(self.parent)
            dialog.resizable(False, False)
            dialog.grab_set()

            frm = ttk.LabelFrame(dialog, text="Policy Details")
            frm.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

            ttk.Label(frm, text="Name:").grid(row=0, column=0, sticky=tk.W, padx=6, pady=6)
            name_var = tk.StringVar(value=policy.name)
            ttk.Entry(frm, textvariable=name_var, width=42).grid(row=0, column=1, sticky=tk.EW, padx=6, pady=6)

            ttk.Label(frm, text="Type:").grid(row=1, column=0, sticky=tk.W, padx=6, pady=6)
            type_var = tk.StringVar(value=policy.policy_type.value)
            ttk.Combobox(frm, textvariable=type_var, values=[t.value for t in PolicyType], state='readonly').grid(row=1, column=1, sticky=tk.EW, padx=6, pady=6)

            ttk.Label(frm, text="Enabled:").grid(row=2, column=0, sticky=tk.W, padx=6, pady=6)
            enabled_var = tk.BooleanVar(value=policy.enabled)
            ttk.Checkbutton(frm, variable=enabled_var, text="Enabled").grid(row=2, column=1, sticky=tk.W, padx=6, pady=6)

            ttk.Label(frm, text="Priority:").grid(row=3, column=0, sticky=tk.W, padx=6, pady=6)
            priority_var = tk.StringVar(value=str(policy.priority))
            ttk.Entry(frm, textvariable=priority_var, width=12).grid(row=3, column=1, sticky=tk.W, padx=6, pady=6)

            ttk.Label(frm, text="Actions (comma):").grid(row=4, column=0, sticky=tk.W, padx=6, pady=6)
            actions_var = tk.StringVar(value=",".join([a.value for a in policy.actions]))
            ttk.Entry(frm, textvariable=actions_var, width=42).grid(row=4, column=1, sticky=tk.EW, padx=6, pady=6)

            ttk.Label(frm, text="Description:").grid(row=5, column=0, sticky=tk.NW, padx=6, pady=6)
            desc_text = tk.Text(frm, height=3, width=50)
            desc_text.insert(tk.END, policy.description)
            desc_text.grid(row=5, column=1, sticky=tk.EW, padx=6, pady=6)

            ttk.Label(frm, text="Rules (JSON list):").grid(row=6, column=0, sticky=tk.NW, padx=6, pady=6)
            rules_text = tk.Text(frm, height=4, width=50)
            rules_text.insert(tk.END, json.dumps(policy.rules, indent=2))
            rules_text.grid(row=6, column=1, sticky=tk.EW, padx=6, pady=6)

            ttk.Label(frm, text="Conditions (JSON list):").grid(row=7, column=0, sticky=tk.NW, padx=6, pady=6)
            conds_text = tk.Text(frm, height=4, width=50)
            conds_text.insert(tk.END, json.dumps(policy.conditions, indent=2))
            conds_text.grid(row=7, column=1, sticky=tk.EW, padx=6, pady=6)

            frm.columnconfigure(1, weight=1)

            btns = ttk.Frame(dialog)
            btns.pack(fill=tk.X, padx=12, pady=10)

            def on_cancel():
                dialog.destroy()

            def on_save():
                try:
                    name = name_var.get().strip()
                    if not name:
                        messagebox.showerror("Validation", "Name is required.")
                        return
                    try:
                        priority = int(priority_var.get().strip())
                    except ValueError:
                        messagebox.showerror("Validation", "Priority must be an integer.")
                        return

                    actions_raw = [a.strip().upper() for a in actions_var.get().split(',') if a.strip()]
                    actions = []
                    for a in actions_raw:
                        if a not in [pa.value for pa in PolicyAction]:
                            messagebox.showerror("Validation", f"Invalid action: {a}")
                            return
                        actions.append(PolicyAction(a))

                    def parse_json_from(text_widget, field_name):
                        raw = text_widget.get('1.0', tk.END).strip()
                        if not raw:
                            return []
                        try:
                            data = json.loads(raw)
                        except Exception as e:
                            messagebox.showerror("Validation", f"{field_name} must be valid JSON list.\n{e}")
                            return None
                        if not isinstance(data, list):
                            messagebox.showerror("Validation", f"{field_name} must be a JSON list.")
                            return None
                        return data

                    rules = parse_json_from(rules_text, "Rules")
                    if rules is None:
                        return
                    conditions = parse_json_from(conds_text, "Conditions")
                    if conditions is None:
                        return

                    updates = {
                        'name': name,
                        'policy_type': PolicyType(type_var.get()),
                        'enabled': enabled_var.get(),
                        'priority': priority,
                        'actions': actions,
                        'description': desc_text.get('1.0', tk.END).strip(),
                        'rules': rules,
                        'conditions': conditions
                    }

                    if self.policy_manager.update_policy(policy_id, **updates):
                        self._refresh_policies()
                        messagebox.showinfo("Policies", "Policy updated successfully.")
                        dialog.destroy()
                    else:
                        messagebox.showerror("Policies", "Failed to update policy. Check console for details.")
                except Exception as e:
                    messagebox.showerror("Policies", f"Error updating policy:\n{e}")

            ttk.Button(btns, text="Cancel", command=on_cancel).pack(side=tk.RIGHT, padx=6)
            ttk.Button(btns, text="Save", command=on_save).pack(side=tk.RIGHT, padx=6)

        self.parent.after(0, open_edit_dialog)
    
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
            messagebox.showerror("Policies", "Failed to delete policy. Check console for details.")
    
    def save_configuration(self):
        """Save all configuration changes"""
        try:
            # Get values safely
            trusted_networks = [line.strip() for line in self.trusted_networks_text.get('1.0', tk.END).strip().split('\n') if line.strip()]
            blocked_networks = [line.strip() for line in self.blocked_networks_text.get('1.0', tk.END).strip().split('\n') if line.strip()]
            
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
                print(f"Configuration saved to: {self.config_manager.config_file}")
                return True
            else:
                print("Failed to save configuration")
                return False
                
        except Exception as e:
            print(f"Error saving configuration: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _on_save(self):
        """Handle Save Configuration button"""
        # Disable button to prevent multiple clicks
        save_button = None
        for child in self.parent.winfo_children():
            if isinstance(child, ttk.Frame):
                for subchild in child.winfo_children():
                    if isinstance(subchild, ttk.Button) and subchild.cget('text') == 'Save Configuration':
                        save_button = subchild
                        break
        if save_button:
            save_button.config(state='disabled', text='Saving...')
        
        # Run save in separate thread to prevent GUI freezing
        def save_worker():
            try:
                success = self.save_configuration()
                
                # Schedule GUI update on main thread
                self.parent.after(0, lambda: self._on_save_complete(success, save_button))
                
            except Exception as e:
                # Schedule error display on main thread
                self.parent.after(0, lambda: self._on_save_error(str(e), save_button))
        
        # Start save thread
        save_thread = threading.Thread(target=save_worker, daemon=True)
        save_thread.start()
    
    def _on_save_complete(self, success, save_button):
        """Handle save completion on main thread"""
        try:
            if success:
                messagebox.showinfo("Configuration", "Configuration saved successfully.\n\nRestart the firewall to apply default action changes.")
            else:
                messagebox.showerror("Configuration", "Failed to save configuration.\nCheck console for error details.")
        finally:
            # Re-enable button
            if save_button:
                save_button.config(state='normal', text='Save Configuration')
    
    def _on_save_error(self, error_msg, save_button):
        """Handle save error on main thread"""
        try:
            messagebox.showerror("Configuration Error", f"Error saving configuration:\n{error_msg}")
        finally:
            # Re-enable button
            if save_button:
                save_button.config(state='normal', text='Save Configuration')

    def _on_reload(self):
        """Reload configuration from file and refresh fields"""
        try:
            if self.config_manager.load_configuration():
                cfg = self.config_manager.get_config()
                self.firewall_enabled_var.set(cfg.firewall_enabled)
                self.default_action_var.set(cfg.default_action)
                self.log_level_var.set(cfg.log_level)
                self.stateful_var.set(cfg.enable_stateful_inspection)
                self.intrusion_var.set(cfg.enable_intrusion_detection)
                self.dos_var.set(cfg.enable_dos_protection)
                self.trusted_networks_text.delete('1.0', tk.END)
                self.trusted_networks_text.insert(tk.END, '\n'.join(cfg.trusted_networks))
                self.blocked_networks_text.delete('1.0', tk.END)
                self.blocked_networks_text.insert(tk.END, '\n'.join(cfg.blocked_networks))
                messagebox.showinfo("Configuration", "Configuration reloaded from file.")
        except Exception as e:
            print(f"Error reloading configuration: {e}")