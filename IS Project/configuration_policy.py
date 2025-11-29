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
                self.save_configuration()
                return True
        except Exception as e:
            print(f"Error loading configuration: {e}")
            return False
        
class ConfigurationManager:
    """Manages firewall configuration"""
    
    def __init__(self, config_file: str = "firewall_config.json"):
        base_dir = os.path.dirname(__file__)
        self.config_file = os.path.join(base_dir, config_file)
        self.config = FirewallConfig()
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


    
class ConfigurationGUI:
    """GUI for configuration management"""
    
    def __init__(
        self, 
        parent, 
        config_manager: ConfigurationManager, 
        on_save_callback=None
    ):
        self.parent = parent
        self.config_manager = config_manager
        self.on_save_callback = on_save_callback
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self._create_general_tab()
        self._create_security_tab()
        self._create_network_tab()
        

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