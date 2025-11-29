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
from datetime import datetime
from enum import Enum
import threading

# Optional YAML import
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


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
        self._max_packets_per_second = 10000  # Private with validation
        
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
    
    def to_dict(self):
        """Convert config to dictionary for JSON serialization"""
        return {
            'firewall_enabled': self.firewall_enabled,
            'default_action': self.default_action,
            'log_level': self.log_level,
            'max_connections': self.max_connections,
            'connection_timeout': self.connection_timeout,
            'enable_stateful_inspection': self.enable_stateful_inspection,
            'enable_intrusion_detection': self.enable_intrusion_detection,
            'enable_dos_protection': self.enable_dos_protection,
            'max_packets_per_second': self.max_packets_per_second,
            'log_packets': self.log_packets,
            'log_connections': self.log_connections,
            'log_security_events': self.log_security_events,
            'log_retention_days': self.log_retention_days,
            'packet_buffer_size': self.packet_buffer_size,
            'rule_evaluation_timeout': self.rule_evaluation_timeout,
            'cleanup_interval': self.cleanup_interval,
            'trusted_networks': self.trusted_networks,
            'blocked_networks': self.blocked_networks,
            'allowed_ports': self.allowed_ports,
            'blocked_ports': self.blocked_ports,
            'enable_demo_rules': self.enable_demo_rules
        }


class ConfigurationManager:
    """Manages firewall configuration with thread-safe updates"""
    
    def __init__(self, config_file: str = "firewall_config.json"):
        base_dir = os.path.dirname(os.path.abspath(__file__)) if __file__ else '.'
        self.config_file = os.path.join(base_dir, config_file)
        self.config = FirewallConfig()
        # Use re-entrant lock to avoid deadlock
        self.config_lock = threading.RLock()
        
        # Load configuration on startup
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
        """Save configuration to file"""
        try:
            with self.config_lock:
                config_dict = self.config.to_dict()
                with open(self.config_file, 'w') as f:
                    json.dump(config_dict, f, indent=2)
                return True
        except Exception as e:
            return False
    
    def load_configuration(self) -> bool:
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                
                with self.config_lock:
                    # Update configuration attributes
                    for key, value in config_data.items():
                        if hasattr(self.config, key):
                            setattr(self.config, key, value)
                
                return True
            else:
                # Create default configuration file
                self.save_configuration()
                return True
        except Exception as e:
            return False
    
    def reset_to_defaults(self) -> bool:
        """Reset configuration to defaults"""
        try:
            with self.config_lock:
                self.config = FirewallConfig()
                return self.save_configuration()
        except Exception as e:
            print(f"Error resetting configuration: {e}")
            return False
    
    def export_configuration(self, filename: str) -> bool:
        """Export configuration to file"""
        try:
            with self.config_lock:
                config_dict = self.config.to_dict()
                with open(filename, 'w') as f:
                    json.dump(config_dict, f, indent=2)
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
                with self.config_lock:
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
        
        # Save/Apply controls
        controls = ttk.Frame(parent)
        controls.pack(fill=tk.X, padx=10, pady=8)
        ttk.Button(controls, text="Save Configuration", command=self._on_save).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls, text="Apply Live Config", command=self._on_apply_live).pack(side=tk.LEFT, padx=5)
    
    def _validate_networks(self):
        """Validate network entries before saving"""
        import ipaddress
        
        trusted_text = self.trusted_networks_text.get('1.0', tk.END).strip()
        blocked_text = self.blocked_networks_text.get('1.0', tk.END).strip()
        
        trusted_lines = [line.strip() for line in trusted_text.split('\n') if line.strip()]
        blocked_lines = [line.strip() for line in blocked_text.split('\n') if line.strip()]
        
        errors = []
        warnings = []
        
        # Validate trusted networks
        for line in trusted_lines:
            try:
                if '/' in line:
                    ipaddress.ip_network(line, strict=False)
                else:
                    ipaddress.ip_address(line)
            except ValueError:
                errors.append(f"Invalid trusted network: {line}")
        
        # Validate blocked networks
        for line in blocked_lines:
            try:
                if '/' in line:
                    ipaddress.ip_network(line, strict=False)
                else:
                    ipaddress.ip_address(line)
            except ValueError:
                errors.append(f"Invalid blocked network: {line}")
        
        # Check for overlaps
        for trusted in trusted_lines:
            for blocked in blocked_lines:
                if trusted == blocked:
                    warnings.append(f"⚠️ {trusted} is in BOTH trusted and blocked lists!")
        
        if errors:
            messagebox.showerror("Validation Error", "\n".join(errors))
            self.validation_label.config(text="❌ Validation failed", foreground="red")
            return False
        elif warnings:
            result = messagebox.askokcancel("Validation Warning", 
                                            "\n".join(warnings) + "\n\nContinue anyway?")
            if not result:
                self.validation_label.config(text="⚠️ Validation warnings", foreground="orange")
                return False
        
        self.validation_label.config(text=f"✅ Valid ({len(trusted_lines)} trusted, {len(blocked_lines)} blocked)", 
                                    foreground="green")
        return True

    
    def _create_general_tab(self):
        """Create general configuration tab"""
        general_frame = ttk.Frame(self.notebook)
        self.notebook.add(general_frame, text="General")
        
        # General settings
        ttk.Label(general_frame, text="General Settings", font=('Arial', 10, 'bold')).pack(anchor=tk.W, padx=10, pady=5)
        
        # Firewall enabled
        self.firewall_enabled_var = tk.BooleanVar(value=self.config_manager.get_config().firewall_enabled)
        ttk.Checkbutton(general_frame, text="Enable Firewall", variable=self.firewall_enabled_var).pack(anchor=tk.W, padx=20)
        
        # Default action
        ttk.Label(general_frame, text="Default Action:").pack(anchor=tk.W, padx=20, pady=(10, 0))
        self.default_action_var = tk.StringVar(value=self.config_manager.get_config().default_action)
        ttk.Combobox(general_frame, textvariable=self.default_action_var, 
                    values=["ALLOW", "DENY"], state="readonly").pack(anchor=tk.W, padx=40)
        
        # Log level
        ttk.Label(general_frame, text="Log Level:").pack(anchor=tk.W, padx=20, pady=(10, 0))
        self.log_level_var = tk.StringVar(value=self.config_manager.get_config().log_level)
        ttk.Combobox(general_frame, textvariable=self.log_level_var,
                    values=["INFO", "WARNING", "ERROR", "CRITICAL"], state="readonly").pack(anchor=tk.W, padx=40)
    
    def _create_security_tab(self):
        """Create security configuration tab"""
        security_frame = ttk.Frame(self.notebook)
        self.notebook.add(security_frame, text="Security")
        
        # Security settings
        ttk.Label(security_frame, text="Security Settings", font=('Arial', 10, 'bold')).pack(anchor=tk.W, padx=10, pady=5)
        
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
        """Create enhanced network configuration tab with validation"""
        network_frame = ttk.Frame(self.notebook)
        self.notebook.add(network_frame, text="Network")
        
<<<<<<< HEAD
        # Network settings
        ttk.Label(network_frame, text="Network Settings", font=('Arial', 10, 'bold')).pack(anchor=tk.W, padx=10, pady=5)
        
        # Trusted networks
        ttk.Label(network_frame, text="Trusted Networks (one per line):").pack(anchor=tk.W, padx=20, pady=(10, 0))
        self.trusted_networks_text = tk.Text(network_frame, height=3, width=50)
        self.trusted_networks_text.pack(anchor=tk.W, padx=40)
        self.trusted_networks_text.insert(tk.END, '\n'.join(self.config_manager.get_config().trusted_networks))
        
        # Blocked networks
        ttk.Label(network_frame, text="Blocked Networks (one per line):").pack(anchor=tk.W, padx=20, pady=(10, 0))
        self.blocked_networks_text = tk.Text(network_frame, height=3, width=50)
        self.blocked_networks_text.pack(anchor=tk.W, padx=40)
        self.blocked_networks_text.insert(tk.END, '\n'.join(self.config_manager.get_config().blocked_networks))
    
=======
        # Instructions
        instructions = ttk.LabelFrame(network_frame, text="📖 Instructions")
        instructions.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(instructions, text="• Trusted Networks: Traffic from/to these IPs is ALWAYS ALLOWED", 
                foreground="green").pack(anchor=tk.W, padx=10, pady=2)
        ttk.Label(instructions, text="• Blocked Networks: Traffic from/to these IPs is ALWAYS BLOCKED", 
                foreground="red").pack(anchor=tk.W, padx=10, pady=2)
        ttk.Label(instructions, text="• Format: One IP per line (e.g., 192.168.1.100 or 10.0.0.0/24)", 
                foreground="blue").pack(anchor=tk.W, padx=10, pady=2)
        
        # Trusted networks
        trusted_frame = ttk.LabelFrame(network_frame, text="✅ Trusted Networks (Whitelist)")
        trusted_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        ttk.Label(trusted_frame, text="Add IPs or networks that should ALWAYS be allowed:").pack(anchor=tk.W, padx=10, pady=5)
        
        trusted_scroll = ttk.Scrollbar(trusted_frame)
        trusted_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.trusted_networks_text = tk.Text(trusted_frame, height=6, width=50, 
                                            yscrollcommand=trusted_scroll.set,
                                            font=("Consolas", 10))
        self.trusted_networks_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        trusted_scroll.config(command=self.trusted_networks_text.yview)
        
        current_trusted = self.config_manager.get_config().trusted_networks
        self.trusted_networks_text.insert(tk.END, '\n'.join(current_trusted))
        
        ttk.Label(trusted_frame, text="Examples: 192.168.1.100, 10.0.0.0/8, 172.16.0.0/16", 
                foreground="gray").pack(anchor=tk.W, padx=10, pady=2)
        
        # Blocked networks
        blocked_frame = ttk.LabelFrame(network_frame, text="🚫 Blocked Networks (Blacklist)")
        blocked_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        ttk.Label(blocked_frame, text="Add IPs or networks that should ALWAYS be blocked:").pack(anchor=tk.W, padx=10, pady=5)
        
        blocked_scroll = ttk.Scrollbar(blocked_frame)
        blocked_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.blocked_networks_text = tk.Text(blocked_frame, height=6, width=50,
                                            yscrollcommand=blocked_scroll.set,
                                            font=("Consolas", 10))
        self.blocked_networks_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        blocked_scroll.config(command=self.blocked_networks_text.yview)
        
        current_blocked = self.config_manager.get_config().blocked_networks
        self.blocked_networks_text.insert(tk.END, '\n'.join(current_blocked))
        
        ttk.Label(blocked_frame, text="Examples: 203.0.113.0/24, 198.51.100.50", 
                foreground="gray").pack(anchor=tk.W, padx=10, pady=2)
        
        # Validation button
        validate_btn_frame = ttk.Frame(network_frame)
        validate_btn_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(validate_btn_frame, text="🔍 Validate Networks", 
                command=self._validate_networks).pack(side=tk.LEFT, padx=5)
        
        self.validation_label = ttk.Label(validate_btn_frame, text="", foreground="blue")
        self.validation_label.pack(side=tk.LEFT, padx=10)

>>>>>>> 85e0e8911306e4ca72b6d358de5d7b08ec72394b
    def save_configuration(self):
        """Save all configuration changes to file only"""
        try:
            # Get values safely
            trusted_networks = [line.strip() for line in self.trusted_networks_text.get('1.0', tk.END).strip().split('\n') if line.strip()]
            blocked_networks = [line.strip() for line in self.blocked_networks_text.get('1.0', tk.END).strip().split('\n') if line.strip()]
            
            # Update configuration object
            cfg = self.config_manager.get_config()
            cfg.firewall_enabled = self.firewall_enabled_var.get()
            cfg.default_action = self.default_action_var.get()
            cfg.log_level = self.log_level_var.get()
            cfg.enable_stateful_inspection = self.stateful_var.get()
            cfg.enable_intrusion_detection = self.intrusion_var.get()
            cfg.enable_dos_protection = self.dos_var.get()
            cfg.trusted_networks = trusted_networks
            cfg.blocked_networks = blocked_networks
            
            # Save to file
            success = self.config_manager.save_configuration()
            
            if success:
                return True
            else:
                return False
                
        except Exception as e:
            return False
    
    def apply_live_configuration(self):
        """Apply configuration changes to firewall immediately"""
        try:
            # Get values safely
            trusted_networks = [line.strip() for line in self.trusted_networks_text.get('1.0', tk.END).strip().split('\n') if line.strip()]
            blocked_networks = [line.strip() for line in self.blocked_networks_text.get('1.0', tk.END).strip().split('\n') if line.strip()]
            
            # Update configuration and save
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
                # Call the callback to apply changes to firewall
                if self.on_save_callback:
                    self.on_save_callback()
                return True
            else:
                return False
                
        except Exception as e:
            return False

    def _on_save(self):
        """Handle Save Configuration button - saves to file only"""
        # Find and disable the save button
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
                messagebox.showinfo("Configuration Saved", "Configuration saved to file successfully!\n\nClick 'Apply Live Config' to apply changes to the firewall.")
            else:
                messagebox.showerror("Configuration", "Failed to save configuration to file.")
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

    def _on_apply_live(self):
        """Handle Apply Live Config button - applies changes to firewall immediately"""
        # Find and disable the apply button
        apply_button = None
        for child in self.parent.winfo_children():
            if isinstance(child, ttk.Frame):
                for subchild in child.winfo_children():
                    if isinstance(subchild, ttk.Button) and subchild.cget('text') == 'Apply Live Config':
                        apply_button = subchild
                        break
        
        if apply_button:
            apply_button.config(state='disabled', text='Applying...')
        
        # Run apply in separate thread
        def apply_worker():
            try:
                success = self.apply_live_configuration()
                # Schedule GUI update on main thread
                self.parent.after(0, lambda: self._on_apply_complete(success, apply_button))
            except Exception as e:
                # Schedule error display on main thread
                self.parent.after(0, lambda: self._on_apply_error(str(e), apply_button))
        
        # Start apply thread
        apply_thread = threading.Thread(target=apply_worker, daemon=True)
        apply_thread.start()
    
    def _on_apply_complete(self, success, apply_button):
        """Handle apply completion on main thread"""
        try:
            if success:
                messagebox.showinfo("Configuration Applied", "Configuration applied to firewall successfully!\n\nChanges are now active and saved to file.")
            else:
                messagebox.showerror("Configuration", "Failed to apply configuration to firewall.")
        finally:
            # Re-enable button
            if apply_button:
                apply_button.config(state='normal', text='Apply Live Config')
    
    def _on_apply_error(self, error_msg, apply_button):
        """Handle apply error on main thread"""
        try:
            messagebox.showerror("Configuration Error", f"Error applying configuration:\n{error_msg}")
        finally:
            # Re-enable button
            if apply_button:
                apply_button.config(state='normal', text='Apply Live Config')