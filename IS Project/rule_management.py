"""
Enhanced Rule Management Module
Professional GUI with click-to-deselect, rule persistence, and live hit counter
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import List, Optional, Dict, Any
import json
import os
from datetime import datetime
from rule_engine import FirewallRule, RuleAction, RuleDirection, Protocol, RuleEngine

class RuleManagementGUI:
    """Enhanced GUI interface for rule management"""
    
    def __init__(self, parent, rule_engine: RuleEngine):
        self.parent = parent
        self.rule_engine = rule_engine
        self.selected_rule = None
        self.last_selected_item = None
        self.auto_refresh_active = True
        
        # Create main frame
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create top toolbar with search
        self._create_toolbar()
        
        # Create rule list
        self._create_rule_list()
        
        # Create rule details frame
        self._create_rule_details()
        
        # Create buttons
        self._create_buttons()
        
        # Load rules
        self._refresh_rule_list()
        
        # Start auto-refresh for hit counters (every 2 seconds)
        self._start_auto_refresh()
    
    def _create_toolbar(self):
        """Create top toolbar with search and filters"""
        toolbar_frame = ttk.Frame(self.frame)
        toolbar_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Search box
        ttk.Label(toolbar_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace('w', lambda *args: self._filter_rules())
        search_entry = ttk.Entry(toolbar_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=(0, 20))
        
        # Filter by status
        ttk.Label(toolbar_frame, text="Status:").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_var = tk.StringVar(value="All")
        filter_combo = ttk.Combobox(toolbar_frame, textvariable=self.filter_var, 
                                    values=["All", "Enabled", "Disabled"], width=10, state='readonly')
        filter_combo.pack(side=tk.LEFT, padx=(0, 20))
        filter_combo.bind('<<ComboboxSelected>>', lambda e: self._filter_rules())
        
        # Auto-refresh toggle
        self.auto_refresh_var = tk.BooleanVar(value=True)
        auto_refresh_check = ttk.Checkbutton(toolbar_frame, text="Auto-Refresh Hit Counter", 
                                            variable=self.auto_refresh_var,
                                            command=self._toggle_auto_refresh)
        auto_refresh_check.pack(side=tk.LEFT, padx=(0, 20))
        
        # Rule count label
        self.rule_count_label = ttk.Label(toolbar_frame, text="Total Rules: 0")
        self.rule_count_label.pack(side=tk.RIGHT)
    
    def _create_rule_list(self):
        """Create rule list treeview with enhanced features"""
        # Rule list frame
        list_frame = ttk.LabelFrame(self.frame, text="Firewall Rules")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=(0, 5), pady=(0, 10))
        
        # Treeview for rules
        columns = ('Priority', 'Name', 'Action', 'Direction', 'Protocol', 'Source', 'Destination', 'Ports', 'Hits', 'Status')
        self.rule_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=12)
        
        # Configure columns with better widths
        column_widths = {
            'Priority': 70,
            'Name': 160,
            'Action': 80,
            'Direction': 90,
            'Protocol': 80,
            'Source': 110,
            'Destination': 110,
            'Ports': 90,
            'Hits': 60,
            'Status': 70
        }
        
        for col in columns:
            self.rule_tree.heading(col, text=col, command=lambda c=col: self._sort_by_column(c))
            self.rule_tree.column(col, width=column_widths.get(col, 100))
        
        # Scrollbars
        vsb = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.rule_tree.yview)
        hsb = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.rule_tree.xview)
        self.rule_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout for scrollbars
        self.rule_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)
        
        # Configure tags for different rule states
        self.rule_tree.tag_configure('disabled', foreground='#888888', background='#f5f5f5')
        self.rule_tree.tag_configure('enabled', foreground='#000000')
        self.rule_tree.tag_configure('allow', background='#e8f5e9')
        self.rule_tree.tag_configure('deny', background='#ffebee')
        self.rule_tree.tag_configure('log', background='#fff9c4')
        self.rule_tree.tag_configure('selected', background='#bbdefb')
        
        # Bind selection with click-to-deselect functionality
        self.rule_tree.bind('<ButtonRelease-1>', self._on_rule_click)
        self.rule_tree.bind('<Double-Button-1>', self._on_rule_double_click)
    
    def _on_rule_click(self, event):
        """Handle rule click with deselect functionality"""
        # Get the item that was clicked
        item = self.rule_tree.identify_row(event.y)
        
        if not item:
            # Clicked on empty space - deselect all
            self.rule_tree.selection_remove(self.rule_tree.selection())
            self._clear_form()
            self.selected_rule = None
            self.last_selected_item = None
            return
        
        # Check if clicking on the same item
        if item == self.last_selected_item:
            # Deselect the item
            self.rule_tree.selection_remove(item)
            self._clear_form()
            self.selected_rule = None
            self.last_selected_item = None
        else:
            # Select the new item
            self.last_selected_item = item
            rule_id = self.rule_tree.item(item)['values'][0]  # Priority is first, but we need ID
            # Find rule by matching all values
            for rule in self.rule_engine.get_all_rules():
                if self._rule_matches_item(rule, item):
                    self._populate_form(rule)
                    self.selected_rule = rule
                    break
    
    def _rule_matches_item(self, rule, item):
        """Check if a rule matches a treeview item"""
        values = self.rule_tree.item(item)['values']
        return (str(rule.priority) == str(values[0]) and 
                rule.name == values[1])
    
    def _on_rule_double_click(self, event):
        """Handle double-click to edit rule"""
        if self.selected_rule:
            self.name_entry.focus_set()
    
    def _sort_by_column(self, col):
        """Sort treeview by column"""
        items = [(self.rule_tree.set(item, col), item) for item in self.rule_tree.get_children('')]
        items.sort()
        
        for index, (val, item) in enumerate(items):
            self.rule_tree.move(item, '', index)
    
    def _filter_rules(self):
        """Filter rules based on search and status filter"""
        search_text = self.search_var.get().lower()
        status_filter = self.filter_var.get()
        
        # Clear current display
        for item in self.rule_tree.get_children():
            self.rule_tree.delete(item)
        
        # Add filtered rules
        visible_count = 0
        for rule in self.rule_engine.get_all_rules():
            # Apply status filter
            if status_filter == "Enabled" and not rule.enabled:
                continue
            elif status_filter == "Disabled" and rule.enabled:
                continue
            
            # Apply search filter
            if search_text:
                searchable = f"{rule.name} {rule.src_ip or ''} {rule.dst_ip or ''} {rule.protocol.value}".lower()
                if search_text not in searchable:
                    continue
            
            self._add_rule_to_tree(rule)
            visible_count += 1
        
        self.rule_count_label.config(text=f"Showing: {visible_count} / {len(self.rule_engine.get_all_rules())}")
    
    def _add_rule_to_tree(self, rule):
        """Add a single rule to the treeview"""
        ports = f"{rule.src_port or 'Any'}:{rule.dst_port or 'Any'}"
        status = '✓ Enabled' if rule.enabled else '✗ Disabled'
        
        # Get hit count
        hit_count = getattr(rule, 'hit_count', 0)
        
        # Determine tags
        tags = []
        if not rule.enabled:
            tags.append('disabled')
        else:
            tags.append('enabled')
        
        if rule.action == RuleAction.ALLOW:
            tags.append('allow')
        elif rule.action == RuleAction.DENY:
            tags.append('deny')
        elif rule.action == RuleAction.LOG:
            tags.append('log')
        
        self.rule_tree.insert('', 'end', values=(
            rule.priority,
            rule.name,
            rule.action.value,
            rule.direction.value,
            rule.protocol.value,
            rule.src_ip or 'Any',
            rule.dst_ip or 'Any',
            ports,
            hit_count,
            status
        ), tags=tuple(tags))
    
    def _create_rule_details(self):
        """Create rule details frame with required field indicators"""
        details_frame = ttk.LabelFrame(self.frame, text="Rule Details")
        details_frame.pack(fill=tk.X, padx=(5, 0), pady=(0, 10))
        
        # Create form fields
        self._create_form_fields(details_frame)
    
    def _create_form_fields(self, parent):
        """Create form fields with required field indicators"""
        # Basic info - Row 1
        basic_frame = ttk.Frame(parent)
        basic_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Name (Required)
        name_label = ttk.Label(basic_frame, text="Name:", foreground='red')
        name_label.grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.name_var = tk.StringVar()
        self.name_entry = ttk.Entry(basic_frame, textvariable=self.name_var, width=30)
        self.name_entry.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        
        # Action (Required)
        action_label = ttk.Label(basic_frame, text="Action:", foreground='red')
        action_label.grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.action_var = tk.StringVar()
        self.action_combo = ttk.Combobox(basic_frame, textvariable=self.action_var, 
                                        values=[action.value for action in RuleAction], 
                                        width=10, state='readonly')
        self.action_combo.grid(row=0, column=3, sticky=tk.W)
        
        # Basic info - Row 2
        # Direction (Required)
        direction_label = ttk.Label(basic_frame, text="Direction:", foreground='red')
        direction_label.grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.direction_var = tk.StringVar()
        self.direction_combo = ttk.Combobox(basic_frame, textvariable=self.direction_var,
                                          values=[direction.value for direction in RuleDirection], 
                                          width=10, state='readonly')
        self.direction_combo.grid(row=1, column=1, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        
        # Protocol (Required)
        protocol_label = ttk.Label(basic_frame, text="Protocol:", foreground='red')
        protocol_label.grid(row=1, column=2, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.protocol_var = tk.StringVar()
        self.protocol_combo = ttk.Combobox(basic_frame, textvariable=self.protocol_var,
                                          values=[protocol.value for protocol in Protocol], 
                                          width=10, state='readonly')
        self.protocol_combo.grid(row=1, column=3, sticky=tk.W, pady=(5, 0))
        
        # Network info
        network_frame = ttk.Frame(parent)
        network_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Source IP (Optional)
        ttk.Label(network_frame, text="Source IP:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.src_ip_var = tk.StringVar()
        self.src_ip_entry = ttk.Entry(network_frame, textvariable=self.src_ip_var, width=20)
        self.src_ip_entry.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        ttk.Label(network_frame, text="(Any if empty)", foreground='gray').grid(row=0, column=2, sticky=tk.W)
        
        # Destination IP (Optional)
        ttk.Label(network_frame, text="Destination IP:").grid(row=0, column=3, sticky=tk.W, padx=(20, 5))
        self.dst_ip_var = tk.StringVar()
        self.dst_ip_entry = ttk.Entry(network_frame, textvariable=self.dst_ip_var, width=20)
        self.dst_ip_entry.grid(row=0, column=4, sticky=tk.W, padx=(0, 5))
        ttk.Label(network_frame, text="(Any if empty)", foreground='gray').grid(row=0, column=5, sticky=tk.W)
        
        # Ports
        ttk.Label(network_frame, text="Source Port:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.src_port_var = tk.StringVar()
        self.src_port_entry = ttk.Entry(network_frame, textvariable=self.src_port_var, width=10)
        self.src_port_entry.grid(row=1, column=1, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        ttk.Label(network_frame, text="(Any if empty)", foreground='gray').grid(row=1, column=2, sticky=tk.W, pady=(5, 0))
        
        ttk.Label(network_frame, text="Destination Port:").grid(row=1, column=3, sticky=tk.W, padx=(20, 5), pady=(5, 0))
        self.dst_port_var = tk.StringVar()
        self.dst_port_entry = ttk.Entry(network_frame, textvariable=self.dst_port_var, width=10)
        self.dst_port_entry.grid(row=1, column=4, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        ttk.Label(network_frame, text="(Any if empty)", foreground='gray').grid(row=1, column=5, sticky=tk.W, pady=(5, 0))
        
        # Additional options
        options_frame = ttk.Frame(parent)
        options_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Priority
        ttk.Label(options_frame, text="Priority:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.priority_var = tk.StringVar(value="100")
        self.priority_entry = ttk.Entry(options_frame, textvariable=self.priority_var, width=10)
        self.priority_entry.grid(row=0, column=1, sticky=tk.W, padx=(0, 10))
        ttk.Label(options_frame, text="(Lower = Higher Priority)", foreground='gray').grid(row=0, column=2, sticky=tk.W, padx=(0, 20))
        
        # Enabled checkbox
        self.enabled_var = tk.BooleanVar(value=True)
        self.enabled_check = ttk.Checkbutton(options_frame, text="Enabled", variable=self.enabled_var)
        self.enabled_check.grid(row=0, column=3, sticky=tk.W)
        
        # Description
        ttk.Label(options_frame, text="Description:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.description_var = tk.StringVar()
        self.description_entry = ttk.Entry(options_frame, textvariable=self.description_var, width=70)
        self.description_entry.grid(row=1, column=1, columnspan=4, sticky=tk.W, pady=(5, 0))
    
    def _create_buttons(self):
        """Create control buttons with better organization"""
        button_frame = ttk.Frame(self.frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Left side - Rule operations
        left_buttons = ttk.Frame(button_frame)
        left_buttons.pack(side=tk.LEFT)
        
        ttk.Button(left_buttons, text="➕ Add Rule", command=self._add_rule).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(left_buttons, text="✏️ Update Rule", command=self._update_rule).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(left_buttons, text="🗑️ Delete Rule", command=self._delete_rule).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(left_buttons, text="🧹 Clear Form", command=self._clear_form).pack(side=tk.LEFT, padx=(0, 5))
        
        # Right side - Import/Export
        right_buttons = ttk.Frame(button_frame)
        right_buttons.pack(side=tk.RIGHT)
        
        ttk.Button(right_buttons, text="📥 Import", command=self._import_rules).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(right_buttons, text="📤 Export", command=self._export_rules).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(right_buttons, text="🔄 Reload", command=self._reload_rules).pack(side=tk.LEFT)
    
    def _start_auto_refresh(self):
        """Start automatic refresh of hit counters"""
        if self.auto_refresh_active and self.auto_refresh_var.get():
            self._update_hit_counters()
            # Schedule next refresh in 2 seconds
            self.parent.after(2000, self._start_auto_refresh)
    
    def _toggle_auto_refresh(self):
        """Toggle auto-refresh on/off"""
        self.auto_refresh_active = self.auto_refresh_var.get()
        if self.auto_refresh_active:
            self._start_auto_refresh()
    
    def _update_hit_counters(self):
        """Update only the hit counter column without full refresh"""
        try:
            for item in self.rule_tree.get_children():
                values = list(self.rule_tree.item(item)['values'])
                rule_name = values[1]  # Name is at index 1
                
                # Find the rule and update hit count
                for rule in self.rule_engine.get_all_rules():
                    if rule.name == rule_name:
                        hit_count = getattr(rule, 'hit_count', 0)
                        values[8] = hit_count  # Hits is at index 8
                        self.rule_tree.item(item, values=values)
                        break
        except Exception as e:
            pass  # Silently handle errors during live update
    
    def _reload_rules(self):
        """Reload rules from persistent storage"""
        self.rule_engine.load_rules_from_file()
        self._refresh_rule_list()
        messagebox.showinfo("Reload Complete", "Rules reloaded from storage.")
    
    def _refresh_rule_list(self):
        """Refresh the rule list display"""
        self._filter_rules()
    
    def _populate_form(self, rule: FirewallRule):
        """Populate form with rule data"""
        self.name_var.set(rule.name)
        self.action_var.set(rule.action.value)
        self.direction_var.set(rule.direction.value)
        self.protocol_var.set(rule.protocol.value)
        self.src_ip_var.set(rule.src_ip or '')
        self.dst_ip_var.set(rule.dst_ip or '')
        self.src_port_var.set(str(rule.src_port) if rule.src_port else '')
        self.dst_port_var.set(str(rule.dst_port) if rule.dst_port else '')
        self.priority_var.set(str(rule.priority))
        self.enabled_var.set(rule.enabled)
        self.description_var.set(rule.description)
    
    def _clear_form(self):
        """Clear form fields"""
        self.name_var.set('')
        self.action_var.set('')
        self.direction_var.set('')
        self.protocol_var.set('')
        self.src_ip_var.set('')
        self.dst_ip_var.set('')
        self.src_port_var.set('')
        self.dst_port_var.set('')
        self.priority_var.set('100')
        self.enabled_var.set(True)
        self.description_var.set('')
        self.selected_rule = None
    
    def _validate_required_fields(self) -> tuple[bool, str]:
        """Validate required fields"""
        if not self.name_var.get().strip():
            return False, "Name is required"
        if not self.action_var.get():
            return False, "Action is required"
        if not self.direction_var.get():
            return False, "Direction is required"
        if not self.protocol_var.get():
            return False, "Protocol is required"
        return True, ""
    
    def _add_rule(self):
        """Add new rule with validation and persistence"""
        # Validate required fields
        valid, error_msg = self._validate_required_fields()
        if not valid:
            messagebox.showerror("Validation Error", error_msg)
            return
        
        try:
            rule = self._create_rule_from_form()
            result = self.rule_engine.add_rule(rule)
            
            if isinstance(result, tuple):
                success, is_duplicate = result
            else:
                success = result
                is_duplicate = False
            
            if is_duplicate:
                messagebox.showerror(
                    "Duplicate Rule", 
                    f"A rule named '{rule.name}' already exists.\n\nPlease use a different name."
                )
            elif success:
                # Save rules to file after adding
                self.rule_engine.save_rules_to_file()
                messagebox.showinfo("Success", f"Rule '{rule.name}' added successfully.")
                self._refresh_rule_list()
                self._clear_form()
            else:
                messagebox.showerror(
                    "Validation Error", 
                    "Failed to add rule. Please check IP addresses and port numbers."
                )
        except ValueError as e:
            messagebox.showerror("Input Error", "Invalid input. Please check all fields.")
        except Exception as e:
            messagebox.showerror("Error", f"Error adding rule: {e}")
    
    def _update_rule(self):
        """Update selected rule with persistence"""
        if not self.selected_rule:
            messagebox.showwarning("No Selection", "Please select a rule to update.")
            return
        
        # Validate required fields
        valid, error_msg = self._validate_required_fields()
        if not valid:
            messagebox.showerror("Validation Error", error_msg)
            return
        
        try:
            rule_data = self._get_form_data()
            if self.rule_engine.update_rule(self.selected_rule.id, **rule_data):
                # Save rules to file after updating
                self.rule_engine.save_rules_to_file()
                messagebox.showinfo("Success", f"Rule '{self.selected_rule.name}' updated successfully.")
                self._refresh_rule_list()
                self.selected_rule = None
                self.last_selected_item = None
                self._clear_form()
            else:
                messagebox.showerror("Error", "Failed to update rule.")
        except Exception as e:
            messagebox.showerror("Error", f"Error updating rule: {e}")
    
    def _delete_rule(self):
        """Delete selected rule with persistence"""
        if not self.selected_rule:
            messagebox.showwarning("No Selection", "Please select a rule to delete.")
            return
        
        if messagebox.askyesno("Confirm Delete", 
                               f"Are you sure you want to delete rule '{self.selected_rule.name}'?\n\nThis action cannot be undone."):
            if self.rule_engine.remove_rule(self.selected_rule.id):
                # Save rules to file after deleting
                self.rule_engine.save_rules_to_file()
                messagebox.showinfo("Success", "Rule deleted successfully.")
                self._refresh_rule_list()
                self._clear_form()
                self.last_selected_item = None
            else:
                messagebox.showerror("Error", "Failed to delete rule.")
    
    def _create_rule_from_form(self) -> FirewallRule:
        """Create rule object from form data"""
        form_data = self._get_form_data()
        return FirewallRule(**form_data)
    
    def _get_form_data(self) -> Dict[str, Any]:
        """Get form data as dictionary"""
        data = {
            'name': self.name_var.get().strip(),
            'action': RuleAction(self.action_var.get()),
            'direction': RuleDirection(self.direction_var.get()),
            'protocol': Protocol(self.protocol_var.get()),
            'enabled': self.enabled_var.get(),
            'priority': int(self.priority_var.get()) if self.priority_var.get() else 100,
            'description': self.description_var.get().strip()
        }
        
        # Optional fields
        src_ip = self.src_ip_var.get().strip()
        if src_ip:
            data['src_ip'] = src_ip
            
        dst_ip = self.dst_ip_var.get().strip()
        if dst_ip:
            data['dst_ip'] = dst_ip
            
        src_port = self.src_port_var.get().strip()
        if src_port:
            data['src_port'] = int(src_port)
            
        dst_port = self.dst_port_var.get().strip()
        if dst_port:
            data['dst_port'] = int(dst_port)
        
        return data
    
    def _import_rules(self):
        """Import rules from JSON file"""
        try:
            filename = filedialog.askopenfilename(
                title="Import Rules",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, 'r') as f:
                    rules_data = json.load(f)
                
                imported = 0
                duplicates = 0
                failed = 0
                
                for rule_data in rules_data:
                    if 'action' in rule_data:
                        rule_data['action'] = RuleAction(rule_data['action'])
                    if 'direction' in rule_data:
                        rule_data['direction'] = RuleDirection(rule_data['direction'])
                    if 'protocol' in rule_data:
                        rule_data['protocol'] = Protocol(rule_data['protocol'])
                    
                    rule = FirewallRule(**rule_data)
                    result = self.rule_engine.add_rule(rule)
                    
                    if isinstance(result, tuple):
                        success, is_duplicate = result
                        if is_duplicate:
                            duplicates += 1
                        elif success:
                            imported += 1
                        else:
                            failed += 1
                    else:
                        if result:
                            imported += 1
                        else:
                            failed += 1
                
                self._refresh_rule_list()
                
                message = f"Import Complete\n\n"
                message += f"✅ Imported: {imported}\n"
                if duplicates > 0:
                    message += f"⚠️ Duplicates skipped: {duplicates}\n"
                if failed > 0:
                    message += f"❌ Failed: {failed}"
                
                messagebox.showinfo("Import Results", message)
        except Exception as e:
            messagebox.showerror("Error", f"Error importing rules: {e}")
    
    def _export_rules(self):
        """Export rules to JSON file"""
        try:
            filename = filedialog.asksaveasfilename(
                title="Export Rules",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            if filename:
                rules_data = []
                for rule in self.rule_engine.get_all_rules():
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
                        'created_at': rule.created_at.isoformat() if rule.created_at else None
                    }
                    rules_data.append(rule_dict)
                
                with open(filename, 'w') as f:
                    json.dump(rules_data, f, indent=2)
                
                messagebox.showinfo("Success", f"Exported {len(rules_data)} rules successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Error exporting rules: {e}")


class RuleManager:
    """Main rule management class"""
    
    def __init__(self, rule_engine: RuleEngine):
        self.rule_engine = rule_engine
        self.gui = None
    
    def show_gui(self, parent=None):
        """Show rule management GUI"""
        if parent is None:
            parent = tk.Tk()
            parent.title("Host-Based Firewall - Rule Manager")
            parent.geometry("1200x700")
            parent.minsize(1000, 600)
        
        self.gui = RuleManagementGUI(parent, self.rule_engine)
        return parent
    
    def get_rule_statistics(self) -> Dict[str, Any]:
        """Get rule statistics"""
        return self.rule_engine.get_rule_statistics()


# For testing
if __name__ == "__main__":
    from rule_engine import RuleEngine
    
    engine = RuleEngine(log_callback=print)
    manager = RuleManager(engine)
    root = manager.show_gui()
    root.mainloop()