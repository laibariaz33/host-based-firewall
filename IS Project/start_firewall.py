#!/usr/bin/env python3
"""
Startup script for the Enhanced Host-Based Firewall
Handles initialization, authentication, and role-based access control
"""

import sys
import os
import traceback

# 🔐 Import authentication system
#from auth_system import authenticate_user, ensure_default_users
'''
def login():
    """Console-based user login before starting the firewall"""
    ensure_default_users()
    print("=== Firewall Login ===")
    username = input("Username: ")
    password = input("Password: ")

    success, message, role = authenticate_user(username, password)
    print(message)
    if not success:
        input("Press Enter to exit...")
        sys.exit(1)
    return role
    '''


def check_requirements():
    """Check if all required modules are available"""
    try:
        import tkinter
        print("✓ Tkinter available")
    except ImportError:
        print("❌ Tkinter not available. Please install tkinter.")
        return False
    
    try:
        import pydivert
        print("✓ PyDivert available")
    except ImportError:
        print("❌ PyDivert not available. Please install: pip install pydivert==2.1.0")
        return False
    
    try:
        import psutil
        print("✓ Psutil available")
    except ImportError:
        print("❌ Psutil not available. Please install: pip install psutil")
        return False
    
    return True


def check_permissions():
    """Check if running with appropriate permissions"""
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if is_admin:
            print("✓ Running with Administrator privileges")
        else:
            print("⚠️  Not running as Administrator - some features may be limited")
        return True
    except:
        print("⚠️  Could not check administrator status")
        return True


def main():
    """Main startup function"""
    print("=== Enhanced Host-Based Firewall Startup ===")

    # 🧠 Step 1: User Authentication
    #role = login()
    #print(f"Logged in as: {role.upper()}")

    # 🧩 Step 2: System checks
    print("\nChecking system requirements...\n")
    if not check_requirements():
        print("\n❌ Missing requirements. Please install missing dependencies.")
        input("Press Enter to exit...")
        return

    # 🛡️ Step 3: Permissions check
    check_permissions()

    print("\nStarting Enhanced Host-Based Firewall...")

    try:
        from firewall import EnhancedFirewallGUI
        import tkinter as tk
        from rule_engine import RuleEngine, RuleAction  # <-- import here

        # Initialize the rule engine with a logger
        def logger(msg):
            print(msg)

        engine = RuleEngine(log_callback=logger)
        engine.set_default_action(RuleAction.DENY)

        # Create main GUI window
        root = tk.Tk()
        gui = EnhancedFirewallGUI(root)

        # ⚙️ Step 4: Apply role-based access control
        if role != "admin":
            print("⚠️ Limited access: You can only view logs and statistics.")
            try:
                # Disable rule modification buttons (if they exist in GUI)
                if hasattr(gui, "add_rule_button"):
                    gui.add_rule_button.config(state="disabled")
                if hasattr(gui, "delete_rule_button"):
                    gui.delete_rule_button.config(state="disabled")
            except:
                pass

        print("✓ Firewall GUI initialized successfully")
        print("✓ Application is ready to use")
        print("\nNote: Run as Administrator for full packet capture functionality")

        # Start GUI loop
        root.mainloop()

    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Please ensure all modules are in the same directory")
        input("Press Enter to exit...")

    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        print("\nFull error details:")
        traceback.print_exc()
        input("Press Enter to exit...")


if __name__ == "__main__":
    main()
