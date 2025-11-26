import tkinter as tk
from tkinter import messagebox, ttk
import hashlib
import os
import json

# File to track first login
FIRST_LOGIN_FILE = "first_login.json"

# Simple credentials store (in production, use a proper database)
VALID_CREDENTIALS = {
    'admin': hashlib.sha256('admin123'.encode()).hexdigest(),
    'guest': hashlib.sha256('guest123'.encode()).hexdigest(),
}

VALID_ROLES = {
    'admin': 'admin',
    'guest': 'guest'
}

def load_first_login_status():
    """Load first login status from file"""
    try:
        if os.path.exists(FIRST_LOGIN_FILE):
            with open(FIRST_LOGIN_FILE, 'r') as f:
                return json.load(f)
        return {'admin': True, 'guest': False}  # admin needs to change password on first login
    except:
        return {'admin': True, 'guest': False}

def save_first_login_status(status):
    """Save first login status to file"""
    try:
        with open(FIRST_LOGIN_FILE, 'w') as f:
            json.dump(status, f)
    except:
        pass

def hash_password(password):
    """Hash a password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def authenticate_user(username, password):
    """
    Authenticate a user with username and password.
    Returns a tuple: (success, message, user_dict, role)
    """
    if username not in VALID_CREDENTIALS:
        return False, "❌ Unknown username.", {"locked": False}, None
    
    password_hash = hash_password(password)
    
    if VALID_CREDENTIALS[username] != password_hash:
        return False, "❌ Incorrect password.", {"locked": False}, None
    
    user_dict = {"role": VALID_ROLES.get(username, 'guest'), "locked": False}
    return True, f"✅ Authentication successful. Welcome {username}!", user_dict, VALID_ROLES.get(username, 'guest')

def ensure_default_users():
    """
    Ensure default users (admin and guest) exist in the credentials store.
    This is called on startup to guarantee these users are available.
    """
    default_users = {
        'admin': hashlib.sha256('admin123'.encode()).hexdigest(),
        'guest': hashlib.sha256('guest123'.encode()).hexdigest(),
    }
    
    # Update VALID_CREDENTIALS with default users if they don't exist
    for username, password_hash in default_users.items():
        if username not in VALID_CREDENTIALS:
            VALID_CREDENTIALS[username] = password_hash
            VALID_ROLES[username] = username

def change_password(username, old_password, new_password):
    """
    Change the password for an existing user.
    Returns True if successful, False otherwise.
    """
    if username not in VALID_CREDENTIALS:
        return False
    
    # Verify old password
    old_password_hash = hash_password(old_password)
    if VALID_CREDENTIALS[username] != old_password_hash:
        return False
    
    # Update password
    new_password_hash = hash_password(new_password)
    VALID_CREDENTIALS[username] = new_password_hash
    return True

def show_change_password_dialog(username):
    """
    Show change password dialog for first-time admin login
    Returns True if password changed successfully, False otherwise
    """
    change_pwd_window = tk.Toplevel()
    change_pwd_window.title("Change Password - Required")
    change_pwd_window.geometry("450x300")
    change_pwd_window.resizable(False, False)
    
    # Center window
    change_pwd_window.update_idletasks()
    x = (change_pwd_window.winfo_screenwidth() // 2) - (change_pwd_window.winfo_width() // 2)
    y = (change_pwd_window.winfo_screenheight() // 2) - (change_pwd_window.winfo_height() // 2)
    change_pwd_window.geometry(f"+{x}+{y}")
    
    # Make it modal
    change_pwd_window.transient()
    change_pwd_window.grab_set()
    change_pwd_window.attributes('-topmost', True)
    
    result = {'success': False}
    
    # Title
    title_frame = ttk.Frame(change_pwd_window)
    title_frame.pack(fill=tk.X, padx=20, pady=20)
    
    title_label = ttk.Label(title_frame, text="⚠️ Change Default Password", 
                            font=("Arial", 14, "bold"))
    title_label.pack()
    
    info_label = ttk.Label(title_frame, 
                          text="For security reasons, you must change your password\nbefore continuing.", 
                          font=("Arial", 9),
                          justify=tk.CENTER)
    info_label.pack(pady=5)
    
    # Form frame
    form_frame = ttk.Frame(change_pwd_window)
    form_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    # Current Password
    ttk.Label(form_frame, text="Current Password:", font=("Arial", 10)).grid(row=0, column=0, sticky=tk.W, pady=10)
    current_pwd_var = tk.StringVar()
    current_pwd_entry = ttk.Entry(form_frame, textvariable=current_pwd_var, width=25, font=("Arial", 10), show="*")
    current_pwd_entry.grid(row=0, column=1, sticky=tk.W, padx=10)
    current_pwd_entry.focus()
    
    # New Password
    ttk.Label(form_frame, text="New Password:", font=("Arial", 10)).grid(row=1, column=0, sticky=tk.W, pady=10)
    new_pwd_var = tk.StringVar()
    new_pwd_entry = ttk.Entry(form_frame, textvariable=new_pwd_var, width=25, font=("Arial", 10), show="*")
    new_pwd_entry.grid(row=1, column=1, sticky=tk.W, padx=10)
    
    # Confirm Password
    ttk.Label(form_frame, text="Confirm Password:", font=("Arial", 10)).grid(row=2, column=0, sticky=tk.W, pady=10)
    confirm_pwd_var = tk.StringVar()
    confirm_pwd_entry = ttk.Entry(form_frame, textvariable=confirm_pwd_var, width=25, font=("Arial", 10), show="*")
    confirm_pwd_entry.grid(row=2, column=1, sticky=tk.W, padx=10)
    
    # Password requirements
    req_frame = ttk.Frame(change_pwd_window)
    req_frame.pack(fill=tk.X, padx=20, pady=5)
    
    req_label = ttk.Label(req_frame, 
                         text="Password Requirements:\n• Minimum 8 characters\n• Cannot be 'admin123'", 
                         font=("Arial", 8),
                         foreground="gray",
                         justify=tk.LEFT)
    req_label.pack(anchor=tk.W)
    
    # Button frame
    button_frame = ttk.Frame(change_pwd_window)
    button_frame.pack(fill=tk.X, padx=20, pady=15)
    
    def validate_and_change():
        current = current_pwd_var.get()
        new_pwd = new_pwd_var.get()
        confirm = confirm_pwd_var.get()
        
        # Validate inputs
        if not current or not new_pwd or not confirm:
            messagebox.showerror("Error", "All fields are required")
            return
        
        # Check if current password is correct
        if hash_password(current) != VALID_CREDENTIALS[username]:
            messagebox.showerror("Error", "Current password is incorrect")
            current_pwd_var.set("")
            current_pwd_entry.focus()
            return
        
        # Check password requirements
        if len(new_pwd) < 8:
            messagebox.showerror("Error", "New password must be at least 8 characters long")
            return
        
        if new_pwd.lower() == 'admin123':
            messagebox.showerror("Error", "Cannot use default password 'admin123'")
            return
        
        # Check if passwords match
        if new_pwd != confirm:
            messagebox.showerror("Error", "New passwords do not match")
            new_pwd_var.set("")
            confirm_pwd_var.set("")
            new_pwd_entry.focus()
            return
        
        # Change password
        if change_password(username, current, new_pwd):
            messagebox.showinfo("Success", "Password changed successfully!")
            result['success'] = True
            change_pwd_window.destroy()
        else:
            messagebox.showerror("Error", "Failed to change password")
    
    def cancel_change():
        if messagebox.askyesno("Cancel", "You must change your password to continue.\nAre you sure you want to cancel?"):
            result['success'] = False
            change_pwd_window.destroy()
    
    change_btn = ttk.Button(button_frame, text="Change Password", command=validate_and_change, width=15)
    change_btn.pack(side=tk.LEFT, padx=5)
    
    cancel_btn = ttk.Button(button_frame, text="Cancel", command=cancel_change, width=15)
    cancel_btn.pack(side=tk.LEFT, padx=5)
    
    # Bind Enter key
    change_pwd_window.bind('<Return>', lambda e: validate_and_change())
    
    # Wait for dialog
    change_pwd_window.wait_window()
    
    return result['success']

def login():
    """
    Display login GUI and return user role ('admin' or 'guest')
    Returns None if user exits without logging in
    """
    # Load first login status
    first_login_status = load_first_login_status()
    
    login_window = tk.Tk()
    login_window.title("Firewall Login")
    login_window.geometry("400x250")
    login_window.resizable(False, False)
    
    # Center window on screen
    login_window.update_idletasks()
    x = (login_window.winfo_screenwidth() // 2) - (login_window.winfo_width() // 2)
    y = (login_window.winfo_screenheight() // 2) - (login_window.winfo_height() // 2)
    login_window.geometry(f"+{x}+{y}")
    
    result = {'role': None, 'cancelled': False}
    
    def on_closing():
        """Handle window close event"""
        result['cancelled'] = True
        login_window.destroy()
    
    # Override window close button
    login_window.protocol("WM_DELETE_WINDOW", on_closing)
    
    # Title
    title_frame = ttk.Frame(login_window)
    title_frame.pack(fill=tk.X, padx=20, pady=20)
    
    title_label = ttk.Label(title_frame, text="Host-Based Firewall", 
                            font=("Arial", 16, "bold"))
    title_label.pack()
    
    subtitle_label = ttk.Label(title_frame, text="Login to continue", 
                               font=("Arial", 10))
    subtitle_label.pack()
    
    # Login form frame
    form_frame = ttk.Frame(login_window)
    form_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    # Username
    ttk.Label(form_frame, text="Username:", font=("Arial", 10)).grid(row=0, column=0, sticky=tk.W, pady=10)
    username_var = tk.StringVar()
    username_entry = ttk.Entry(form_frame, textvariable=username_var, width=25, font=("Arial", 10))
    username_entry.grid(row=0, column=1, sticky=tk.W, padx=10)
    username_entry.focus()
    
    # Password
    ttk.Label(form_frame, text="Password:", font=("Arial", 10)).grid(row=1, column=0, sticky=tk.W, pady=10)
    password_var = tk.StringVar()
    password_entry = ttk.Entry(form_frame, textvariable=password_var, width=25, font=("Arial", 10), show="*")
    password_entry.grid(row=1, column=1, sticky=tk.W, padx=10)
    
    # Button frame with better spacing
    button_frame = ttk.Frame(login_window)
    button_frame.pack(fill=tk.X, padx=20, pady=15)
    
    def perform_login():
        username = username_var.get().strip()
        password = password_var.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        
        success, message, user_dict, role = authenticate_user(username, password)
        
        if not success:
            messagebox.showerror("Login Failed", message)
            password_var.set("")
            password_entry.focus()
            return
        
        # Check if admin first login
        if username == 'admin' and first_login_status.get('admin', True):
            # Hide login window temporarily
            login_window.withdraw()
            
            # Show change password dialog
            password_changed = show_change_password_dialog(username)
            
            if password_changed:
                # Mark admin as having changed password
                first_login_status['admin'] = False
                save_first_login_status(first_login_status)
                
                # Login successful
                result['role'] = role
                login_window.destroy()
            else:
                # User cancelled password change
                messagebox.showwarning("Warning", "You must change your password to continue as admin")
                login_window.deiconify()
                username_var.set("")
                password_var.set("")
                username_entry.focus()
                return
        else:
            # Login successful (guest or admin after first login)
            result['role'] = role
            login_window.destroy()
    
    def perform_exit():
        """Handle exit button click"""
        result['cancelled'] = True
        login_window.destroy()
    
    # Create buttons with explicit width to ensure full text is visible
    login_btn = ttk.Button(button_frame, text="Login", command=perform_login, width=12)
    login_btn.pack(side=tk.LEFT, padx=5)
    
    exit_btn = ttk.Button(button_frame, text="Exit", command=perform_exit, width=12)
    exit_btn.pack(side=tk.LEFT, padx=5)
    
    # Bind Enter key to login
    login_window.bind('<Return>', lambda e: perform_login())
    
    # Keep window on top
    login_window.attributes('-topmost', True)
    
    # Wait for login
    login_window.mainloop()
    
    # Check if user cancelled/closed window
    if result['cancelled'] or result['role'] is None:
        return None  # Return None instead of 'guest'
    
    return result['role']

if __name__ == "__main__":
    # Test the login
    ensure_default_users()
    role = login()
    if role:
        print(f"Logged in as: {role}")
    else:
        print("Login cancelled")