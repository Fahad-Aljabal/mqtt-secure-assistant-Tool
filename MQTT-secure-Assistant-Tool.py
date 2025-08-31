import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import subprocess
import re
import os
import logging
from logging.handlers import RotatingFileHandler
import datetime
import threading
import time
import winsound
from collections import deque

# Global variables
mosquitto_exe_path = ""
broker_process = None
alerts_enabled = True

# Alert tracking
access_attempts = deque(maxlen=10)
publish_attempts = deque(maxlen=10)

# ALERT SYSTEM
def trigger_alert(message):
    """Trigger visual and audible alert for security events"""
    if not alerts_enabled:
        return
        
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_entry = f"[{timestamp}] ALERT: {message}\n"
    
    # Updating the alert
    alert_text.config(state="normal")
    alert_text.insert(tk.END, alert_entry)
    alert_text.see(tk.END)
    alert_text.config(state="disabled")
    
    # Flash window
    root.attributes('-topmost', 1)
    root.attributes('-topmost', 0)
    
    # alert trigger 
    try:
        winsound.MessageBeep(winsound.MB_ICONWARNING)
    except:
        pass
    
    # Show alert popup
    alert_window = tk.Toplevel(root)
    alert_window.title("SECURITY ALERT")
    alert_window.geometry("400x200")
    
    tk.Label(alert_window, text="SECURITY ALERT", font=('Arial', 14, 'bold'), fg='red').pack(pady=10)
    tk.Label(alert_window, text=message, wraplength=380).pack(pady=5)
    
    def dismiss():
        alert_window.destroy()
    
    tk.Button(alert_window, text="Dismiss", command=dismiss).pack(pady=10)

def check_alert_thresholds():
    """Check if we've crossed alert thresholds"""
    current_time = time.time()
    
    # Check unauthorized access 
    if len(access_attempts) >= 10:
        time_diff = current_time - access_attempts[0]
        if time_diff <= 10:  # 10 attempts in 10 seconds
            trigger_alert("Excessive unauthorized access attempts detected!")
            access_attempts.clear()  # Reset after alert
    
    # Check denied publish (10 attepmts in 10 seconds and Resting)
    if len(publish_attempts) >= 10:
        time_diff = current_time - publish_attempts[0]
        if time_diff <= 10:  # 10 attempts in 10 seconds
            trigger_alert("Excessive denied publish attempts detected!")
            publish_attempts.clear()  

# PASSWORD Strength Check
def validate_password_strength(password):
    if len(password) < 8:
        return False
    if not re.search(r"[a-z]", password): return False
    if not re.search(r"[A-Z]", password): return False
    if not re.search(r"\d", password): return False
    if not re.search(r"[^\w\s]", password): return False
    return True

#ACL FILE HANDLING
def save_acl_file(username, topic, access, filename):
    """More robust ACL file handling that prevents duplicates"""
    # Remove any existing entries for this user first
    if os.path.exists(filename):
        with open(filename, "r") as f:
            content = f.read()
        pattern = re.compile(r"user " + re.escape(username) + r"\n(?:topic .*\n)*\n?")
        content = pattern.sub("", content)
    else:
        content = ""
    
    # Add new entries
    with open(filename, "w") as f:
        f.write(content)
        f.write(f"user {username}\n")
        for t in topic.split(","):
            t = t.strip()
            if t:
                f.write(f"topic {access} {t}\n")
        f.write("\n")

# PASSWORD FILE OPERATIONS
def generate_password(username, password, passwd_path, pw_file):
    if not os.path.exists(pw_file):
        open(pw_file, "w").close()
    subprocess.run([passwd_path, "-b", pw_file, username, password], check=True)
    log_event("auth", f"User '{username}' created/updated")

#TLS 
def generate_tls_certs(cert_dir, openssl_path):
    os.makedirs(cert_dir, exist_ok=True)
    key_path = os.path.join(cert_dir, "server.key")
    crt_path = os.path.join(cert_dir, "server.crt")
    subprocess.run([
        openssl_path, "req", "-x509", "-nodes", "-days", "365",
        "-newkey", "rsa:2048",
        "-keyout", key_path,
        "-out", crt_path,
        "-subj", "/C=US/ST=State/L=City/O=Company/CN=localhost"
    ], check=True)
    log_event("system", "TLS certificates generated")
    return crt_path, key_path

# CONFIG FILE=
def generate_config_file(password_file, acl_file, crt_path, key_path, filename):
    with open(filename, "w") as f:
        f.write("allow_anonymous false\n")
        f.write(f"password_file {password_file}\n")
        f.write(f"acl_file {acl_file}\n")
        f.write("listener 8883\n")
        f.write(f"certfile {crt_path}\n")
        f.write(f"keyfile {key_path}\n")
        f.write("log_dest file mosquitto.log\n")
        f.write("log_type all\n")
    log_event("system", "Configuration file generated")

# ADDING USER MODIFY
def load_users():
    """Load users from password file into listbox"""
    user_listbox.delete(0, tk.END)
    pw_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "passwordfile")
    if os.path.exists(pw_file):
        with open(pw_file, "r") as f:
            for line in f:
                if ":" in line:
                    user_listbox.insert(tk.END, line.split(":")[0])

def delete_user():
    """Completely remove user and all their topics from both password and ACL files"""
    selected = user_listbox.curselection()
    if not selected:
        messagebox.showwarning("No selection", "Please select a user to delete.")
        return

    username = user_listbox.get(selected[0])
    base_dir = os.path.dirname(os.path.abspath(__file__))
    pw_file = os.path.join(base_dir, "passwordfile")
    acl_file = os.path.join(base_dir, "aclfile")

    try:
        # Remove from password file
        if os.path.exists(pw_file):
            with open(pw_file, "r") as f:
                lines = [line for line in f.readlines() if not line.startswith(f"{username}:")]
            with open(pw_file, "w") as f:
                f.writelines(lines)

        # Remove from ACL
        if os.path.exists(acl_file):
            with open(acl_file, "r") as f:
                content = f.read()
            
            # the user line
            pattern = re.compile(rf"^user {re.escape(username)}\n(?:topic .*\n)*", re.MULTILINE)
            new_content = pattern.sub("", content)
            
            # Remove  double empty lines
            new_content = re.sub(r"\n{3,}", "\n\n", new_content)
            
            with open(acl_file, "w") as f:
                f.write(new_content)

        messagebox.showinfo("Deleted", f"User '{username}' and all related topics deleted.")
        log_event("auth", f"User '{username}' completely deleted from system")
        load_users()
        user_topic_label.config(text=f"User '{username}' deleted.")  # Clear the topics display
    except Exception as e:
        messagebox.showerror("Error", f"Failed to delete user:\n{e}")
        log_event("error", f"Failed to delete user: {str(e)}")

def modify_user():
    """Open window to modify user topics"""
    selected = user_listbox.curselection()
    if not selected:
        messagebox.showwarning("No selection", "Please select a user to modify.")
        return

    username = user_listbox.get(selected[0])
    acl_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aclfile")
    
    # Create modification dialog
    mod_window = tk.Toplevel(root)
    mod_window.title(f"Modify User: {username}")
    mod_window.grab_set()  # Make window modal
    
    # Get current topics
    current_topics = []
    if os.path.exists(acl_file):
        with open(acl_file, "r") as f:
            content = f.read()
        # Find summery topics for this user
        pattern = re.compile(rf"user {re.escape(username)}\n((?:topic .*\n)*)")
        match = pattern.search(content)
        if match:
            current_topics = [line.strip() for line in match.group(1).split("\n") if line.strip()]

    # Topic listbox with scrolling
    tk.Label(mod_window, text=f"Topics for {username}:").pack(pady=5)
    topic_frame = tk.Frame(mod_window)
    topic_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    
    scrollbar = tk.Scrollbar(topic_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    topics_listbox = tk.Listbox(topic_frame, yscrollcommand=scrollbar.set, width=50, height=10)
    for topic in current_topics:
        topics_listbox.insert(tk.END, topic)
    topics_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.config(command=topics_listbox.yview)

    # Add topic section
    tk.Label(mod_window, text="Add New Topic:").pack(pady=(10,0))
    add_frame = tk.Frame(mod_window)
    add_frame.pack(pady=5)
    
    tk.Label(add_frame, text="Topic Path:").grid(row=0, column=0)
    new_topic_entry = tk.Entry(add_frame, width=30)
    new_topic_entry.grid(row=0, column=1)
    
    tk.Label(add_frame, text="Permission:").grid(row=1, column=0)
    new_topic_access = tk.StringVar(value="readwrite")
    tk.OptionMenu(add_frame, new_topic_access, "read", "write", "readwrite").grid(row=1, column=1)
    
    def add_topic():
        topic = new_topic_entry.get().strip()
        if not topic:
            messagebox.showwarning("Input Error", "Topic cannot be empty")
            return
        access = new_topic_access.get()
        topics_listbox.insert(tk.END, f"topic {access} {topic}")
        new_topic_entry.delete(0, tk.END)
    
    tk.Button(add_frame, text="Add Topic", command=add_topic).grid(row=2, columnspan=2, pady=5)

    # Edit  topic
    def edit_topic():
        selected = topics_listbox.curselection()
        if not selected:
            return
            
        topic_line = topics_listbox.get(selected[0])
        if not topic_line.startswith("topic "):
            return
            
        # Parse current permission
        parts = topic_line.split()
        current_permission = parts[1]
        current_topic = " ".join(parts[2:])
        
        # Create edit dialog
        edit_window = tk.Toplevel(mod_window)
        edit_window.title("Edit Topic Permission")
        
        tk.Label(edit_window, text="Topic:").pack()
        tk.Label(edit_window, text=current_topic).pack()
        
        tk.Label(edit_window, text="Permission:").pack()
        edit_access = tk.StringVar(value=current_permission)
        tk.OptionMenu(edit_window, edit_access, "read", "write", "readwrite").pack()
        
        def save_edit():
            new_line = f"topic {edit_access.get()} {current_topic}"
            topics_listbox.delete(selected[0])
            topics_listbox.insert(selected[0], new_line)
            edit_window.destroy()
            
        tk.Button(edit_window, text="Save", command=save_edit).pack()
        tk.Button(edit_window, text="Cancel", command=edit_window.destroy).pack()

    # Remove selected topic
    def remove_topic():
        selected = topics_listbox.curselection()
        if selected:
            topics_listbox.delete(selected[0])
    
    # Button frame for topic actions
    action_frame = tk.Frame(mod_window)
    action_frame.pack(pady=5)
    
    tk.Button(action_frame, text="Edit Permission", command=edit_topic).pack(side=tk.LEFT, padx=5)
    tk.Button(action_frame, text="Remove Topic", command=remove_topic).pack(side=tk.LEFT, padx=5)

    # Save changes
    def save_changes():
        # Remove old user entries
        if os.path.exists(acl_file):
            with open(acl_file, "r") as f:
                content = f.read()
            
            # Remove existing user block
            pattern = re.compile(rf"user {re.escape(username)}\n(?:topic .*\n)*")
            new_content = pattern.sub("", content)
            
            # Add new entries if we have topics
            if topics_listbox.size() > 0:
                new_content += f"user {username}\n"
                for i in range(topics_listbox.size()):
                    new_content += topics_listbox.get(i) + "\n"
                new_content += "\n"
            
            # Clean up empty lines
            new_content = re.sub(r"\n{3,}", "\n\n", new_content)
            
            with open(acl_file, "w") as f:
                f.write(new_content)
        
        messagebox.showinfo("Success", f"User {username} topics updated")
        mod_window.destroy()
        load_users()
        show_user_topics(None)  
    
    tk.Button(mod_window, text="Save Changes", command=save_changes).pack(pady=10)
    tk.Button(mod_window, text="Cancel", command=mod_window.destroy).pack(pady=5)

def show_user_topics(event):
    """Show topics for selected user"""
    selection = user_listbox.curselection()
    if not selection:
        user_topic_label.config(text="No user selected")
        return
    
    username = user_listbox.get(selection[0])
    acl_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aclfile")
    topics = []
    
    if os.path.exists(acl_file):
        with open(acl_file, "r") as f:
            content = f.read()
        
        # find all topics for this user
        pattern = re.compile(rf"user {re.escape(username)}\n((?:topic .*\n)*)")
        match = pattern.search(content)
        if match:
            topics = [line.strip() for line in match.group(1).split("\n") if line.strip()]
    
    if topics:
        user_topic_label.config(text=f"User '{username}' permissions:\n" + "\n".join(topics))
    else:
        user_topic_label.config(text=f"No topics found for user '{username}'.")

def restart_broker():
    """Restart the Mosquitto broker to apply changes"""
    global broker_process
    
    if broker_process:
        try:
            broker_process.terminate()
            broker_process.wait()
            log_event("system", "Broker stopped")
        except Exception as e:
            log_event("error", f"Error stopping broker: {str(e)}")
    
    launch_secure_broker()

#  MAIN CONFIGURATION
def submit():
    """Handle form submission for new user/config"""
    user = entry_user.get()
    pw = entry_pw.get()
    if not validate_password_strength(pw):
        messagebox.showwarning("Weak Password", "Password must be at least 8 characters and include uppercase, lowercase, digit, and symbol.")
        return
    topic = entry_topic.get()
    access = var_access.get()
    passwd_path = passwd_path_entry.get()
    tls_mode = tls_mode_var.get()

    if not user or not pw or not topic or not passwd_path:
        messagebox.showwarning("Input error", "All fields must be filled.")
        return

    base_dir = os.path.dirname(os.path.abspath(__file__))
    openssl_path = os.path.join(base_dir, "openssl", "openssl.exe")
    tls_dir = os.path.join(base_dir, "tls")
    pw_file = os.path.join(base_dir, "passwordfile")
    acl_file = os.path.join(base_dir, "aclfile")
    conf_file = os.path.join(base_dir, "mosquitto.conf")

    if tls_mode == "generate":
        if not os.path.exists(openssl_path):
            messagebox.showerror("Error", "OpenSSL not found in ./openssl/. Place openssl.exe there.")
            return
        try:
            crt_path, key_path = generate_tls_certs(tls_dir, openssl_path)
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to generate TLS certs:\n{e}")
            log_event("error", f"Failed to generate TLS certs: {str(e)}")
            return
    else:
        crt_path = certfile_entry.get()
        key_path = keyfile_entry.get()
        if not crt_path or not key_path:
            messagebox.showerror("Error", "Please select both certificate and key files.")
            return
        if not os.path.exists(crt_path) or not os.path.exists(key_path):
            messagebox.showerror("Error", "Selected certificate or key file does not exist.")
            return

    try:
        generate_password(user, pw, passwd_path, pw_file)
        save_acl_file(user, topic, access, acl_file)
        generate_config_file(pw_file, acl_file, crt_path, key_path, conf_file)
        messagebox.showinfo("Success", f"User '{user}' added.\nMosquitto config with TLS generated.")
        load_users()
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to process:\n{e}")
        log_event("error", f"Failed to process user creation: {str(e)}")

# FILE FUNCTIONS
def browse_passwd():
    path = filedialog.askopenfilename(title="Select mosquitto_passwd.exe")
    passwd_path_entry.delete(0, tk.END)
    passwd_path_entry.insert(0, path)

def browse_certfile():
    path = filedialog.askopenfilename(title="Select Certificate File (.crt)")
    certfile_entry.delete(0, tk.END)
    certfile_entry.insert(0, path)

def browse_keyfile():
    path = filedialog.askopenfilename(title="Select Private Key File (.key)")
    keyfile_entry.delete(0, tk.END)
    keyfile_entry.insert(0, path)

def toggle_tls_inputs():
    """Toggle TLS input fields based on selection"""
    state = "normal" if tls_mode_var.get() == "provide" else "disabled"
    certfile_entry.config(state=state)
    keyfile_entry.config(state=state)
    browse_cert_btn.config(state=state)
    browse_key_btn.config(state=state)

# BROKER MANAGEMENT
def set_mosquitto_exe():
    """Set path to mosquitto executable"""
    global mosquitto_exe_path
    mosquitto_exe_path = filedialog.askopenfilename(title="Select mosquitto.exe")
    log_event("system", f"Mosquitto executable set to: {mosquitto_exe_path}")

def launch_secure_broker():
    """Launch the MQTT broker with secure configuration"""
    global mosquitto_exe_path, broker_process
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    conf_file = os.path.join(base_dir, "mosquitto.conf")
    pw_file = os.path.join(base_dir, "passwordfile")
    acl_file = os.path.join(base_dir, "aclfile")

    if not mosquitto_exe_path:
        messagebox.showerror("Error", "Mosquitto executable path not set.")
        return
    if not os.path.exists(conf_file):
        messagebox.showerror("Error", "mosquitto.conf not found.")
        return
    if not os.path.exists(pw_file) or os.path.getsize(pw_file) == 0:
        messagebox.showerror("Error", "Password file missing or empty.")
        return
    if not os.path.exists(acl_file) or os.path.getsize(acl_file) == 0:
        messagebox.showerror("Error", "ACL file missing or empty.")
        return

    try:
        #  broker launch command
        broker_process = subprocess.Popen(
            [mosquitto_exe_path, '-v', '-c', conf_file],
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
        
        # Start monitoring
        threading.Thread(
            target=monitor_log_file,
            args=(os.path.join(base_dir, "mosquitto.log"),),
            daemon=True
        ).start()
        
        messagebox.showinfo("Success", "Mosquitto broker launched securely in new console window.")
        log_event("system", "Mosquitto broker started with full logging")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to launch Mosquitto:\n{e}")
        log_event("error", f"Failed to launch Mosquitto: {str(e)}")

def monitor_log_file(log_file_path):
    """Monitor the Mosquitto log file for events"""
    try:
        
        while not os.path.exists(log_file_path):
            time.sleep(0.5)
        
        
        with open(log_file_path, 'r') as f:
            
            f.seek(0, 2)
            
            while True:
                line = f.readline()
                if line:
                    process_broker_line(line)
                else:
                    time.sleep(0.1)
    except Exception as e:
        log_event("error", f"Log monitoring error: {str(e)}")

def process_broker_line(line):
    """Process a line from the broker log"""
    try:
        line = line.strip()
        if not line:
            return
        
        current_time = time.time()
        
        
        if "New connection from" in line:
            client = line.split('New connection from ')[1].split(' ')[0]
            log_event("auth", f"New connection: {client}")
            
        elif "not authorised" in line:
            client = line.split('Client ')[1].split(' ')[0]
            log_event("auth", f"Unauthorized access attempt: {client}")
            access_attempts.append(current_time)
            check_alert_thresholds()
                
        elif "Denied PUBLISH" in line:
            topic = line.split("'")[1] if "'" in line else "unknown"
            log_event("pub", f"Publish denied on topic '{topic}'")
            publish_attempts.append(current_time)
            check_alert_thresholds()
                
        elif "Denied SUBSCRIBE" in line:
            topic = line.split("'")[1] if "'" in line else "unknown"
            log_event("sub", f"Subscribe denied on topic '{topic}'")
                
        elif "Received PUBLISH" in line:
            client_match = re.search(r"Received PUBLISH from (.+?)(?:\s|$)", line)
            client_id = client_match.group(1) if client_match else "unknown"
            log_event("pub", f"Received publish from {client_id}")
            
    except Exception as e:
        log_event("error", f"Error processing log line: {str(e)}")

# CREATE ALERTS TAB
def create_alerts_tab():
    """Create the alerts tab with controls"""
    alerts_tab = ttk.Frame(tabs)
    tabs.add(alerts_tab, text="Alerts")
    
    # Alert viewer
    ttk.Label(alerts_tab, text="Security Alerts:").pack(pady=(10, 5))
    
    global alert_text
    alert_text = tk.Text(alerts_tab, height=15, width=70, state="disabled", bg="white")
    alert_text.pack(padx=10, pady=5)
    
    # Control frame
    control_frame = ttk.Frame(alerts_tab)
    control_frame.pack(pady=5)
    
    # Clear alerts button
    ttk.Button(control_frame, text="Clear Alerts", command=lambda: clear_alerts(alert_text)).pack(side=tk.LEFT, padx=5)
    
    # Alert toggle button
    global alert_toggle_btn
    alert_toggle_btn = ttk.Button(control_frame, text=f"Alerts: {'ON' if alerts_enabled else 'OFF'}", 
                                command=toggle_alerts)
    alert_toggle_btn.pack(side=tk.LEFT, padx=5)
    
    return alert_text

def clear_alerts(alert_widget):
    """Clear the alerts display"""
    alert_widget.config(state="normal")
    alert_widget.delete(1.0, tk.END)
    alert_widget.config(state="disabled")

# MODIFIED LOGGING TAB
def create_logging_tab():
    """Create the logging tab with controls"""
    logs_tab = ttk.Frame(tabs)
    tabs.add(logs_tab, text="Logs")
    
    
    ttk.Label(logs_tab, text="All Events:").pack(pady=(10, 5))
    log_text = tk.Text(logs_tab, height=15, width=70, state="disabled", bg="white")
    log_text.pack(padx=10, pady=5)
    
    
    control_frame = ttk.Frame(logs_tab)
    control_frame.pack(pady=5)
    
    
    ttk.Button(control_frame, text="Clear Logs", command=lambda: clear_logs(log_text)).pack(side=tk.LEFT, padx=5)
    
    
    ttk.Button(control_frame, text="Save Logs to File", command=save_logs_to_file).pack(side=tk.LEFT, padx=5)
    
    return log_text
# LOGGING SYSTEM
def log_event(event_type, message):
    """Log an event based on user's selection"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {event_type.upper()}: {message}\n"
    
    # Always log to file
    logger.info(f"{event_type.upper()}: {message}")
    
    # Update the log text widget
    log_text.config(state="normal")
    log_text.insert(tk.END, log_entry)
    log_text.see(tk.END)
    log_text.config(state="disabled")

def create_logging_tab():
    """Create the logging tab with controls"""
    logs_tab = ttk.Frame(tabs)
    tabs.add(logs_tab, text="Logs")
    
    # Log viewer
    ttk.Label(logs_tab, text="Security Events (Access and Publish Status):").pack(pady=(10, 5))
    log_text = tk.Text(logs_tab, height=15, width=70, state="disabled")
    log_text.pack(padx=10, pady=5)
    
    # Clear logs button
    ttk.Button(logs_tab, text="Clear Logs", command=lambda: clear_logs(log_text)).pack(pady=5)
    
    # Save logs to file button
    ttk.Button(logs_tab, text="Save Logs to File", command=save_logs_to_file).pack(pady=5)
    
    return log_text

def clear_logs(log_widget):
    """Clear the log display"""
    log_widget.config(state="normal")
    log_widget.delete(1.0, tk.END)
    log_widget.config(state="disabled")

def save_logs_to_file():
    """Save logs to a file"""
    file_path = filedialog.asksaveasfilename(
        defaultextension=".log",
        filetypes=[("Log files", "*.log"), ("All files", "*.*")]
    )
    if file_path:
        try:
            with open(file_path, "w") as f:
                f.write(log_text.get(1.0, tk.END))
            messagebox.showinfo("Success", f"Logs saved to {file_path}")
            log_event("system", f"Logs saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save logs: {str(e)}")
            log_event("error", f"Failed to save logs: {str(e)}")

# MAIN GUI SETUP
root = tk.Tk()
root.title("MQTT Secure Assistant")
root.geometry("800x600")

# Style configuration
style = ttk.Style()
style.configure('TFrame', background='#f0f0f0')
style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
style.configure('TButton', font=('Arial', 10), padding=5)
style.configure('TNotebook', background='#f0f0f0')
style.configure('TNotebook.Tab', font=('Arial', 10, 'bold'), padding=[10, 5])

# Main container
main_frame = ttk.Frame(root)
main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Notebook (tabs)
tabs = ttk.Notebook(main_frame)
config_tab = ttk.Frame(tabs)
users_tab = ttk.Frame(tabs)
tabs.add(config_tab, text="Config Generator")
tabs.add(users_tab, text="User Management")

# Create logging and alerts tabs
log_text = create_logging_tab()
def toggle_alerts():
    """Toggle alert system on/off"""
    global alerts_enabled
    alerts_enabled = not alerts_enabled
    new_text = f"Alerts: {'ON' if alerts_enabled else 'OFF'}"
    alert_toggle_btn.config(text=new_text)

alert_text = create_alerts_tab()
tabs.pack(expand=1, fill="both")


# Setup logging
logger = logging.getLogger('mqtt_broker')
logger.setLevel(logging.INFO)
handler = RotatingFileHandler('mqtt_broker.log', maxBytes=1000000, backupCount=5)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Config tab widgets
config_frame = ttk.Frame(config_tab)
config_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# User credentials frame
cred_frame = ttk.LabelFrame(config_frame, text="User Credentials", padding=10)
cred_frame.grid(row=0, column=0, sticky="ew", pady=5)

ttk.Label(cred_frame, text="publisher/subscriber").grid(row=0, column=0, sticky="w", pady=2)
entry_user = ttk.Entry(cred_frame)
entry_user.grid(row=0, column=1, sticky="ew", pady=2)

ttk.Label(cred_frame, text="Password").grid(row=1, column=0, sticky="w", pady=2)
entry_pw = ttk.Entry(cred_frame, show="*")
entry_pw.grid(row=1, column=1, sticky="ew", pady=2)

ttk.Label(cred_frame, text="Topic").grid(row=2, column=0, sticky="w", pady=2)
entry_topic = ttk.Entry(cred_frame)
entry_topic.grid(row=2, column=1, sticky="ew", pady=2)

ttk.Label(cred_frame, text="Access").grid(row=3, column=0, sticky="w", pady=2)
var_access = tk.StringVar(value="readwrite")
access_menu = ttk.OptionMenu(cred_frame, var_access, "readwrite", "read", "write", "readwrite")
access_menu.grid(row=3, column=1, sticky="ew", pady=2)

# Tools frame
tools_frame = ttk.LabelFrame(config_frame, text="Tools Paths", padding=10)
tools_frame.grid(row=1, column=0, sticky="ew", pady=5)

ttk.Label(tools_frame, text="mosquitto_passwd Path").grid(row=0, column=0, sticky="w", pady=2)
passwd_path_entry = ttk.Entry(tools_frame)
passwd_path_entry.grid(row=0, column=1, sticky="ew", pady=2)
ttk.Button(tools_frame, text="Browse", command=browse_passwd).grid(row=0, column=2, padx=5)

# TLS frame
tls_frame = ttk.LabelFrame(config_frame, text="TLS Configuration", padding=10)
tls_frame.grid(row=2, column=0, sticky="ew", pady=5)

ttk.Label(tls_frame, text="TLS Mode").grid(row=0, column=0, sticky="w", pady=2)
tls_mode_var = tk.StringVar(value="generate")
ttk.Radiobutton(tls_frame, text="Auto-generate TLS Certs", variable=tls_mode_var, value="generate", command=toggle_tls_inputs).grid(row=0, column=1, sticky="w", pady=2)
ttk.Radiobutton(tls_frame, text="Use existing TLS Certs", variable=tls_mode_var, value="provide", command=toggle_tls_inputs).grid(row=1, column=1, sticky="w", pady=2)

ttk.Label(tls_frame, text="Certificate (.crt)").grid(row=2, column=0, sticky="w", pady=2)
certfile_entry = ttk.Entry(tls_frame, state="disabled")
certfile_entry.grid(row=2, column=1, sticky="ew", pady=2)
browse_cert_btn = ttk.Button(tls_frame, text="Browse", command=browse_certfile, state="disabled")
browse_cert_btn.grid(row=2, column=2, padx=5)

ttk.Label(tls_frame, text="Private Key (.key)").grid(row=3, column=0, sticky="w", pady=2)
keyfile_entry = ttk.Entry(tls_frame, state="disabled")
keyfile_entry.grid(row=3, column=1, sticky="ew", pady=2)
browse_key_btn = ttk.Button(tls_frame, text="Browse", command=browse_keyfile, state="disabled")
browse_key_btn.grid(row=3, column=2, padx=5)

# buttons
action_frame = ttk.Frame(config_frame)
action_frame.grid(row=3, column=0, sticky="ew", pady=10)

ttk.Button(action_frame, text="Add User & Secure Config", command=submit).pack(side=tk.LEFT, padx=5)
ttk.Button(action_frame, text="Set Mosquitto Executable", command=set_mosquitto_exe).pack(side=tk.LEFT, padx=5)
ttk.Button(action_frame, text="Launch Broker Securely", command=launch_secure_broker).pack(side=tk.LEFT, padx=5)

# Users tab widgets
users_frame = ttk.Frame(users_tab)
users_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

ttk.Label(users_frame, text="publisher/subscriber:").pack(anchor="w")
user_listbox = tk.Listbox(users_frame, width=40, height=10, font=('Arial', 10))
user_listbox.pack(fill=tk.BOTH, expand=True, pady=5)

# Button frame
button_frame = ttk.Frame(users_frame)
button_frame.pack(fill=tk.X, pady=5)

ttk.Button(button_frame, text="Delete publisher/subscriber", command=delete_user).pack(side=tk.LEFT, padx=5)
ttk.Button(button_frame, text="Modify User", command=modify_user).pack(side=tk.LEFT, padx=5)
ttk.Button(button_frame, text="Restart Broker", command=restart_broker).pack(side=tk.LEFT, padx=5)

user_topic_label = ttk.Label(users_frame, text="Select a user to view/modify their topics", 
                           wraplength=350, justify="left")
user_topic_label.pack(pady=5)

user_listbox.bind("<<ListboxSelect>>", show_user_topics)

# Initial setup
load_users()
log_event("system", "MQTT Secure Configurator started")

root.mainloop()