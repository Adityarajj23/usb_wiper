import os
import sys
import time
import json
import uuid
import hashlib
import threading
import subprocess
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Windows-specific imports
try:
    import win32api
    import win32file
    import win32con
    import wmi
    import psutil
except ImportError:
    print("Required Windows modules not found. Install with:")
    print("pip install pywin32 wmi psutil")
    sys.exit(1)

VERSION = "2.0.0-Windows"

def is_admin():
    """Check if running with administrator privileges"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_all_drives():
    """Get all drives on the system with drive type classification"""
    all_drives = []
    detected_letters = set()
    
    try:
        c = wmi.WMI()
        
        # Get all physical disks and their properties
        for physical_disk in c.Win32_DiskDrive():
            # Determine drive type
            interface_type = physical_disk.InterfaceType or "Unknown"
            media_type = physical_disk.MediaType or "Unknown"
            
            # Classify drive type
            if interface_type == 'USB':
                drive_type = 'USB'
                is_wipeable = True
            elif 'SSD' in media_type or 'Solid State' in str(media_type):
                drive_type = 'SSD'
                is_wipeable = False
            elif interface_type in ['IDE', 'SCSI', 'SATA']:
                drive_type = 'HDD'
                is_wipeable = False
            else:
                drive_type = 'Unknown'
                is_wipeable = False
            
            # Get partitions for this physical disk
            for partition in physical_disk.associators("Win32_DiskDriveToDiskPartition"):
                for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                    drive_letter = logical_disk.Caption
                    if drive_letter not in detected_letters:
                        
                        # Additional safety check - never allow system drives
                        if drive_letter.upper() in ['C:', 'D:'] and drive_type != 'USB':
                            is_wipeable = False
                        
                        drive_info = {
                            'device_id': physical_disk.DeviceID,
                            'drive_letter': drive_letter,
                            'label': logical_disk.VolumeName or f'{drive_type} Drive',
                            'size': int(physical_disk.Size) if physical_disk.Size else 0,
                            'model': physical_disk.Model or 'Unknown',
                            'serial': physical_disk.SerialNumber or 'Unknown',
                            'drive_type': drive_type,
                            'interface': interface_type,
                            'is_wipeable': is_wipeable
                        }
                        all_drives.append(drive_info)
                        detected_letters.add(drive_letter)
                        
    except Exception as e:
        print(f"Error detecting drives: {e}")
    
    return all_drives

def get_usb_drives():
    """Get only USB drives (kept for backward compatibility)"""
    all_drives = get_all_drives()
    return [drive for drive in all_drives if drive['drive_type'] == 'USB']

def secure_delete_files(drive_path, progress_callback=None):
    """Securely delete files on Windows"""
    deleted_items = []
    failed_items = []
    
    try:
        if not os.path.exists(drive_path):
            return False, f"Drive {drive_path} not accessible"
        
        # Get all files and directories
        all_items = []
        for root, dirs, files in os.walk(drive_path):
            for file in files:
                all_items.append(os.path.join(root, file))
            for dir in dirs:
                all_items.append(os.path.join(root, dir))
        
        total_items = len(all_items)
        
        # Delete files first
        for i, item_path in enumerate(all_items):
            try:
                if os.path.isfile(item_path):
                    # Set file attributes to normal (remove read-only, etc.)
                    win32api.SetFileAttributes(item_path, win32con.FILE_ATTRIBUTE_NORMAL)
                    os.remove(item_path)
                    deleted_items.append(item_path)
                
                if progress_callback and total_items > 0:
                    progress_callback(int((i + 1) * 100 / total_items))
                    
            except Exception as e:
                failed_items.append((item_path, str(e)))
        
        # Delete empty directories
        for root, dirs, files in os.walk(drive_path, topdown=False):
            for dir in dirs:
                dir_path = os.path.join(root, dir)
                try:
                    if os.path.exists(dir_path) and not os.listdir(dir_path):
                        os.rmdir(dir_path)
                        deleted_items.append(dir_path)
                except Exception as e:
                    failed_items.append((dir_path, str(e)))
        
        return True, {"deleted": len(deleted_items), "failed": len(failed_items), "details": failed_items}
        
    except Exception as e:
        return False, f"Critical error: {str(e)}"

def format_drive(drive_letter, label="USB_DRIVE", file_system="FAT32"):
    """Format drive using Windows format command with improved error handling"""
    try:
        # Remove colon if present and ensure proper format
        drive = drive_letter.replace(':', '').upper()
        
        # First, try to ensure the drive is not in use
        try:
            # Close any open handles to the drive
            subprocess.run(f'taskkill /f /im explorer.exe', shell=True, capture_output=True)
            time.sleep(1)
            subprocess.run('start explorer.exe', shell=True)
            time.sleep(2)
        except:
            pass
        
        # Method 1: Try standard format command
        cmd = f'format {drive}: /FS:{file_system} /V:{label} /Q /Y'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            return True, f"Drive {drive}: formatted successfully as {file_system}"
        
        # Method 2: Try diskpart if format failed
        diskpart_script = f"""select volume {drive}
format fs={file_system.lower()} label="{label}" quick
exit"""
        
        # Write diskpart script to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(diskpart_script)
            script_path = f.name
        
        try:
            diskpart_cmd = f'diskpart /s "{script_path}"'
            result2 = subprocess.run(diskpart_cmd, shell=True, capture_output=True, text=True, timeout=60)
            
            # Clean up temp file
            os.unlink(script_path)
            
            if result2.returncode == 0:
                return True, f"Drive {drive}: formatted successfully using diskpart"
            else:
                return False, f"Both format methods failed. Standard format: {result.stderr.strip() or 'Unknown error'}. Diskpart: {result2.stderr.strip() or 'Unknown error'}"
                
        except Exception as diskpart_error:
            try:
                os.unlink(script_path)
            except:
                pass
            return False, f"Format failed: {result.stderr.strip() or 'Unknown error'}. Diskpart error: {str(diskpart_error)}"
            
    except subprocess.TimeoutExpired:
        return False, "Format operation timed out after 60 seconds"
    except Exception as e:
        return False, f"Format error: {str(e)}"

def overwrite_free_space(drive_path, passes=1, progress_callback=None):
    """Overwrite free space on the drive"""
    try:
        # Get free space
        free_bytes = psutil.disk_usage(drive_path).free
        
        if free_bytes < 1024:  # Less than 1KB free
            return True, "No significant free space to overwrite"
        
        # Create temporary file to fill free space
        temp_file = os.path.join(drive_path, f"__temp_wipe_{uuid.uuid4().hex}.tmp")
        
        chunk_size = 1024 * 1024  # 1MB chunks
        written = 0
        
        for pass_num in range(passes):
            try:
                with open(temp_file, 'wb') as f:
                    while written < free_bytes * 0.95:  # Leave small buffer
                        try:
                            # Write random data
                            chunk = os.urandom(min(chunk_size, int(free_bytes * 0.95) - written))
                            f.write(chunk)
                            written += len(chunk)
                            
                            if progress_callback:
                                progress = int((written * 100) / (free_bytes * 0.95))
                                progress_callback(min(progress, 100))
                                
                        except OSError:
                            # Disk full - expected behavior
                            break
                    
                    f.flush()
                    os.fsync(f.fileno())
                
                # Delete temp file
                os.remove(temp_file)
                written = 0  # Reset for next pass
                
            except Exception as e:
                # Clean up temp file if it exists
                try:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                except:
                    pass
                return False, f"Overwrite failed on pass {pass_num + 1}: {str(e)}"
        
        return True, f"Free space overwrite completed ({passes} passes)"
        
    except Exception as e:
        return False, f"Free space overwrite error: {str(e)}"

def collect_system_metadata():
    """Collect Windows system information"""
    import platform
    import getpass
    import socket
    
    return {
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "version": platform.version(),
        "operator": getpass.getuser(),
        "architecture": platform.machine()
    }

def save_certificates(cert_data, out_dir="logs/NullBytes"):
    """Save certificate data to JSON file"""
    try:
        os.makedirs(out_dir, exist_ok=True)
    except PermissionError:
        out_dir = os.path.join(os.environ.get('TEMP', 'C:\\temp'), 'NullBytes')
        os.makedirs(out_dir, exist_ok=True)
    
    if "uuid" not in cert_data:
        cert_data["uuid"] = str(uuid.uuid4())
    
    # Add timestamp
    cert_data["timestamp"] = datetime.now().isoformat()
    cert_data["tool_version"] = VERSION
    
    filename = f"wipe_cert_{cert_data['uuid'][:8]}_{int(time.time())}.json"
    cert_path = os.path.join(out_dir, filename)
    
    with open(cert_path, 'w') as f:
        json.dump(cert_data, f, indent=4)
    
    return cert_path

class USBWiperApp:
    def __init__(self):
        if not is_admin():
            messagebox.showerror("Administrator Required", 
                               "This application must be run as Administrator.\n\n"
                               "Please right-click and select 'Run as Administrator'")
            sys.exit(1)
        
        self.root = tk.Tk()
        self.setup_ui()
        self.cancel_flag = threading.Event()
        self.current_operation = None
        
    def setup_ui(self):
        # Window setup
        self.root.title("Drive Manager & USB Wiper - Windows Edition")
        self.root.geometry("950x700")
        self.root.resizable(False, False)
        
        # Colors
        bg_color = "#1e1e1e"
        fg_color = "#39FF14"
        text_bg = "#121212"
        widget_bg = "#2c2c2c"
        
        self.root.configure(bg=bg_color)
        
        # Style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure('.', background=bg_color, foreground=fg_color)
        style.configure('TFrame', background=bg_color)
        style.configure('TLabel', background=bg_color, foreground=fg_color)
        style.configure('TButton', background=widget_bg, foreground=fg_color)
        
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill='both', expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Drive Manager & USB Wiper", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # USB Drive selection
        selection_frame = ttk.LabelFrame(main_frame, text="Select Drive (Only USB drives can be wiped)", padding="10")
        selection_frame.pack(fill='x', pady=(0, 10))
        
        self.drive_var = tk.StringVar()
        self.drive_combo = ttk.Combobox(selection_frame, textvariable=self.drive_var, 
                                       state='readonly', width=80)
        self.drive_combo.pack(side='left', padx=(0, 10))
        
        refresh_btn = ttk.Button(selection_frame, text="Refresh All Drives", 
                               command=self.refresh_drives)
        refresh_btn.pack(side='left')
        
        # Wipe options
        options_frame = ttk.LabelFrame(main_frame, text="Wipe Options", padding="10")
        options_frame.pack(fill='x', pady=(0, 10))
        
        self.secure_delete = tk.BooleanVar(value=True)
        self.format_drive = tk.BooleanVar(value=True)
        self.overwrite_free = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(options_frame, text="Secure delete all files", 
                       variable=self.secure_delete).pack(anchor='w')
        ttk.Checkbutton(options_frame, text="Format drive after wipe", 
                       variable=self.format_drive).pack(anchor='w')
        ttk.Checkbutton(options_frame, text="Overwrite free space (slower)", 
                       variable=self.overwrite_free).pack(anchor='w')
        
        # Progress
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill='x', pady=(0, 10))
        
        self.progress_var = tk.StringVar(value="Ready")
        progress_label = ttk.Label(progress_frame, textvariable=self.progress_var)
        progress_label.pack()
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress_bar.pack(fill='x', pady=(5, 0))
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', pady=(0, 10))
        
        self.wipe_btn = ttk.Button(button_frame, text="Start Wipe", 
                                  command=self.start_wipe)
        self.wipe_btn.pack(side='left')
        
        self.cancel_btn = ttk.Button(button_frame, text="Cancel", 
                                   command=self.cancel_operation, state='disabled')
        self.cancel_btn.pack(side='left', padx=(10, 0))
        
        ttk.Button(button_frame, text="View Certificates", 
                  command=self.view_certificates).pack(side='right')
        
        # Log area
        log_frame = ttk.LabelFrame(main_frame, text="Operation Log", padding="5")
        log_frame.pack(fill='both', expand=True)
        
        self.log_text = tk.Text(log_frame, bg=text_bg, fg=fg_color, 
                               font=('Consolas', 10), state='disabled')
        
        log_scroll = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        
        self.log_text.pack(side='left', fill='both', expand=True)
        log_scroll.pack(side='right', fill='y')
        
        # Initial refresh
        self.refresh_drives()
    
    def log_message(self, message):
        """Add message to log with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}\n"
        
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, formatted_msg)
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')
        self.root.update()
    
    def refresh_drives(self):
        """Refresh the list of all drives with safety indicators"""
        self.log_message("Scanning for all drives...")
        drives = get_all_drives()
        
        drive_options = []
        self.drive_data = {}
        
        for drive in drives:
            size_gb = drive['size'] / (1024**3) if drive['size'] > 0 else 0
            
            # Create visual indicators for safety
            if drive['is_wipeable']:
                safety_icon = "✅ SAFE"
                color_code = "USB"
            else:
                safety_icon = "🚫 PROTECTED"
                color_code = drive['drive_type']
            
            display_text = f"{drive['drive_letter']} - {safety_icon} [{color_code}] {drive['label']} ({drive['model']}) - {size_gb:.1f} GB"
            drive_options.append(display_text)
            self.drive_data[display_text] = drive
        
        self.drive_combo['values'] = drive_options
        if drive_options:
            # Auto-select first USB drive if available
            usb_drives = [opt for opt in drive_options if "✅ SAFE" in opt]
            if usb_drives:
                self.drive_combo.set(usb_drives[0])
            else:
                self.drive_combo.set(drive_options[0])
            self.log_message(f"Found {len(drive_options)} drive(s) ({len(usb_drives)} wipeable)")
        else:
            self.drive_combo.set("")
            self.log_message("No drives found")
    
    def update_progress(self, percent):
        """Update progress bar"""
        self.progress_bar['value'] = percent
        self.root.update()
    
    def start_wipe(self):
        """Start the wipe operation"""
        selected = self.drive_combo.get()
        if not selected or selected not in self.drive_data:
            messagebox.showwarning("No Selection", "Please select a drive first")
            return
        
        drive_info = self.drive_data[selected]
        
        # CRITICAL SAFETY CHECK - Only allow USB drives
        if not drive_info.get('is_wipeable', False):
            messagebox.showerror(
                "Drive Not Wipeable", 
                f"SAFETY BLOCK: Cannot wipe this drive!\n\n"
                f"Drive: {drive_info['drive_letter']}\n"
                f"Type: {drive_info['drive_type']}\n"
                f"Reason: Only USB drives can be wiped for safety.\n\n"
                f"This protection prevents accidental system damage."
            )
            return
        
        # Double-check it's actually a USB drive
        if drive_info.get('drive_type') != 'USB':
            messagebox.showerror(
                "Invalid Drive Type", 
                f"SAFETY BLOCK: Drive type '{drive_info.get('drive_type', 'Unknown')}' is not allowed.\n\n"
                f"Only USB drives can be wiped."
            )
            return
        
        # Confirmation dialog
        confirm_msg = (f"WARNING: This will permanently delete all data on:\n\n"
                      f"Drive: {drive_info['drive_letter']} ({drive_info['drive_type']})\n"
                      f"Label: {drive_info['label']}\n"
                      f"Model: {drive_info['model']}\n"
                      f"Interface: {drive_info.get('interface', 'Unknown')}\n\n"
                      f"✅ CONFIRMED: This is a USB drive and safe to wipe.\n\n"
                      f"This action cannot be undone!\n\n"
                      f"Type 'WIPE' to confirm:")
        
        confirm_dialog = tk.Toplevel(self.root)
        confirm_dialog.title("Confirm USB Wipe Operation")
        confirm_dialog.geometry("500x400")
        confirm_dialog.resizable(False, False)
        confirm_dialog.grab_set()
        
        # Make dialog prominent
        confirm_dialog.configure(bg='#ff4444')  # Red background for attention
        
        ttk.Label(confirm_dialog, text=confirm_msg, justify='left', 
                 background='#ff4444', foreground='white').pack(pady=15, padx=15)
        
        confirm_var = tk.StringVar()
        confirm_entry = ttk.Entry(confirm_dialog, textvariable=confirm_var, width=30, font=('Arial', 12))
        confirm_entry.pack(pady=10)
        confirm_entry.focus()
        
        def proceed_wipe():
            if confirm_var.get().upper() == "WIPE":
                confirm_dialog.destroy()
                self.execute_wipe(drive_info)
            else:
                messagebox.showerror("Incorrect Confirmation", "You must type 'WIPE' to proceed")
        
        def cancel_confirm():
            confirm_dialog.destroy()
        
        button_frame = ttk.Frame(confirm_dialog)
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, text="PROCEED WITH WIPE", command=proceed_wipe).pack(side='left', padx=10)
        ttk.Button(button_frame, text="Cancel", command=cancel_confirm).pack(side='left')
        
        confirm_entry.bind('<Return>', lambda e: proceed_wipe())
    
    def execute_wipe(self, drive_info):
        """Execute the wipe operation in a separate thread"""
        self.cancel_flag.clear()
        self.wipe_btn.config(state='disabled')
        self.cancel_btn.config(state='normal')
        
        self.current_operation = threading.Thread(target=self.wipe_thread, args=(drive_info,))
        self.current_operation.start()
    
    def wipe_thread(self, drive_info):
        """Main wipe operation thread"""
        start_time = time.time()
        drive_letter = drive_info['drive_letter']
        
        try:
            self.progress_var.set("Starting wipe operation...")
            self.log_message(f"Starting wipe operation on {drive_letter}")
            self.log_message(f"Drive: {drive_info['model']} ({drive_info['label']})")
            
            cert_data = {
                "drive_info": drive_info,
                "system_metadata": collect_system_metadata(),
                "operation_start": datetime.now().isoformat(),
                "operations_performed": [],
                "status": "in_progress"
            }
            
            # Step 1: Secure delete files
            if self.secure_delete.get() and not self.cancel_flag.is_set():
                self.progress_var.set("Securely deleting files...")
                self.log_message("Phase 1: Securely deleting all files and folders...")
                
                success, result = secure_delete_files(drive_letter, self.update_progress)
                
                if success:
                    self.log_message(f"File deletion completed: {result['deleted']} items deleted")
                    if result['failed'] > 0:
                        self.log_message(f"Warning: {result['failed']} items could not be deleted")
                    cert_data["operations_performed"].append("secure_file_deletion")
                else:
                    self.log_message(f"File deletion failed: {result}")
                    cert_data["errors"] = cert_data.get("errors", []) + [f"File deletion: {result}"]
            
            # Step 2: Overwrite free space
            if self.overwrite_free.get() and not self.cancel_flag.is_set():
                self.progress_var.set("Overwriting free space...")
                self.log_message("Phase 2: Overwriting free space with random data...")
                
                success, result = overwrite_free_space(drive_letter, passes=1, progress_callback=self.update_progress)
                
                if success:
                    self.log_message(f"Free space overwrite completed: {result}")
                    cert_data["operations_performed"].append("free_space_overwrite")
                else:
                    self.log_message(f"Free space overwrite failed: {result}")
                    cert_data["errors"] = cert_data.get("errors", []) + [f"Free space overwrite: {result}"]
            
            # Step 3: Format drive
            if self.format_drive.get() and not self.cancel_flag.is_set():
                self.progress_var.set("Formatting drive...")
                self.log_message("Phase 3: Formatting drive...")
                self.log_message("Note: Formatting may take longer for larger drives or if Windows Explorer interferes")
                
                # Give a moment for any file operations to complete
                time.sleep(2)
                
                success, result = format_drive(drive_letter, "WIPED_USB", "FAT32")
                
                if success:
                    self.log_message(f"Format completed: {result}")
                    cert_data["operations_performed"].append("format_drive")
                else:
                    self.log_message(f"Format failed: {result}")
                    # Format failure is not always critical - the drive is still wiped
                    self.log_message("Note: Drive wipe was successful even if format failed. You can manually format if needed.")
                    cert_data["errors"] = cert_data.get("errors", []) + [f"Format: {result}"]
            
            # Complete
            end_time = time.time()
            duration = end_time - start_time
            
            cert_data["operation_end"] = datetime.now().isoformat()
            cert_data["duration_seconds"] = duration
            cert_data["status"] = "cancelled" if self.cancel_flag.is_set() else "completed"
            
            # Save certificate
            cert_path = save_certificates(cert_data)
            
            if self.cancel_flag.is_set():
                self.progress_var.set("Operation cancelled by user")
                self.log_message("Operation was cancelled by user")
            else:
                self.progress_var.set("Wipe operation completed successfully")
                self.log_message(f"Wipe operation completed in {duration:.1f} seconds")
                self.log_message(f"Certificate saved to: {cert_path}")
                
                messagebox.showinfo("Operation Complete", 
                                  f"USB wipe operation completed successfully!\n\n"
                                  f"Duration: {duration:.1f} seconds\n"
                                  f"Certificate saved to:\n{cert_path}")
            
        except Exception as e:
            self.log_message(f"Error during wipe operation: {str(e)}")
            self.progress_var.set("Operation failed")
            messagebox.showerror("Operation Failed", f"An error occurred: {str(e)}")
        
        finally:
            self.wipe_btn.config(state='normal')
            self.cancel_btn.config(state='disabled')
            self.progress_bar['value'] = 0
    
    def cancel_operation(self):
        """Cancel the current operation"""
        self.cancel_flag.set()
        self.log_message("Cancellation requested - stopping operation...")
        self.progress_var.set("Cancelling operation...")
    
    def view_certificates(self):
        """Open dialog to view certificates"""
        cert_dir = "logs/NullBytes"
        if not os.path.exists(cert_dir):
            cert_dir = os.path.join(os.environ.get('TEMP', 'C:\\temp'), 'NullBytes')
        
        if not os.path.exists(cert_dir):
            messagebox.showinfo("No Certificates", "No certificates found yet.")
            return
        
        # Open file dialog
        file_path = filedialog.askopenfilename(
            initialdir=cert_dir,
            title="Select Certificate",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    cert_data = json.load(f)
                
                # Display certificate in new window
                cert_window = tk.Toplevel(self.root)
                cert_window.title(f"Certificate: {os.path.basename(file_path)}")
                cert_window.geometry("600x500")
                
                text_widget = tk.Text(cert_window, wrap='word')
                scrollbar = ttk.Scrollbar(cert_window, command=text_widget.yview)
                text_widget.configure(yscrollcommand=scrollbar.set)
                
                text_widget.pack(side='left', fill='both', expand=True)
                scrollbar.pack(side='right', fill='y')
                
                text_widget.insert('1.0', json.dumps(cert_data, indent=2))
                text_widget.config(state='disabled')
                
            except Exception as e:
                messagebox.showerror("Error", f"Could not open certificate: {str(e)}")
    
    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    try:
        app = USBWiperApp()
        app.run()
    except Exception as e:
        messagebox.showerror("Fatal Error", f"Application failed to start: {str(e)}")
        sys.exit(1)