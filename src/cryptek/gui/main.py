"""
CrypTek GUI - Modern tabbed interface for encryption/decryption
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import sys
from pathlib import Path
from typing import Optional
import string

from ..core.constants import AlgorithmType, AESMode, LogFormat, RSA_KEY_SIZES
from ..core.exceptions import CrypTekError
from ..utils.logger import CrypTekLogger
from ..utils.file_operations import FileOperations
from ..utils.validation import InputValidator
from ..utils.permissions import PermissionChecker


class CrypTekGUI:
    """Modern tabbed GUI application for CrypTek."""
    
    def __init__(self, root: tk.Tk) -> None:
        """Initialize the GUI application.
        
        Args:
            root: Tkinter root window
        """
        self.root = root
        self.root.title("CrypTek - File Encryption Utility v1.0.0")
        self.root.geometry("800x650")
        self.root.resizable(True, True)
        
        # Initialize components
        self.validator = InputValidator()
        self.permission_checker = PermissionChecker()
        
        # Variables
        self._setup_variables()
        
        # Create modern themed GUI
        self._setup_theme()
        self._create_widgets()
        
        # Check admin privileges
        self._check_admin_status()
    
    def _setup_variables(self) -> None:
        """Set up tkinter variables."""
        # Main operation variables
        self.mode_var = tk.StringVar(value="encrypt")
        self.path_var = tk.StringVar()
        self.path_type_var = tk.StringVar(value="file")
        self.key_var = tk.StringVar()
        self.ext_var = tk.StringVar(value=".cryptek")
        
        # Algorithm variables
        self.algo_var = tk.StringVar(value="AES256")
        self.aes_mode_var = tk.StringVar(value="CBC")
        self.rsa_keysize_var = tk.StringVar(value="2048")
        self.blowfish_keysize_var = tk.StringVar(value="128")
        self.passphrase_var = tk.StringVar()
        
        # Options
        self.delete_original_var = tk.BooleanVar()
        self.show_password_var = tk.BooleanVar()
        
        # Logging (optional)
        self.enable_logging_var = tk.BooleanVar(value=True)
        self.log_var = tk.StringVar()
        self.log_format_var = tk.StringVar(value="text")
        
        # Progress
        self.progress_var = tk.StringVar(value="Ready")
        
        # Set default log file
        self.log_var.set(str(Path.home() / "cryptek_audit.log"))
    
    def _setup_theme(self) -> None:
        """Set up modern theme and styling."""
        style = ttk.Style()
        
        # Use modern theme if available
        available_themes = style.theme_names()
        if "clam" in available_themes:
            style.theme_use("clam")
        elif "vista" in available_themes:
            style.theme_use("vista")
        
        # Configure custom styles
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("Heading.TLabel", font=("Segoe UI", 11, "bold"))
        style.configure("Success.TLabel", foreground="green")
        style.configure("Warning.TLabel", foreground="orange")
        style.configure("Error.TLabel", foreground="red")
    
    def _create_widgets(self) -> None:
        """Create and layout GUI widgets with tabbed interface."""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(
            main_frame, 
            text="🛡️ CrypTek File Encryption", 
            style="Title.TLabel"
        )
        title_label.grid(row=0, column=0, pady=(0, 20))
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create tabs
        self._create_main_tab()
        self._create_advanced_tab()
        self._create_log_tab()
        
        # Action buttons at bottom
        self._create_action_buttons(main_frame)
    
    def _create_main_tab(self) -> None:
        """Create the main operation tab."""
        main_tab = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(main_tab, text="  Main  ")
        
        # Configure grid
        main_tab.columnconfigure(1, weight=1)
        
        row = 0
        
        # Operation Mode
        mode_frame = ttk.LabelFrame(main_tab, text="Operation Mode", padding="10")
        mode_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        
        ttk.Radiobutton(
            mode_frame, text="🔒 Encrypt Files", variable=self.mode_var, 
            value="encrypt", command=self._on_mode_change
        ).pack(side=tk.LEFT, padx=(0, 30))
        
        ttk.Radiobutton(
            mode_frame, text="🔓 Decrypt Files", variable=self.mode_var, 
            value="decrypt", command=self._on_mode_change
        ).pack(side=tk.LEFT)
        row += 1
        
        # Target Selection
        target_frame = ttk.LabelFrame(main_tab, text="Select Target", padding="10")
        target_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        target_frame.columnconfigure(1, weight=1)
        
        # Target type selection
        type_frame = ttk.Frame(target_frame)
        type_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(type_frame, text="Target Type:", style="Heading.TLabel").pack(side=tk.LEFT, padx=(0, 15))
        
        ttk.Radiobutton(
            type_frame, text="📄 File", variable=self.path_type_var, 
            value="file", command=self._update_browse_button
        ).pack(side=tk.LEFT, padx=(0, 15))
        
        ttk.Radiobutton(
            type_frame, text="📁 Folder", variable=self.path_type_var, 
            value="folder", command=self._update_browse_button
        ).pack(side=tk.LEFT, padx=(0, 15))
        
        ttk.Radiobutton(
            type_frame, text="💽 Drive", variable=self.path_type_var, 
            value="drive", command=self._update_browse_button
        ).pack(side=tk.LEFT)
        
        # Path selection
        ttk.Label(target_frame, text="Selected Path:").grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        
        path_entry_frame = ttk.Frame(target_frame)
        path_entry_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))
        path_entry_frame.columnconfigure(0, weight=1)
        
        self.path_entry = ttk.Entry(path_entry_frame, textvariable=self.path_var, font=("Consolas", 9))
        self.path_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        
        self.browse_button = ttk.Button(path_entry_frame, text="Browse File", command=self._browse_path)
        self.browse_button.grid(row=0, column=1)
        row += 1
        
        # Authentication
        auth_frame = ttk.LabelFrame(main_tab, text="Authentication", padding="10")
        auth_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        auth_frame.columnconfigure(1, weight=1)
        
        ttk.Label(auth_frame, text="Password/Key:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        key_frame = ttk.Frame(auth_frame)
        key_frame.grid(row=0, column=1, sticky=(tk.W, tk.E))
        key_frame.columnconfigure(0, weight=1)
        
        self.key_entry = ttk.Entry(key_frame, textvariable=self.key_var, show="*", font=("Consolas", 9))
        self.key_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        
        ttk.Button(key_frame, text="Key File", command=self._browse_key_file).grid(row=0, column=1, padx=(0, 10))
        
        ttk.Checkbutton(
            key_frame, text="Show", variable=self.show_password_var,
            command=self._toggle_password_visibility
        ).grid(row=0, column=2)
        row += 1
        
        # Algorithm Selection
        algo_frame = ttk.LabelFrame(main_tab, text="Encryption Algorithm", padding="10")
        algo_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        algo_frame.columnconfigure(1, weight=1)
        
        ttk.Label(algo_frame, text="Algorithm:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        algo_combo = ttk.Combobox(
            algo_frame, textvariable=self.algo_var,
            values=[alg.value for alg in AlgorithmType],
            state="readonly", width=15
        )
        algo_combo.grid(row=0, column=1, sticky=tk.W, pady=(0, 10))
        algo_combo.bind('<<ComboboxSelected>>', self._update_algorithm_options)
        
        # Algorithm-specific options
        self.algo_options_frame = ttk.Frame(algo_frame)
        self.algo_options_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E))
        self.algo_options_frame.columnconfigure(1, weight=1)
        
        self._update_algorithm_options()
        row += 1
        
        # File Options
        options_frame = ttk.LabelFrame(main_tab, text="Options", padding="10")
        options_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        # Extension for encryption
        ext_frame = ttk.Frame(options_frame)
        ext_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        ext_frame.columnconfigure(1, weight=1)
        
        self.ext_label = ttk.Label(ext_frame, text="File Extension:")
        self.ext_label.grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        self.ext_entry = ttk.Entry(ext_frame, textvariable=self.ext_var, width=15)
        self.ext_entry.grid(row=0, column=1, sticky=tk.W)
        
        # Delete original files
        ttk.Checkbutton(
            options_frame, text="Delete original files after encryption", 
            variable=self.delete_original_var
        ).grid(row=1, column=0, sticky=tk.W, pady=(0, 5))
    
    def _create_advanced_tab(self) -> None:
        """Create the advanced settings tab."""
        advanced_tab = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(advanced_tab, text="  Advanced  ")
        
        # Drive Selection (for advanced users)
        drive_frame = ttk.LabelFrame(advanced_tab, text="Drive Selection", padding="10")
        drive_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        drive_frame.columnconfigure(0, weight=1)
        
        ttk.Label(drive_frame, text="Available Drives:", style="Heading.TLabel").grid(row=0, column=0, sticky=tk.W, pady=(0, 10))
        
        # Drive listbox
        drives_frame = ttk.Frame(drive_frame)
        drives_frame.grid(row=1, column=0, sticky=(tk.W, tk.E))
        drives_frame.columnconfigure(0, weight=1)
        
        self.drives_listbox = tk.Listbox(drives_frame, height=4, font=("Consolas", 9))
        self.drives_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        
        drives_scroll = ttk.Scrollbar(drives_frame, orient="vertical", command=self.drives_listbox.yview)
        drives_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.drives_listbox.config(yscrollcommand=drives_scroll.set)
        
        ttk.Button(drives_frame, text="Refresh Drives", command=self._refresh_drives).grid(row=1, column=0, pady=(10, 0), sticky=tk.W)
        ttk.Button(drives_frame, text="Select Drive", command=self._select_drive).grid(row=1, column=1, pady=(10, 0), sticky=tk.E)
        
        self._refresh_drives()
        
        # Security Options
        security_frame = ttk.LabelFrame(advanced_tab, text="Security Options", padding="10")
        security_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        
        ttk.Label(security_frame, text="⚠️ Administrator privileges required for drive operations", 
                 style="Warning.TLabel").pack(anchor=tk.W, pady=(0, 10))
        
        # Performance note
        perf_frame = ttk.LabelFrame(advanced_tab, text="Performance Note", padding="10")
        perf_frame.grid(row=2, column=0, sticky=(tk.W, tk.E))
        
        ttk.Label(perf_frame, text="📁 Folders are processed recursively by default\n"
                                  "💽 Drive encryption may take considerable time\n"
                                  "🔒 Large files will show progress during processing", 
                 justify=tk.LEFT).pack(anchor=tk.W)
    
    def _create_log_tab(self) -> None:
        """Create the logging configuration tab."""
        log_tab = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(log_tab, text="  Logging  ")
        
        # Enable/Disable logging
        ttk.Checkbutton(
            log_tab, text="Enable Operation Logging", 
            variable=self.enable_logging_var,
            command=self._toggle_logging
        ).grid(row=0, column=0, sticky=tk.W, pady=(0, 20))
        
        # Logging configuration
        self.log_config_frame = ttk.LabelFrame(log_tab, text="Log Configuration", padding="10")
        self.log_config_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        self.log_config_frame.columnconfigure(1, weight=1)
        
        # Log file path
        ttk.Label(self.log_config_frame, text="Log File:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        log_path_frame = ttk.Frame(self.log_config_frame)
        log_path_frame.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=(0, 10))
        log_path_frame.columnconfigure(0, weight=1)
        
        ttk.Entry(log_path_frame, textvariable=self.log_var, font=("Consolas", 9)).grid(
            row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 10)
        )
        ttk.Button(log_path_frame, text="Browse", command=self._browse_log_file).grid(row=0, column=1)
        
        # Log format
        ttk.Label(self.log_config_frame, text="Format:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10))
        ttk.Combobox(
            self.log_config_frame, textvariable=self.log_format_var,
            values=["text", "json"], state="readonly", width=10
        ).grid(row=1, column=1, sticky=tk.W)
        
        # Log preview area
        preview_frame = ttk.LabelFrame(log_tab, text="Recent Operations", padding="10")
        preview_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(15, 0))
        preview_frame.columnconfigure(0, weight=1)
        preview_frame.rowconfigure(0, weight=1)
        log_tab.rowconfigure(2, weight=1)
        
        self.output_text = scrolledtext.ScrolledText(
            preview_frame, height=15, state=tk.DISABLED,
            wrap=tk.WORD, font=("Consolas", 9)
        )
        self.output_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self._toggle_logging()
    
    def _create_action_buttons(self, parent) -> None:
        """Create action buttons at the bottom."""
        # Separator
        ttk.Separator(parent, orient="horizontal").grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Button frame
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=3, column=0, pady=(15, 0))
        
        # Progress label
        self.progress_label = ttk.Label(button_frame, textvariable=self.progress_var, font=("Segoe UI", 10, "bold"))
        self.progress_label.pack(pady=(0, 15))
        
        # Buttons
        buttons_container = ttk.Frame(button_frame)
        buttons_container.pack()
        
        self.start_button = ttk.Button(
            buttons_container, text="🚀 Start Operation", command=self._start_operation
        )
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(buttons_container, text="🔄 Clear", command=self._clear_form).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(buttons_container, text="❌ Exit", command=self.root.quit).pack(side=tk.LEFT)
    
    def _refresh_drives(self) -> None:
        """Refresh the list of available drives."""
        self.drives_listbox.delete(0, tk.END)
        
        # Get drive letters on Windows
        import platform
        if platform.system() == "Windows":
            import os
            drives = ['%s:' % d for d in string.ascii_uppercase if os.path.exists('%s:' % d)]
            for drive in drives:
                self.drives_listbox.insert(tk.END, f"{drive}\\ (Drive)")
        else:
            # On Unix-like systems, show common mount points
            common_mounts = ["/", "/home", "/tmp", "/var", "/usr"]
            for mount in common_mounts:
                if Path(mount).exists():
                    self.drives_listbox.insert(tk.END, f"{mount} (Mount Point)")
    
    def _select_drive(self) -> None:
        """Select a drive from the list."""
        selection = self.drives_listbox.curselection()
        if selection:
            drive_text = self.drives_listbox.get(selection[0])
            drive_path = drive_text.split(" ")[0]
            self.path_var.set(drive_path)
            self.path_type_var.set("drive")
            self._update_browse_button()
    
    def _update_browse_button(self) -> None:
        """Update browse button text based on selected type."""
        path_type = self.path_type_var.get()
        if path_type == "file":
            self.browse_button.config(text="Browse File")
        elif path_type == "folder":
            self.browse_button.config(text="Browse Folder")
        else:  # drive
            self.browse_button.config(text="Browse Drive")
    
    def _toggle_logging(self) -> None:
        """Toggle logging configuration availability."""
        if self.enable_logging_var.get():
            # Enable logging widgets
            for child in self.log_config_frame.winfo_children():
                child.configure(state="normal")
        else:
            # Disable logging widgets
            for child in self.log_config_frame.winfo_children():
                if hasattr(child, 'configure'):
                    try:
                        child.configure(state="disabled")
                    except tk.TclError:
                        pass  # Some widgets don't support state
    
    def _update_algorithm_options(self, event=None) -> None:
        """Update algorithm-specific options based on selection."""
        # Clear existing options
        for widget in self.algo_options_frame.winfo_children():
            widget.destroy()
        
        algo = self.algo_var.get()
        
        if algo.startswith("AES"):
            ttk.Label(self.algo_options_frame, text="Mode:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
            aes_mode_combo = ttk.Combobox(
                self.algo_options_frame, textvariable=self.aes_mode_var,
                values=[mode.value for mode in AESMode], state="readonly", width=10
            )
            aes_mode_combo.grid(row=0, column=1, sticky=tk.W)
        
        elif algo == "RSA":
            ttk.Label(self.algo_options_frame, text="Key Size:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
            rsa_combo = ttk.Combobox(
                self.algo_options_frame, textvariable=self.rsa_keysize_var,
                values=[str(size) for size in RSA_KEY_SIZES], state="readonly", width=10
            )
            rsa_combo.grid(row=0, column=1, sticky=tk.W)
            
            ttk.Label(self.algo_options_frame, text="Passphrase:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
            ttk.Entry(self.algo_options_frame, textvariable=self.passphrase_var, show="*", width=20).grid(
                row=1, column=1, sticky=tk.W, pady=(5, 0)
            )
        
        elif algo == "Blowfish":
            ttk.Label(self.algo_options_frame, text="Key Size (bits):").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
            bf_entry = ttk.Entry(self.algo_options_frame, textvariable=self.blowfish_keysize_var, width=10)
            bf_entry.grid(row=0, column=1, sticky=tk.W)
            
            ttk.Label(self.algo_options_frame, text="(32-448)", font=("Segoe UI", 8)).grid(
                row=0, column=2, sticky=tk.W, padx=(5, 0)
            )
    
    def _on_mode_change(self) -> None:
        """Handle mode change between encrypt/decrypt."""
        if self.mode_var.get() == "decrypt":
            self.ext_entry.config(state="disabled")
            self.ext_label.config(state="disabled")
            self.delete_original_var.set(False)
        else:
            self.ext_entry.config(state="normal")
            self.ext_label.config(state="normal")
    
    def _toggle_password_visibility(self) -> None:
        """Toggle password visibility in the key entry field."""
        if self.show_password_var.get():
            self.key_entry.config(show="")
        else:
            self.key_entry.config(show="*")
    
    def _browse_path(self) -> None:
        """Browse for file, folder, or drive based on selection."""
        path_type = self.path_type_var.get()
        
        if path_type == "file":
            if self.mode_var.get() == "encrypt":
                path = filedialog.askopenfilename(title="Select file to encrypt")
            else:
                path = filedialog.askopenfilename(
                    title="Select encrypted file to decrypt",
                    filetypes=[("Encrypted files", "*.cryptek *.vault *.enc *.encrypted"), ("All files", "*.*")]
                )
        elif path_type == "folder":
            path = filedialog.askdirectory(title=f"Select folder to {self.mode_var.get()}")
        else:  # drive
            path = filedialog.askdirectory(title="Select drive root directory")
        
        if path:
            self.path_var.set(path)
    
    def _browse_key_file(self) -> None:
        """Browse for RSA key file."""
        file_path = filedialog.askopenfilename(
            title="Select Key File",
            filetypes=[
                ("PEM files", "*.pem"), 
                ("DER files", "*.der"), 
                ("Key files", "*.key"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            self.key_var.set(file_path)
            self.key_entry.config(show="")  # Show file path
    
    def _browse_log_file(self) -> None:
        """Browse for log file location."""
        file_path = filedialog.asksaveasfilename(
            title="Select Log File Location",
            defaultextension=".log",
            filetypes=[
                ("Log files", "*.log"), 
                ("Text files", "*.txt"), 
                ("All files", "*.*")
            ]
        )
        if file_path:
            self.log_var.set(file_path)
    
    def _clear_form(self) -> None:
        """Clear all form fields to defaults."""
        self.path_var.set("")
        self.key_var.set("")
        self.ext_var.set(".cryptek")
        self.delete_original_var.set(False)
        self.passphrase_var.set("")
        self.show_password_var.set(False)
        self.key_entry.config(show="*")
        
        # Clear output
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.progress_var.set("Ready")
    
    def _log_to_output(self, message: str, level: str = "INFO") -> None:
        """Add message to output text widget.
        
        Args:
            message: Message to log
            level: Log level (INFO, WARNING, ERROR, SUCCESS)
        """
        if not self.enable_logging_var.get():
            return
            
        self.output_text.config(state=tk.NORMAL)
        
        # Add timestamp
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color code based on level
        if level == "ERROR":
            self.output_text.insert(tk.END, f"[{timestamp}] ❌ {message}\n")
        elif level == "WARNING":
            self.output_text.insert(tk.END, f"[{timestamp}] ⚠️ {message}\n")
        elif level == "SUCCESS":
            self.output_text.insert(tk.END, f"[{timestamp}] ✅ {message}\n")
        else:
            self.output_text.insert(tk.END, f"[{timestamp}] ℹ️ {message}\n")
        
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.root.update()
    
    def _validate_inputs(self) -> list[str]:
        """Validate user inputs.
        
        Returns:
            List of validation errors
        """
        errors = []
        
        try:
            # Validate path
            if not self.path_var.get().strip():
                errors.append("Please select a file, folder, or drive to process")
            else:
                self.validator.validate_path(self.path_var.get().strip())
            
            # Validate key/password
            if not self.key_var.get().strip():
                errors.append("Please enter a password or select a key file")
            
            # Validate algorithm-specific parameters
            algo = self.validator.validate_algorithm(self.algo_var.get())
            
            if algo == AlgorithmType.BLOWFISH:
                try:
                    keysize = int(self.blowfish_keysize_var.get())
                    self.validator.validate_key_size(algo, keysize)
                except ValueError:
                    errors.append("Invalid Blowfish key size - must be a number")
            
            # Validate extension for encryption (now optional with default)
            if self.mode_var.get() == "encrypt" and not self.ext_var.get().strip():
                self.ext_var.set(".cryptek")  # Set default
        
        except CrypTekError as e:
            errors.append(str(e))
        
        return errors
    
    def _check_admin_status(self) -> None:
        """Check and display administrator status."""
        if self.permission_checker.is_admin():
            self._log_to_output("Running with administrator privileges", "SUCCESS")
            self.progress_var.set("Ready (Admin Mode)")
        else:
            self._log_to_output(
                "Running without administrator privileges. Drive operations may require elevation.", 
                "WARNING"
            )
            self.progress_var.set("Ready (Limited Mode)")
    
    def _start_operation(self) -> None:
        """Start the encryption/decryption operation."""
        # Validate inputs
        errors = self._validate_inputs()
        if errors:
            messagebox.showerror("Input Validation Error", "\n".join(errors))
            return
        
        # Disable start button and update progress
        self.start_button.config(state="disabled")
        self.progress_var.set("Starting operation...")
        
        # Clear previous output if logging is enabled
        if self.enable_logging_var.get():
            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete(1.0, tk.END)
            self.output_text.config(state=tk.DISABLED)
        
        # Start operation in separate thread
        thread = threading.Thread(target=self._run_operation, daemon=True)
        thread.start()
    
    def _run_operation(self) -> None:
        """Run the encryption/decryption operation in a separate thread."""
        try:
            # Initialize logger only if logging is enabled
            logger = None
            if self.enable_logging_var.get():
                logger = CrypTekLogger(self.log_var.get(), LogFormat(self.log_format_var.get()))
            
            # Initialize file processor
            file_ops = FileOperations(logger)
            
            # Prepare algorithm parameters
            algorithm_params = {
                'aes_mode': self.aes_mode_var.get(),
                'rsa_keysize': int(self.rsa_keysize_var.get()),
                'blowfish_keysize': int(self.blowfish_keysize_var.get()),
                'passphrase': self.passphrase_var.get() if self.passphrase_var.get() else None
            }
            
            # Log operation start
            self._log_to_output(f"Starting {self.mode_var.get()} operation...")
            self._log_to_output(f"Algorithm: {self.algo_var.get()}")
            self._log_to_output(f"Target: {self.path_var.get()}")
            
            # Auto-enable recursive for folders and drives
            recursive = self.path_type_var.get() in ["folder", "drive"]
            if recursive:
                self._log_to_output("Processing recursively (folders/drives)")
            
            # Validate algorithm
            algorithm = self.validator.validate_algorithm(self.algo_var.get())
            
            # Process files
            self.progress_var.set("Processing files...")
            processed_files = file_ops.process_files(
                path=self.path_var.get().strip(),
                mode=self.mode_var.get(),
                algorithm=algorithm,
                key=self.key_var.get().strip(),
                extension=self.ext_var.get().strip(),
                recursive=recursive,
                delete_original=self.delete_original_var.get(),
                algorithm_params=algorithm_params
            )
            
            # Report success
            self.progress_var.set("Operation completed successfully!")
            self._log_to_output(f"Operation completed successfully!", "SUCCESS")
            self._log_to_output(f"Processed {len(processed_files)} files", "SUCCESS")
            
            # Show success dialog
            log_info = f"\n\nCheck the log file for detailed information:\n{self.log_var.get()}" if self.enable_logging_var.get() else ""
            messagebox.showinfo(
                "Operation Complete", 
                f"{self.mode_var.get().title()} operation completed successfully!\n"
                f"Processed {len(processed_files)} files.{log_info}"
            )
            
        except CrypTekError as e:
            error_msg = f"Operation failed: {str(e)}"
            self._log_to_output(error_msg, "ERROR")
            self.progress_var.set("Operation failed")
            messagebox.showerror("Operation Failed", error_msg)
        
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            self._log_to_output(error_msg, "ERROR")
            self.progress_var.set("Operation failed")
            messagebox.showerror("Unexpected Error", error_msg)
        
        finally:
            # Re-enable start button
            self.start_button.config(state="normal")


def main() -> int:
    """Main GUI entry point.
    
    Returns:
        Exit code (0 for success)
    """
    try:
        # Create and configure root window
        root = tk.Tk()
        
        # Set window icon (if available)
        try:
            # root.iconbitmap("assets/icon.ico")  # Uncomment if icon exists
            pass
        except:
            pass
        
        # Initialize and run GUI
        app = CrypTekGUI(root)
        root.mainloop()
        
        return 0
        
    except Exception as e:
        print(f"GUI startup failed: {str(e)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())