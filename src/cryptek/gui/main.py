"""
CrypTek GUI - Tkinter-based graphical user interface
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import sys
from pathlib import Path
from typing import Optional

from ..core.constants import AlgorithmType, AESMode, LogFormat, RSA_KEY_SIZES
from ..core.exceptions import CrypTekError
from ..utils.logger import CrypTekLogger
from ..utils.file_operations import FileOperations
from ..utils.validation import InputValidator
from ..utils.permissions import PermissionChecker


class CrypTekGUI:
    """Main GUI application for CrypTek."""
    
    def __init__(self, root: tk.Tk) -> None:
        """Initialize the GUI application.
        
        Args:
            root: Tkinter root window
        """
        self.root = root
        self.root.title("CrypTek - Encryption Utility v1.0.0")
        self.root.geometry("850x750")
        self.root.resizable(True, True)
        
        # Initialize components
        self.validator = InputValidator()
        self.permission_checker = PermissionChecker()
        
        # Variables
        self._setup_variables()
        
        # Create GUI
        self._create_widgets()
        self._update_algorithm_options()
        
        # Check admin privileges
        self._check_admin_status()
    
    def _setup_variables(self) -> None:
        """Set up tkinter variables."""
        self.mode_var = tk.StringVar(value="encrypt")
        self.path_var = tk.StringVar()
        self.algo_var = tk.StringVar(value="AES256")
        self.aes_mode_var = tk.StringVar(value="CBC")
        self.rsa_keysize_var = tk.StringVar(value="2048")
        self.blowfish_keysize_var = tk.StringVar(value="128")
        self.key_var = tk.StringVar()
        self.ext_var = tk.StringVar(value=".vault")
        self.recursive_var = tk.BooleanVar()
        self.delete_original_var = tk.BooleanVar()
        self.log_var = tk.StringVar()
        self.log_format_var = tk.StringVar(value="text")
        self.passphrase_var = tk.StringVar()
        self.progress_var = tk.StringVar(value="Ready")
        
        # Set default log file
        self.log_var.set(str(Path.home() / "cryptek_audit.log"))
    
    def _create_widgets(self) -> None:
        """Create and layout GUI widgets."""
        # Main frame with padding
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        row = 0
        
        # Title
        title_label = ttk.Label(
            main_frame, 
            text="CrypTek Encryption Utility", 
            font=("Arial", 18, "bold")
        )
        title_label.grid(row=row, column=0, columnspan=3, pady=(0, 25))
        row += 1
        
        # Mode selection
        mode_frame = ttk.LabelFrame(main_frame, text="Operation Mode", padding="10")
        mode_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Radiobutton(
            mode_frame, text="Encrypt Files", variable=self.mode_var, 
            value="encrypt", command=self._on_mode_change
        ).pack(side=tk.LEFT, padx=(0, 20))
        
        ttk.Radiobutton(
            mode_frame, text="Decrypt Files", variable=self.mode_var, 
            value="decrypt", command=self._on_mode_change
        ).pack(side=tk.LEFT)
        row += 1
        
        # Path selection
        path_frame = ttk.LabelFrame(main_frame, text="File/Folder Selection", padding="10")
        path_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        path_frame.columnconfigure(0, weight=1)
        
        ttk.Entry(path_frame, textvariable=self.path_var).grid(
            row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 10)
        )
        ttk.Button(path_frame, text="Browse", command=self._browse_path).grid(row=0, column=1)
        row += 1
        
        # Algorithm selection
        algo_frame = ttk.LabelFrame(main_frame, text="Encryption Algorithm", padding="10")
        algo_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        algo_frame.columnconfigure(1, weight=1)
        
        ttk.Label(algo_frame, text="Algorithm:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        algo_combo = ttk.Combobox(
            algo_frame, textvariable=self.algo_var,
            values=[alg.value for alg in AlgorithmType],
            state="readonly", width=15
        )
        algo_combo.grid(row=0, column=1, sticky=tk.W)
        algo_combo.bind('<<ComboboxSelected>>', self._update_algorithm_options)
        
        # Algorithm-specific options frame
        self.algo_options_frame = ttk.Frame(algo_frame)
        self.algo_options_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        self.algo_options_frame.columnconfigure(1, weight=1)
        row += 1
        
        # Key/Password section
        key_frame = ttk.LabelFrame(main_frame, text="Authentication", padding="10")
        key_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        key_frame.columnconfigure(1, weight=1)
        
        ttk.Label(key_frame, text="Password/Key:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        key_entry_frame = ttk.Frame(key_frame)
        key_entry_frame.grid(row=0, column=1, sticky=(tk.W, tk.E))
        key_entry_frame.columnconfigure(0, weight=1)
        
        self.key_entry = ttk.Entry(key_entry_frame, textvariable=self.key_var, show="*")
        self.key_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        ttk.Button(key_entry_frame, text="Key File", command=self._browse_key_file).grid(row=0, column=1)
        
        # Show/Hide password button
        self.show_password_var = tk.BooleanVar()
        ttk.Checkbutton(
            key_frame, text="Show password", variable=self.show_password_var,
            command=self._toggle_password_visibility
        ).grid(row=1, column=1, sticky=tk.W, pady=(5, 0))
        row += 1
        
        # File options
        options_frame = ttk.LabelFrame(main_frame, text="File Options", padding="10")
        options_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Extension entry
        ext_frame = ttk.Frame(options_frame)
        ext_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=2)
        ext_frame.columnconfigure(1, weight=1)
        
        ttk.Label(ext_frame, text="Extension:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.ext_entry = ttk.Entry(ext_frame, textvariable=self.ext_var, width=10)
        self.ext_entry.grid(row=0, column=1, sticky=tk.W)
        
        # Checkboxes
        ttk.Checkbutton(
            options_frame, text="Process folders recursively", 
            variable=self.recursive_var
        ).grid(row=1, column=0, sticky=tk.W, pady=2)
        
        ttk.Checkbutton(
            options_frame, text="Delete original files after encryption", 
            variable=self.delete_original_var
        ).grid(row=2, column=0, sticky=tk.W, pady=2)
        row += 1
        
        # Logging section
        log_frame = ttk.LabelFrame(main_frame, text="Logging", padding="10")
        log_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        log_frame.columnconfigure(1, weight=1)
        
        ttk.Label(log_frame, text="Log File:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        log_entry_frame = ttk.Frame(log_frame)
        log_entry_frame.grid(row=0, column=1, sticky=(tk.W, tk.E))
        log_entry_frame.columnconfigure(0, weight=1)
        
        ttk.Entry(log_entry_frame, textvariable=self.log_var).grid(
            row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 10)
        )
        ttk.Button(log_entry_frame, text="Browse", command=self._browse_log_file).grid(row=0, column=1)
        
        ttk.Label(log_frame, text="Format:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        ttk.Combobox(
            log_frame, textvariable=self.log_format_var,
            values=["text", "json"], state="readonly", width=10
        ).grid(row=1, column=1, sticky=tk.W, pady=(5, 0))
        row += 1
        
        # Action buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=row, column=0, columnspan=2, pady=20)
        
        self.start_button = ttk.Button(
            button_frame, text="Start Operation", command=self._start_operation,
            style="Accent.TButton"
        )
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Clear Form", command=self._clear_form).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Exit", command=self.root.quit).pack(side=tk.LEFT, padx=5)
        row += 1
        
        # Progress and output
        progress_frame = ttk.LabelFrame(main_frame, text="Progress & Output", padding="10")
        progress_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        progress_frame.columnconfigure(0, weight=1)
        progress_frame.rowconfigure(1, weight=1)
        main_frame.rowconfigure(row, weight=1)
        
        # Progress label
        ttk.Label(progress_frame, textvariable=self.progress_var, font=("Arial", 10, "bold")).grid(
            row=0, column=0, sticky=tk.W, pady=(0, 10)
        )
        
        # Output text area
        self.output_text = scrolledtext.ScrolledText(
            progress_frame, height=12, state=tk.DISABLED,
            wrap=tk.WORD, font=("Consolas", 9)
        )
        self.output_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    
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
                values=[mode.value for mode in AESMode], state="readonly", width=8
            )
            aes_mode_combo.grid(row=0, column=1, sticky=tk.W)
        
        elif algo == "RSA":
            ttk.Label(self.algo_options_frame, text="Key Size:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
            rsa_combo = ttk.Combobox(
                self.algo_options_frame, textvariable=self.rsa_keysize_var,
                values=[str(size) for size in RSA_KEY_SIZES], state="readonly", width=8
            )
            rsa_combo.grid(row=0, column=1, sticky=tk.W)
            
            ttk.Label(self.algo_options_frame, text="Passphrase:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
            ttk.Entry(self.algo_options_frame, textvariable=self.passphrase_var, show="*", width=20).grid(
                row=1, column=1, sticky=tk.W, pady=(5, 0)
            )
        
        elif algo == "Blowfish":
            ttk.Label(self.algo_options_frame, text="Key Size (bits):").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
            bf_entry = ttk.Entry(self.algo_options_frame, textvariable=self.blowfish_keysize_var, width=8)
            bf_entry.grid(row=0, column=1, sticky=tk.W)
            
            ttk.Label(self.algo_options_frame, text="(32-448)", font=("Arial", 8)).grid(
                row=0, column=2, sticky=tk.W, padx=(5, 0)
            )
    
    def _on_mode_change(self) -> None:
        """Handle mode change between encrypt/decrypt."""
        if self.mode_var.get() == "decrypt":
            self.ext_entry.config(state="disabled")
            self.delete_original_var.set(False)
        else:
            self.ext_entry.config(state="normal")
    
    def _toggle_password_visibility(self) -> None:
        """Toggle password visibility in the key entry field."""
        if self.show_password_var.get():
            self.key_entry.config(show="")
        else:
            self.key_entry.config(show="*")
    
    def _browse_path(self) -> None:
        """Browse for file or folder to process."""
        if self.mode_var.get() == "encrypt":
            # For encryption, allow both files and directories
            path = filedialog.askdirectory(title="Select folder to encrypt")
            if not path:
                path = filedialog.askopenfilename(title="Select file to encrypt")
        else:
            # For decryption, typically select encrypted files
            path = filedialog.askopenfilename(
                title="Select encrypted file to decrypt",
                filetypes=[("Encrypted files", "*.vault *.enc *.encrypted"), ("All files", "*.*")]
            )
            if not path:
                path = filedialog.askdirectory(title="Select folder with encrypted files")
        
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
            self.key_entry.config(show="")  # Show file path instead of hiding
    
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
        self.ext_var.set(".vault")
        self.recursive_var.set(False)
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
            level: Log level (INFO, WARNING, ERROR)
        """
        self.output_text.config(state=tk.NORMAL)
        
        # Color code based on level
        if level == "ERROR":
            self.output_text.insert(tk.END, f"❌ {message}\\n")
        elif level == "WARNING":
            self.output_text.insert(tk.END, f"⚠️  {message}\\n")
        elif level == "SUCCESS":
            self.output_text.insert(tk.END, f"✅ {message}\\n")
        else:
            self.output_text.insert(tk.END, f"ℹ️  {message}\\n")
        
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
                errors.append("Please select a file or folder to process")
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
            
            # Validate extension for encryption
            if self.mode_var.get() == "encrypt":
                if not self.ext_var.get().strip():
                    errors.append("Please enter a file extension for encrypted files")
                else:
                    self.validator.validate_extension(self.ext_var.get().strip())
            
            # Validate log file
            if not self.log_var.get().strip():
                errors.append("Please select a log file location")
            else:
                self.validator.validate_log_path(self.log_var.get().strip())
        
        except CrypTekError as e:
            errors.append(str(e))
        
        return errors
    
    def _check_admin_status(self) -> None:
        """Check and display administrator status."""
        if self.permission_checker.is_admin():
            self._log_to_output("Running with administrator privileges", "SUCCESS")
        else:
            self._log_to_output(
                "Running without administrator privileges. Some operations may require elevation.", 
                "WARNING"
            )
    
    def _start_operation(self) -> None:
        """Start the encryption/decryption operation."""
        # Validate inputs
        errors = self._validate_inputs()
        if errors:
            messagebox.showerror("Input Validation Error", "\\n".join(errors))
            return
        
        # Disable start button and update progress
        self.start_button.config(state="disabled")
        self.progress_var.set("Starting operation...")
        
        # Clear previous output
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
        
        # Start operation in separate thread
        thread = threading.Thread(target=self._run_operation, daemon=True)
        thread.start()
    
    def _run_operation(self) -> None:
        """Run the encryption/decryption operation in a separate thread."""
        try:
            # Initialize logger
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
            
            if self.recursive_var.get():
                self._log_to_output("Processing recursively")
            
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
                recursive=self.recursive_var.get(),
                delete_original=self.delete_original_var.get(),
                algorithm_params=algorithm_params
            )
            
            # Report success
            self.progress_var.set("Operation completed successfully!")
            self._log_to_output(f"Operation completed successfully!", "SUCCESS")
            self._log_to_output(f"Processed {len(processed_files)} files", "SUCCESS")
            
            # Show success dialog
            messagebox.showinfo(
                "Operation Complete", 
                f"{self.mode_var.get().title()} operation completed successfully!\\n"
                f"Processed {len(processed_files)} files.\\n\\n"
                f"Check the log file for detailed information:\\n{self.log_var.get()}"
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