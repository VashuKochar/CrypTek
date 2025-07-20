"""Enhanced logging system for CrypTek."""

import json
import datetime
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from enum import Enum

from ..core.constants import LogFormat, MAX_LOG_SIZE
from ..core.exceptions import FileOperationError


class LogLevel(Enum):
    """Log levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class CrypTekLogger:
    """Enhanced logging system for CrypTek operations."""
    
    def __init__(self, log_file: str, format_type: LogFormat = LogFormat.TEXT) -> None:
        """Initialize the logger.
        
        Args:
            log_file: Path to log file
            format_type: Log format (TEXT or JSON)
            
        Raises:
            FileOperationError: If log file cannot be created
        """
        self.log_file = Path(log_file)
        self.format_type = format_type
        
        # Create log directory if it doesn't exist
        try:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise FileOperationError(f"Cannot create log directory: {str(e)}")
        
        # Set up Python logging
        self._setup_python_logging()
        
        # Check log file size and rotate if necessary
        self._check_log_rotation()
    
    def _setup_python_logging(self) -> None:
        """Set up Python logging configuration."""
        self.logger = logging.getLogger(f"cryptek.{id(self)}")
        self.logger.setLevel(logging.DEBUG)
        
        # Remove existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # Add file handler
        try:
            handler = logging.FileHandler(self.log_file, encoding='utf-8')
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        except OSError as e:
            raise FileOperationError(f"Cannot create log file: {str(e)}")
    
    def _check_log_rotation(self) -> None:
        """Check if log file needs rotation."""
        if self.log_file.exists() and self.log_file.stat().st_size > MAX_LOG_SIZE:
            backup_file = self.log_file.with_suffix(f"{self.log_file.suffix}.bak")
            if backup_file.exists():
                backup_file.unlink()
            self.log_file.rename(backup_file)
    
    def log_operation(self, operation: str, algorithm: str, input_path: str,
                     output_path: str, status: str, error_message: Optional[str] = None,
                     additional_info: Optional[Dict[str, Any]] = None,
                     level: LogLevel = LogLevel.INFO) -> None:
        """Log encryption/decryption operation.
        
        Args:
            operation: Operation type (encrypt/decrypt)
            algorithm: Algorithm used
            input_path: Input file path
            output_path: Output file path
            status: Operation status
            error_message: Optional error message
            additional_info: Additional information
            level: Log level
        """
        timestamp = datetime.datetime.now().isoformat()
        
        log_entry = {
            'timestamp': timestamp,
            'operation': operation,
            'algorithm': algorithm,
            'input_path': input_path,
            'output_path': output_path,
            'status': status,
            'error_message': error_message,
            'additional_info': additional_info or {}
        }
        
        try:
            if self.format_type == LogFormat.JSON:
                self._log_json(log_entry)
            else:
                self._log_text(log_entry)
            
            # Also log to Python logger
            log_message = f"{operation.upper()} {algorithm} - {status}"
            if error_message:
                log_message += f" - {error_message}"
            
            getattr(self.logger, level.value.lower())(log_message)
            
        except Exception as e:
            # Fallback logging to avoid losing important information
            try:
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.write(f"[{timestamp}] LOGGING ERROR: {str(e)}\\n")
            except:
                pass  # If we can't even write the error, give up
    
    def _log_text(self, entry: Dict[str, Any]) -> None:
        """Log in plain text format.
        
        Args:
            entry: Log entry dictionary
        """
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(f"[{entry['timestamp']}] {entry['operation'].upper()} - {entry['algorithm']}\\n")
            f.write(f"  Input: {entry['input_path']}\\n")
            f.write(f"  Output: {entry['output_path']}\\n")
            f.write(f"  Status: {entry['status']}\\n")
            
            if entry['error_message']:
                f.write(f"  Error: {entry['error_message']}\\n")
            
            if entry['additional_info']:
                for key, value in entry['additional_info'].items():
                    f.write(f"  {key}: {value}\\n")
            
            f.write("-" * 80 + "\\n")
    
    def _log_json(self, entry: Dict[str, Any]) -> None:
        """Log in JSON format.
        
        Args:
            entry: Log entry dictionary
        """
        with open(self.log_file, 'a', encoding='utf-8') as f:
            json.dump(entry, f, indent=2, ensure_ascii=False)
            f.write('\\n')
    
    def log_info(self, message: str, additional_info: Optional[Dict[str, Any]] = None) -> None:
        """Log general information.
        
        Args:
            message: Info message
            additional_info: Additional information
        """
        self.log_operation(
            operation="INFO",
            algorithm="",
            input_path="",
            output_path="",
            status="INFO",
            error_message=None,
            additional_info={'message': message, **(additional_info or {})},
            level=LogLevel.INFO
        )
    
    def log_error(self, message: str, error_details: Optional[str] = None,
                  additional_info: Optional[Dict[str, Any]] = None) -> None:
        """Log error message.
        
        Args:
            message: Error message
            error_details: Optional error details
            additional_info: Additional information
        """
        self.log_operation(
            operation="ERROR",
            algorithm="",
            input_path="",
            output_path="",
            status="ERROR",
            error_message=error_details,
            additional_info={'message': message, **(additional_info or {})},
            level=LogLevel.ERROR
        )
    
    def log_warning(self, message: str, additional_info: Optional[Dict[str, Any]] = None) -> None:
        """Log warning message.
        
        Args:
            message: Warning message
            additional_info: Additional information
        """
        self.log_operation(
            operation="WARNING",
            algorithm="",
            input_path="",
            output_path="",
            status="WARNING",
            error_message=None,
            additional_info={'message': message, **(additional_info or {})},
            level=LogLevel.WARNING
        )