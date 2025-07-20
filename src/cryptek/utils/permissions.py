"""Permission checking utilities for CrypTek."""

import os
import sys
import ctypes
from pathlib import Path
from typing import List

from ..core.exceptions import PermissionError as CrypTekPermissionError


class PermissionChecker:
    """Handles permission checking and elevation."""
    
    @staticmethod
    def is_admin() -> bool:
        """Check if running with administrator privileges.
        
        Returns:
            True if running as administrator
        """
        try:
            if sys.platform == "win32":
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except:
            return False
    
    @staticmethod
    def is_drive_path(path: str) -> bool:
        """Check if path is a drive root.
        
        Args:
            path: Path to check
            
        Returns:
            True if path is a drive root
        """
        if sys.platform == "win32":
            # Windows drive letters (C:, D:, etc.)
            drive_letters = [f"{chr(i)}:" for i in range(ord('A'), ord('Z') + 1)]
            path_upper = path.upper().rstrip('\\\\/')
            return path_upper in drive_letters or (len(path_upper) == 3 and path_upper[1:] == ":\\\\")
        else:
            # Unix-like systems
            return path == "/" or path.startswith("/dev/") or path.startswith("/mnt/")
    
    @staticmethod
    def requires_admin(path: str) -> bool:
        """Check if path requires administrator privileges.
        
        Args:
            path: Path to check
            
        Returns:
            True if administrator privileges are required
        """
        # Drive operations require admin
        if PermissionChecker.is_drive_path(path):
            return True
        
        # System directories on Windows
        if sys.platform == "win32":
            system_paths = [
                "C:\\\\Windows",
                "C:\\\\Program Files",
                "C:\\\\Program Files (x86)",
                "C:\\\\ProgramData"
            ]
            path_lower = path.lower()
            if any(path_lower.startswith(sys_path.lower()) for sys_path in system_paths):
                return True
        
        # System directories on Unix-like systems
        else:
            system_paths = ["/etc", "/usr", "/opt", "/boot", "/sys", "/proc"]
            if any(path.startswith(sys_path) for sys_path in system_paths):
                return True
        
        return False
    
    @staticmethod
    def check_file_permissions(file_path: Path, operation: str = "read") -> bool:
        """Check file permissions.
        
        Args:
            file_path: Path to file
            operation: Operation type (read, write, execute)
            
        Returns:
            True if operation is allowed
        """
        if not file_path.exists():
            return False
        
        try:
            if operation == "read":
                return os.access(file_path, os.R_OK)
            elif operation == "write":
                return os.access(file_path, os.W_OK)
            elif operation == "execute":
                return os.access(file_path, os.X_OK)
            else:
                return False
        except OSError:
            return False
    
    @staticmethod
    def check_directory_permissions(dir_path: Path, operation: str = "read") -> bool:
        """Check directory permissions.
        
        Args:
            dir_path: Path to directory
            operation: Operation type (read, write, execute)
            
        Returns:
            True if operation is allowed
        """
        if not dir_path.exists() or not dir_path.is_dir():
            return False
        
        try:
            if operation == "read":
                return os.access(dir_path, os.R_OK)
            elif operation == "write":
                return os.access(dir_path, os.W_OK)
            elif operation == "execute":
                return os.access(dir_path, os.X_OK)
            else:
                return False
        except OSError:
            return False
    
    @staticmethod
    def validate_permissions(path: str, operation: str = "read") -> None:
        """Validate permissions for path.
        
        Args:
            path: Path to validate
            operation: Operation type
            
        Raises:
            CrypTekPermissionError: If permissions are insufficient
        """
        path_obj = Path(path)
        
        # Check if admin privileges are required
        if PermissionChecker.requires_admin(path) and not PermissionChecker.is_admin():
            raise CrypTekPermissionError(
                "Administrator privileges required for this operation",
                f"Path: {path}"
            )
        
        # Check file/directory permissions
        if path_obj.exists():
            if path_obj.is_file():
                if not PermissionChecker.check_file_permissions(path_obj, operation):
                    raise CrypTekPermissionError(
                        f"Insufficient permissions for {operation} operation",
                        f"File: {path}"
                    )
            elif path_obj.is_dir():
                if not PermissionChecker.check_directory_permissions(path_obj, operation):
                    raise CrypTekPermissionError(
                        f"Insufficient permissions for {operation} operation",
                        f"Directory: {path}"
                    )
        
        # For write operations, check parent directory
        if operation == "write" and not path_obj.exists():
            parent_dir = path_obj.parent
            if not PermissionChecker.check_directory_permissions(parent_dir, "write"):
                raise CrypTekPermissionError(
                    "Insufficient permissions to create file",
                    f"Parent directory: {parent_dir}"
                )
    
    @staticmethod
    def get_permission_info(path: str) -> dict:
        """Get detailed permission information for path.
        
        Args:
            path: Path to analyze
            
        Returns:
            Dictionary with permission information
        """
        path_obj = Path(path)
        info = {
            "path": str(path_obj),
            "exists": path_obj.exists(),
            "is_file": path_obj.is_file() if path_obj.exists() else None,
            "is_directory": path_obj.is_dir() if path_obj.exists() else None,
            "requires_admin": PermissionChecker.requires_admin(path),
            "is_admin": PermissionChecker.is_admin(),
            "readable": False,
            "writable": False,
            "executable": False
        }
        
        if path_obj.exists():
            info["readable"] = PermissionChecker.check_file_permissions(path_obj, "read")
            info["writable"] = PermissionChecker.check_file_permissions(path_obj, "write")
            info["executable"] = PermissionChecker.check_file_permissions(path_obj, "execute")
        
        return info