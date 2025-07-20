"""Input validation utilities for CrypTek."""

import os
import re
from pathlib import Path
from typing import List, Optional

from ..core.constants import (
    AlgorithmType, AESMode, RSA_KEY_SIZES, 
    BLOWFISH_MIN_KEY_SIZE, BLOWFISH_MAX_KEY_SIZE,
    MAX_FILE_SIZE
)
from ..core.exceptions import ValidationError


class InputValidator:
    """Validates user inputs and parameters."""
    
    @staticmethod
    def validate_path(path: str, must_exist: bool = True) -> Path:
        """Validate file or directory path.
        
        Args:
            path: Path to validate
            must_exist: Whether path must exist
            
        Returns:
            Validated Path object
            
        Raises:
            ValidationError: If path is invalid
        """
        if not path or not path.strip():
            raise ValidationError("Path cannot be empty")
        
        try:
            path_obj = Path(path).resolve()
        except (OSError, ValueError) as e:
            raise ValidationError(f"Invalid path: {str(e)}")
        
        if must_exist and not path_obj.exists():
            raise ValidationError(f"Path does not exist: {path}")
        
        # Check for suspicious paths
        if str(path_obj).startswith(('/proc', '/sys', '/dev')) and os.name == 'posix':
            raise ValidationError("System paths are not allowed")
        
        return path_obj
    
    @staticmethod
    def validate_algorithm(algorithm: str) -> AlgorithmType:
        """Validate encryption algorithm.
        
        Args:
            algorithm: Algorithm name
            
        Returns:
            Validated AlgorithmType
            
        Raises:
            ValidationError: If algorithm is invalid
        """
        if not algorithm:
            raise ValidationError("Algorithm cannot be empty")
        
        try:
            return AlgorithmType(algorithm.upper())
        except ValueError:
            valid_algorithms = [alg.value for alg in AlgorithmType]
            raise ValidationError(
                f"Unsupported algorithm: {algorithm}. "
                f"Supported algorithms: {', '.join(valid_algorithms)}"
            )
    
    @staticmethod
    def validate_aes_mode(mode: str) -> AESMode:
        """Validate AES mode.
        
        Args:
            mode: AES mode
            
        Returns:
            Validated AESMode
            
        Raises:
            ValidationError: If mode is invalid
        """
        if not mode:
            raise ValidationError("AES mode cannot be empty")
        
        try:
            return AESMode(mode.upper())
        except ValueError:
            valid_modes = [mode.value for mode in AESMode]
            raise ValidationError(
                f"Unsupported AES mode: {mode}. "
                f"Supported modes: {', '.join(valid_modes)}"
            )
    
    @staticmethod
    def validate_key_size(algorithm: AlgorithmType, key_size: int) -> int:
        """Validate key size for given algorithm.
        
        Args:
            algorithm: Encryption algorithm
            key_size: Key size in bits
            
        Returns:
            Validated key size
            
        Raises:
            ValidationError: If key size is invalid
        """
        if algorithm in [AlgorithmType.AES128, AlgorithmType.AES256]:
            if algorithm == AlgorithmType.AES128 and key_size != 128:
                raise ValidationError("AES128 requires 128-bit key")
            elif algorithm == AlgorithmType.AES256 and key_size != 256:
                raise ValidationError("AES256 requires 256-bit key")
        
        elif algorithm == AlgorithmType.RSA:
            if key_size not in RSA_KEY_SIZES:
                raise ValidationError(
                    f"Invalid RSA key size: {key_size}. "
                    f"Supported sizes: {', '.join(map(str, RSA_KEY_SIZES))}"
                )
        
        elif algorithm == AlgorithmType.BLOWFISH:
            if not (BLOWFISH_MIN_KEY_SIZE <= key_size <= BLOWFISH_MAX_KEY_SIZE):
                raise ValidationError(
                    f"Blowfish key size must be between "
                    f"{BLOWFISH_MIN_KEY_SIZE} and {BLOWFISH_MAX_KEY_SIZE} bits"
                )
        
        return key_size
    
    @staticmethod
    def validate_password(password: str, min_length: int = 8) -> str:
        """Validate password strength.
        
        Args:
            password: Password to validate
            min_length: Minimum password length
            
        Returns:
            Validated password
            
        Raises:
            ValidationError: If password is weak
        """
        if not password:
            raise ValidationError("Password cannot be empty")
        
        if len(password) < min_length:
            raise ValidationError(f"Password must be at least {min_length} characters")
        
        # Check for basic complexity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        complexity_score = sum([has_upper, has_lower, has_digit, has_special])
        
        if len(password) >= 12 and complexity_score >= 2:
            return password  # Good password
        elif len(password) >= 8 and complexity_score >= 3:
            return password  # Acceptable password
        else:
            raise ValidationError(
                "Password is too weak. Use a longer password with mixed case, "
                "numbers, and special characters"
            )
    
    @staticmethod
    def validate_extension(extension: str) -> str:
        """Validate file extension.
        
        Args:
            extension: File extension
            
        Returns:
            Validated extension
            
        Raises:
            ValidationError: If extension is invalid
        """
        if not extension:
            raise ValidationError("Extension cannot be empty")
        
        if not extension.startswith('.'):
            extension = '.' + extension
        
        # Check for valid extension format
        if not re.match(r'^\\.[a-zA-Z0-9_-]+$', extension):
            raise ValidationError(
                "Extension must contain only letters, numbers, underscores, and hyphens"
            )
        
        if len(extension) > 10:
            raise ValidationError("Extension is too long (max 10 characters)")
        
        return extension
    
    @staticmethod
    def validate_file_size(file_path: Path) -> int:
        """Validate file size.
        
        Args:
            file_path: Path to file
            
        Returns:
            File size in bytes
            
        Raises:
            ValidationError: If file is too large
        """
        try:
            file_size = file_path.stat().st_size
        except OSError as e:
            raise ValidationError(f"Cannot access file: {str(e)}")
        
        if file_size > MAX_FILE_SIZE:
            raise ValidationError(
                f"File too large: {file_size} bytes. "
                f"Maximum size: {MAX_FILE_SIZE} bytes"
            )
        
        return file_size
    
    @staticmethod
    def validate_log_path(log_path: str) -> Path:
        """Validate log file path.
        
        Args:
            log_path: Log file path
            
        Returns:
            Validated Path object
            
        Raises:
            ValidationError: If log path is invalid
        """
        if not log_path:
            raise ValidationError("Log path cannot be empty")
        
        path_obj = Path(log_path)
        
        # Check if parent directory is writable
        parent_dir = path_obj.parent
        if not parent_dir.exists():
            try:
                parent_dir.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                raise ValidationError(f"Cannot create log directory: {str(e)}")
        
        if not os.access(parent_dir, os.W_OK):
            raise ValidationError(f"Log directory is not writable: {parent_dir}")
        
        return path_obj