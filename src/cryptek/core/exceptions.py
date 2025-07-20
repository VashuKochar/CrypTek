"""Custom exceptions for CrypTek."""

from typing import Optional


class CrypTekError(Exception):
    """Base exception for all CrypTek errors."""
    
    def __init__(self, message: str, details: Optional[str] = None) -> None:
        """Initialize CrypTek error.
        
        Args:
            message: Error message
            details: Optional additional error details
        """
        super().__init__(message)
        self.message = message
        self.details = details
    
    def __str__(self) -> str:
        """Return string representation of error."""
        if self.details:
            return f"{self.message}: {self.details}"
        return self.message


class EncryptionError(CrypTekError):
    """Exception raised during encryption operations."""
    pass


class DecryptionError(CrypTekError):
    """Exception raised during decryption operations."""
    pass


class ValidationError(CrypTekError):
    """Exception raised during input validation."""
    pass


class FileOperationError(CrypTekError):
    """Exception raised during file operations."""
    pass


class PermissionError(CrypTekError):
    """Exception raised when insufficient permissions."""
    pass


class UnsupportedAlgorithmError(CrypTekError):
    """Exception raised when using unsupported algorithm."""
    pass