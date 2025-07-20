"""
CrypTek - Standalone encryption/decryption utility for Windows.

A comprehensive encryption tool that supports multiple algorithms including AES, RSA, and Blowfish
with both CLI and GUI interfaces.
"""

__version__ = "1.0.0"
__author__ = "CrypTek Team"
__email__ = "contact@cryptek.dev"
__license__ = "MIT"

from .core.exceptions import CrypTekError, EncryptionError, DecryptionError

__all__ = [
    "__version__",
    "__author__", 
    "__email__",
    "__license__",
    "CrypTekError",
    "EncryptionError", 
    "DecryptionError"
]