"""Constants used throughout CrypTek."""

from enum import Enum
from typing import Final

# Version information
VERSION: Final[str] = "1.0.0"

# Cryptographic constants
DEFAULT_SALT_SIZE: Final[int] = 16
DEFAULT_IV_SIZE: Final[int] = 16
DEFAULT_PBKDF2_ITERATIONS: Final[int] = 100000
DEFAULT_AES_KEY_SIZE: Final[int] = 256
DEFAULT_RSA_KEY_SIZE: Final[int] = 2048
DEFAULT_BLOWFISH_KEY_SIZE: Final[int] = 128

# File operation constants
METADATA_HEADER_SIZE: Final[int] = 4
MAX_FILE_SIZE: Final[int] = 10 * 1024 * 1024 * 1024  # 10GB
CHUNK_SIZE: Final[int] = 64 * 1024  # 64KB chunks for large files

# Logging constants
DEFAULT_LOG_FORMAT: Final[str] = "text"
MAX_LOG_SIZE: Final[int] = 100 * 1024 * 1024  # 100MB


class AlgorithmType(Enum):
    """Supported encryption algorithms."""
    AES128 = "AES128"
    AES256 = "AES256"
    RSA = "RSA"
    BLOWFISH = "Blowfish"


class AESMode(Enum):
    """Supported AES modes."""
    CBC = "CBC"
    GCM = "GCM"


class LogFormat(Enum):
    """Supported log formats."""
    TEXT = "text"
    JSON = "json"


class OperationMode(Enum):
    """Operation modes."""
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


# Supported file extensions
ENCRYPTED_EXTENSIONS: Final[list[str]] = [".vault", ".enc", ".encrypted", ".cryptek"]

# RSA key sizes
RSA_KEY_SIZES: Final[list[int]] = [1024, 2048, 3072, 4096]

# Blowfish key size range
BLOWFISH_MIN_KEY_SIZE: Final[int] = 32
BLOWFISH_MAX_KEY_SIZE: Final[int] = 448