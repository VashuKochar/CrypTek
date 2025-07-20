"""Core cryptographic engine for CrypTek."""

import os
import struct
from typing import Tuple, Optional, Union, Dict, Any
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes

from .constants import (
    DEFAULT_SALT_SIZE, DEFAULT_IV_SIZE, DEFAULT_PBKDF2_ITERATIONS,
    DEFAULT_AES_KEY_SIZE, DEFAULT_RSA_KEY_SIZE, DEFAULT_BLOWFISH_KEY_SIZE,
    AlgorithmType, AESMode, BLOWFISH_MIN_KEY_SIZE, BLOWFISH_MAX_KEY_SIZE
)
from .exceptions import EncryptionError, DecryptionError, ValidationError
from .metadata import MetadataManager


class CryptoEngine:
    """Core cryptographic engine for encryption/decryption operations."""
    
    def __init__(self) -> None:
        """Initialize the crypto engine."""
        self.backend = default_backend()
        self.metadata_manager = MetadataManager()
    
    def _derive_key(self, password: str, salt: bytes, key_length: int = 32) -> bytes:
        """Derive encryption key from password using PBKDF2.
        
        Args:
            password: Password string
            salt: Salt bytes
            key_length: Desired key length in bytes
            
        Returns:
            Derived key bytes
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=DEFAULT_PBKDF2_ITERATIONS,
            backend=self.backend
        )
        return kdf.derive(password.encode('utf-8'))
    
    def _pad_data(self, data: bytes, block_size: int = 16) -> bytes:
        """Apply PKCS7 padding to data.
        
        Args:
            data: Data to pad
            block_size: Block size for padding
            
        Returns:
            Padded data
        """
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad_data(self, data: bytes) -> bytes:
        """Remove PKCS7 padding from data.
        
        Args:
            data: Padded data
            
        Returns:
            Unpadded data
            
        Raises:
            DecryptionError: If padding is invalid
        """
        try:
            padding_length = data[-1]
            if padding_length > len(data) or padding_length == 0:
                raise DecryptionError("Invalid padding")
            
            # Verify padding
            for i in range(padding_length):
                if data[-(i + 1)] != padding_length:
                    raise DecryptionError("Invalid padding")
            
            return data[:-padding_length]
        except (IndexError, TypeError) as e:
            raise DecryptionError(f"Invalid padding: {str(e)}")
    
    def encrypt_aes(self, data: bytes, key: Union[str, bytes], mode: AESMode = AESMode.CBC,
                   key_size: int = DEFAULT_AES_KEY_SIZE, original_filename: str = '') -> bytes:
        """Encrypt data using AES.
        
        Args:
            data: Data to encrypt
            key: Password string or key bytes
            mode: AES mode (CBC or GCM)
            key_size: Key size in bits (128 or 256)
            original_filename: Original filename for metadata
            
        Returns:
            Encrypted data with metadata
            
        Raises:
            EncryptionError: If encryption fails
            ValidationError: If parameters are invalid
        """
        if key_size not in [128, 256]:
            raise ValidationError(f"Invalid AES key size: {key_size}")
        
        try:
            key_bytes = key_size // 8
            
            if isinstance(key, str):
                salt = get_random_bytes(DEFAULT_SALT_SIZE)
                derived_key = self._derive_key(key, salt, key_bytes)
            else:
                salt = b''
                derived_key = key[:key_bytes]
            
            iv = get_random_bytes(DEFAULT_IV_SIZE)
            
            if mode == AESMode.CBC:
                cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=self.backend)
                padded_data = self._pad_data(data)
            elif mode == AESMode.GCM:
                cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=self.backend)
                padded_data = data
            else:
                raise ValidationError(f"Unsupported AES mode: {mode}")
            
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            if mode == AESMode.GCM:
                tag = encryptor.tag
                result = salt + iv + tag + encrypted_data
            else:
                result = salt + iv + encrypted_data
            
            algorithm_name = f"AES{key_size}-{mode.value}"
            metadata = self.metadata_manager.create_metadata(original_filename, algorithm_name)
            return metadata + result
            
        except Exception as e:
            raise EncryptionError(f"AES encryption failed: {str(e)}")
    
    def decrypt_aes(self, encrypted_data: bytes, key: Union[str, bytes],
                   mode: AESMode = AESMode.CBC, key_size: int = DEFAULT_AES_KEY_SIZE) -> Tuple[bytes, str]:
        """Decrypt AES encrypted data.
        
        Args:
            encrypted_data: Encrypted data with metadata
            key: Password string or key bytes
            mode: AES mode (CBC or GCM)
            key_size: Key size in bits (128 or 256)
            
        Returns:
            Tuple of (decrypted data, original filename)
            
        Raises:
            DecryptionError: If decryption fails
        """
        try:
            metadata, encrypted_content = self.metadata_manager.extract_metadata(encrypted_data)
            key_bytes = key_size // 8
            
            if isinstance(key, str):
                salt = encrypted_content[:DEFAULT_SALT_SIZE]
                iv = encrypted_content[DEFAULT_SALT_SIZE:DEFAULT_SALT_SIZE + DEFAULT_IV_SIZE]
                derived_key = self._derive_key(key, salt, key_bytes)
                
                if mode == AESMode.GCM:
                    tag_start = DEFAULT_SALT_SIZE + DEFAULT_IV_SIZE
                    tag = encrypted_content[tag_start:tag_start + 16]
                    data_to_decrypt = encrypted_content[tag_start + 16:]
                else:
                    data_to_decrypt = encrypted_content[DEFAULT_SALT_SIZE + DEFAULT_IV_SIZE:]
            else:
                derived_key = key[:key_bytes]
                iv = encrypted_content[:DEFAULT_IV_SIZE]
                
                if mode == AESMode.GCM:
                    tag = encrypted_content[DEFAULT_IV_SIZE:DEFAULT_IV_SIZE + 16]
                    data_to_decrypt = encrypted_content[DEFAULT_IV_SIZE + 16:]
                else:
                    data_to_decrypt = encrypted_content[DEFAULT_IV_SIZE:]
            
            if mode == AESMode.CBC:
                cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=self.backend)
            elif mode == AESMode.GCM:
                cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag), backend=self.backend)
            
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(data_to_decrypt) + decryptor.finalize()
            
            if mode == AESMode.CBC:
                decrypted_data = self._unpad_data(decrypted_data)
            
            return decrypted_data, metadata.get('original_filename', '')
            
        except Exception as e:
            raise DecryptionError(f"AES decryption failed: {str(e)}")
    
    def encrypt_rsa_hybrid(self, data: bytes, public_key_path: str,
                          key_size: int = DEFAULT_RSA_KEY_SIZE, original_filename: str = '') -> bytes:
        """Encrypt data using RSA hybrid encryption (RSA + AES).
        
        Args:
            data: Data to encrypt
            public_key_path: Path to RSA public key file
            key_size: RSA key size in bits
            original_filename: Original filename for metadata
            
        Returns:
            Encrypted data with metadata
            
        Raises:
            EncryptionError: If encryption fails
        """
        try:
            # Load public key
            key_path = Path(public_key_path)
            if not key_path.exists():
                raise EncryptionError(f"Public key file not found: {public_key_path}")
            
            with open(key_path, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(key_file.read(), backend=self.backend)
            
            # Generate random AES key
            aes_key = get_random_bytes(32)
            
            # Encrypt data with AES-GCM
            aes_encrypted = self.encrypt_aes(data, aes_key, AESMode.GCM, 256, original_filename)
            
            # Encrypt AES key with RSA
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Combine encrypted key and data
            key_length = len(encrypted_aes_key)
            result = struct.pack('<I', key_length) + encrypted_aes_key + aes_encrypted
            
            algorithm_name = f"RSA{key_size}-Hybrid"
            metadata = self.metadata_manager.create_metadata(original_filename, algorithm_name)
            return metadata + result
            
        except Exception as e:
            raise EncryptionError(f"RSA hybrid encryption failed: {str(e)}")
    
    def decrypt_rsa_hybrid(self, encrypted_data: bytes, private_key_path: str,
                          passphrase: Optional[str] = None) -> Tuple[bytes, str]:
        """Decrypt RSA hybrid encrypted data.
        
        Args:
            encrypted_data: Encrypted data with metadata
            private_key_path: Path to RSA private key file
            passphrase: Optional passphrase for encrypted private key
            
        Returns:
            Tuple of (decrypted data, original filename)
            
        Raises:
            DecryptionError: If decryption fails
        """
        try:
            metadata, encrypted_content = self.metadata_manager.extract_metadata(encrypted_data)
            
            # Load private key
            key_path = Path(private_key_path)
            if not key_path.exists():
                raise DecryptionError(f"Private key file not found: {private_key_path}")
            
            with open(key_path, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=passphrase.encode('utf-8') if passphrase else None,
                    backend=self.backend
                )
            
            # Extract encrypted AES key
            key_length = struct.unpack('<I', encrypted_content[:4])[0]
            encrypted_aes_key = encrypted_content[4:4 + key_length]
            aes_encrypted_data = encrypted_content[4 + key_length:]
            
            # Decrypt AES key with RSA
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt data with AES
            decrypted_data, _ = self.decrypt_aes(aes_encrypted_data, aes_key, AESMode.GCM, 256)
            
            return decrypted_data, metadata.get('original_filename', '')
            
        except Exception as e:
            raise DecryptionError(f"RSA hybrid decryption failed: {str(e)}")
    
    def encrypt_blowfish(self, data: bytes, key: Union[str, bytes],
                        key_size: int = DEFAULT_BLOWFISH_KEY_SIZE, original_filename: str = '') -> bytes:
        """Encrypt data using Blowfish.
        
        Args:
            data: Data to encrypt
            key: Password string or key bytes
            key_size: Key size in bits
            original_filename: Original filename for metadata
            
        Returns:
            Encrypted data with metadata
            
        Raises:
            EncryptionError: If encryption fails
            ValidationError: If key size is invalid
        """
        if not (BLOWFISH_MIN_KEY_SIZE <= key_size <= BLOWFISH_MAX_KEY_SIZE):
            raise ValidationError(f"Blowfish key size must be between {BLOWFISH_MIN_KEY_SIZE} and {BLOWFISH_MAX_KEY_SIZE} bits")
        
        try:
            key_length = max(4, min(56, key_size // 8))  # Blowfish key: 4-56 bytes
            
            if isinstance(key, str):
                salt = get_random_bytes(DEFAULT_SALT_SIZE)
                derived_key = self._derive_key(key, salt, key_length)
            else:
                salt = b''
                derived_key = key[:key_length]
            
            iv = get_random_bytes(8)  # Blowfish block size is 8 bytes
            cipher = Blowfish.new(derived_key, Blowfish.MODE_CBC, iv)
            
            padded_data = self._pad_data(data, 8)
            encrypted_data = cipher.encrypt(padded_data)
            
            result = salt + iv + encrypted_data
            algorithm_name = f"Blowfish{key_size}"
            metadata = self.metadata_manager.create_metadata(original_filename, algorithm_name)
            return metadata + result
            
        except Exception as e:
            raise EncryptionError(f"Blowfish encryption failed: {str(e)}")
    
    def decrypt_blowfish(self, encrypted_data: bytes, key: Union[str, bytes],
                        key_size: int = DEFAULT_BLOWFISH_KEY_SIZE) -> Tuple[bytes, str]:
        """Decrypt Blowfish encrypted data.
        
        Args:
            encrypted_data: Encrypted data with metadata
            key: Password string or key bytes
            key_size: Key size in bits
            
        Returns:
            Tuple of (decrypted data, original filename)
            
        Raises:
            DecryptionError: If decryption fails
        """
        try:
            metadata, encrypted_content = self.metadata_manager.extract_metadata(encrypted_data)
            key_length = max(4, min(56, key_size // 8))
            
            if isinstance(key, str):
                salt = encrypted_content[:DEFAULT_SALT_SIZE]
                iv = encrypted_content[DEFAULT_SALT_SIZE:DEFAULT_SALT_SIZE + 8]
                data_to_decrypt = encrypted_content[DEFAULT_SALT_SIZE + 8:]
                derived_key = self._derive_key(key, salt, key_length)
            else:
                derived_key = key[:key_length]
                iv = encrypted_content[:8]
                data_to_decrypt = encrypted_content[8:]
            
            cipher = Blowfish.new(derived_key, Blowfish.MODE_CBC, iv)
            decrypted_data = cipher.decrypt(data_to_decrypt)
            decrypted_data = self._unpad_data(decrypted_data)
            
            return decrypted_data, metadata.get('original_filename', '')
            
        except Exception as e:
            raise DecryptionError(f"Blowfish decryption failed: {str(e)}")