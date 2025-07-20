"""Tests for the crypto engine."""

import pytest
import tempfile
from pathlib import Path

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from cryptek.core.crypto_engine import CryptoEngine
from cryptek.core.constants import AESMode
from cryptek.core.exceptions import EncryptionError, DecryptionError


class TestCryptoEngine:
    """Test suite for CryptoEngine."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.crypto = CryptoEngine()
        self.test_data = b"This is a test message for encryption."
        self.test_password = "testpassword123"
        self.test_filename = "test.txt"
    
    def test_aes_cbc_encryption_decryption(self):
        """Test AES-CBC encryption and decryption."""
        # Encrypt
        encrypted = self.crypto.encrypt_aes(
            self.test_data, self.test_password, AESMode.CBC, 256, self.test_filename
        )
        
        assert len(encrypted) > len(self.test_data)
        
        # Decrypt
        decrypted, filename = self.crypto.decrypt_aes(
            encrypted, self.test_password, AESMode.CBC, 256
        )
        
        assert decrypted == self.test_data
        assert filename == self.test_filename
    
    def test_aes_gcm_encryption_decryption(self):
        """Test AES-GCM encryption and decryption."""
        # Encrypt
        encrypted = self.crypto.encrypt_aes(
            self.test_data, self.test_password, AESMode.GCM, 256, self.test_filename
        )
        
        assert len(encrypted) > len(self.test_data)
        
        # Decrypt
        decrypted, filename = self.crypto.decrypt_aes(
            encrypted, self.test_password, AESMode.GCM, 256
        )
        
        assert decrypted == self.test_data
        assert filename == self.test_filename
    
    def test_aes_128_encryption_decryption(self):
        """Test AES-128 encryption and decryption."""
        # Encrypt
        encrypted = self.crypto.encrypt_aes(
            self.test_data, self.test_password, AESMode.CBC, 128, self.test_filename
        )
        
        # Decrypt
        decrypted, filename = self.crypto.decrypt_aes(
            encrypted, self.test_password, AESMode.CBC, 128
        )
        
        assert decrypted == self.test_data
        assert filename == self.test_filename
    
    def test_blowfish_encryption_decryption(self):
        """Test Blowfish encryption and decryption."""
        # Encrypt
        encrypted = self.crypto.encrypt_blowfish(
            self.test_data, self.test_password, 128, self.test_filename
        )
        
        assert len(encrypted) > len(self.test_data)
        
        # Decrypt
        decrypted, filename = self.crypto.decrypt_blowfish(
            encrypted, self.test_password, 128
        )
        
        assert decrypted == self.test_data
        assert filename == self.test_filename
    
    def test_blowfish_variable_key_size(self):
        """Test Blowfish with different key sizes."""
        key_sizes = [64, 128, 256, 448]
        
        for key_size in key_sizes:
            encrypted = self.crypto.encrypt_blowfish(
                self.test_data, self.test_password, key_size, self.test_filename
            )
            
            decrypted, filename = self.crypto.decrypt_blowfish(
                encrypted, self.test_password, key_size
            )
            
            assert decrypted == self.test_data
            assert filename == self.test_filename
    
    def test_rsa_hybrid_with_temp_keys(self):
        """Test RSA hybrid encryption with temporary keys."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Generate temporary RSA key pair for testing
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=self.crypto.backend
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            # Serialize keys
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Write keys to temporary files
            private_key_path = Path(temp_dir) / "private.pem"
            public_key_path = Path(temp_dir) / "public.pem"
            
            private_key_path.write_bytes(private_pem)
            public_key_path.write_bytes(public_pem)
            
            # Test encryption/decryption
            encrypted = self.crypto.encrypt_rsa_hybrid(
                self.test_data, str(public_key_path), 2048, self.test_filename
            )
            
            decrypted, filename = self.crypto.decrypt_rsa_hybrid(
                encrypted, str(private_key_path)
            )
            
            assert decrypted == self.test_data
            assert filename == self.test_filename
    
    def test_wrong_password_fails(self):
        """Test that wrong password causes decryption to fail."""
        encrypted = self.crypto.encrypt_aes(
            self.test_data, self.test_password, AESMode.CBC, 256, self.test_filename
        )
        
        with pytest.raises(DecryptionError):
            self.crypto.decrypt_aes(encrypted, "wrongpassword", AESMode.CBC, 256)
    
    def test_corrupted_data_fails(self):
        """Test that corrupted data causes decryption to fail."""
        encrypted = self.crypto.encrypt_aes(
            self.test_data, self.test_password, AESMode.CBC, 256, self.test_filename
        )
        
        # Corrupt the data
        corrupted = encrypted[:-10] + b"corrupted!"
        
        with pytest.raises(DecryptionError):
            self.crypto.decrypt_aes(corrupted, self.test_password, AESMode.CBC, 256)
    
    def test_empty_data(self):
        """Test encryption/decryption of empty data."""
        empty_data = b""
        
        encrypted = self.crypto.encrypt_aes(
            empty_data, self.test_password, AESMode.CBC, 256, self.test_filename
        )
        
        decrypted, filename = self.crypto.decrypt_aes(
            encrypted, self.test_password, AESMode.CBC, 256
        )
        
        assert decrypted == empty_data
        assert filename == self.test_filename
    
    def test_large_data(self):
        """Test encryption/decryption of large data."""
        large_data = b"X" * 1024 * 1024  # 1MB of data
        
        encrypted = self.crypto.encrypt_aes(
            large_data, self.test_password, AESMode.GCM, 256, self.test_filename
        )
        
        decrypted, filename = self.crypto.decrypt_aes(
            encrypted, self.test_password, AESMode.GCM, 256
        )
        
        assert decrypted == large_data
        assert filename == self.test_filename