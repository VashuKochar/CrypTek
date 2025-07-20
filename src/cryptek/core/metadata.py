"""Metadata management for encrypted files."""

import json
import struct
from typing import Dict, Any, Tuple
from .constants import METADATA_HEADER_SIZE, VERSION
from .exceptions import DecryptionError


class MetadataManager:
    """Manages metadata for encrypted files."""
    
    @staticmethod
    def create_metadata(original_filename: str, algorithm: str, 
                       additional_info: Dict[str, Any] = None) -> bytes:
        """Create metadata header for encrypted files.
        
        Args:
            original_filename: Original filename before encryption
            algorithm: Encryption algorithm used
            additional_info: Additional metadata information
            
        Returns:
            Serialized metadata as bytes
        """
        metadata = {
            'original_filename': original_filename,
            'algorithm': algorithm,
            'version': VERSION,
            'additional_info': additional_info or {}
        }
        
        metadata_json = json.dumps(metadata, separators=(',', ':')).encode('utf-8')
        return struct.pack('<I', len(metadata_json)) + metadata_json
    
    @staticmethod
    def extract_metadata(data: bytes) -> Tuple[Dict[str, Any], bytes]:
        """Extract metadata from encrypted file.
        
        Args:
            data: Encrypted file data with metadata header
            
        Returns:
            Tuple of (metadata dict, encrypted content bytes)
            
        Raises:
            DecryptionError: If metadata is invalid or corrupted
        """
        if len(data) < METADATA_HEADER_SIZE:
            raise DecryptionError("File too small to contain valid metadata")
        
        try:
            metadata_length = struct.unpack('<I', data[:METADATA_HEADER_SIZE])[0]
            
            if metadata_length > len(data) - METADATA_HEADER_SIZE:
                raise DecryptionError("Invalid metadata length")
            
            metadata_end = METADATA_HEADER_SIZE + metadata_length
            metadata_json = data[METADATA_HEADER_SIZE:metadata_end]
            encrypted_content = data[metadata_end:]
            
            metadata = json.loads(metadata_json.decode('utf-8'))
            
            # Validate required fields
            required_fields = ['original_filename', 'algorithm', 'version']
            for field in required_fields:
                if field not in metadata:
                    raise DecryptionError(f"Missing required metadata field: {field}")
            
            return metadata, encrypted_content
            
        except (struct.error, json.JSONDecodeError, UnicodeDecodeError) as e:
            raise DecryptionError(f"Corrupted metadata: {str(e)}")
    
    @staticmethod
    def validate_metadata(metadata: Dict[str, Any]) -> bool:
        """Validate metadata structure and content.
        
        Args:
            metadata: Metadata dictionary to validate
            
        Returns:
            True if metadata is valid
        """
        required_fields = ['original_filename', 'algorithm', 'version']
        
        for field in required_fields:
            if field not in metadata:
                return False
        
        # Check if algorithm is supported
        supported_algorithms = ['AES128', 'AES256', 'RSA', 'Blowfish']
        algorithm = metadata['algorithm']
        
        if not any(algorithm.startswith(alg) for alg in supported_algorithms):
            return False
        
        return True