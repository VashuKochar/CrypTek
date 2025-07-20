"""File operations utility for CrypTek."""

import os
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional, Generator, Tuple

from ..core.constants import CHUNK_SIZE, MAX_FILE_SIZE, AlgorithmType, AESMode
from ..core.crypto_engine import CryptoEngine
from ..core.exceptions import FileOperationError, EncryptionError, DecryptionError
from .logger import CrypTekLogger
from .validation import InputValidator
from .permissions import PermissionChecker


class FileOperations:
    """Handles file and directory operations for encryption/decryption."""
    
    def __init__(self, logger: CrypTekLogger) -> None:
        """Initialize file operations.
        
        Args:
            logger: Logger instance for operation logging
        """
        self.crypto_engine = CryptoEngine()
        self.logger = logger
        self.validator = InputValidator()
        self.permission_checker = PermissionChecker()
    
    def get_files_to_process(self, path: str, recursive: bool = False,
                           file_patterns: Optional[List[str]] = None) -> List[Path]:
        """Get list of files to process.
        
        Args:
            path: Base path to scan
            recursive: Whether to scan recursively
            file_patterns: Optional file patterns to match
            
        Returns:
            List of file paths to process
            
        Raises:
            FileOperationError: If path is invalid or inaccessible
        """
        try:
            # Validate and check permissions
            path_obj = self.validator.validate_path(path, must_exist=True)
            self.permission_checker.validate_permissions(str(path_obj), "read")
            
            files = []
            
            if path_obj.is_file():
                # Single file
                self.validator.validate_file_size(path_obj)
                files.append(path_obj)
                
            elif path_obj.is_dir():
                # Directory
                if recursive:
                    files.extend(self._scan_directory_recursive(path_obj, file_patterns))
                else:
                    files.extend(self._scan_directory_flat(path_obj, file_patterns))
            
            else:
                # Handle special cases like drive paths
                if self.permission_checker.is_drive_path(str(path_obj)):
                    if not self.permission_checker.is_admin():
                        raise FileOperationError(
                            "Administrator privileges required for drive operations"
                        )
                    files.extend(self._scan_drive(path_obj, recursive, file_patterns))
                else:
                    raise FileOperationError(f"Invalid path type: {path}")
            
            if not files:
                self.logger.log_warning(f"No files found to process in: {path}")
            
            return files
            
        except Exception as e:
            error_msg = f"Failed to scan path {path}: {str(e)}"
            self.logger.log_error(error_msg)
            raise FileOperationError(error_msg)
    
    def _scan_directory_flat(self, directory: Path,
                           file_patterns: Optional[List[str]] = None) -> List[Path]:
        """Scan directory without recursion.
        
        Args:
            directory: Directory to scan
            file_patterns: Optional file patterns to match
            
        Returns:
            List of file paths
        """
        files = []
        try:
            for item in directory.iterdir():
                if item.is_file() and self._matches_patterns(item, file_patterns):
                    try:
                        self.validator.validate_file_size(item)
                        files.append(item)
                    except Exception as e:
                        self.logger.log_warning(f"Skipping file {item}: {str(e)}")
        except OSError as e:
            raise FileOperationError(f"Cannot access directory {directory}: {str(e)}")
        
        return files
    
    def _scan_directory_recursive(self, directory: Path,
                                 file_patterns: Optional[List[str]] = None) -> List[Path]:
        """Scan directory recursively.
        
        Args:
            directory: Directory to scan
            file_patterns: Optional file patterns to match
            
        Returns:
            List of file paths
        """
        files = []
        try:
            for root, dirs, filenames in os.walk(directory):
                root_path = Path(root)
                
                # Skip inaccessible directories
                if not self.permission_checker.check_directory_permissions(root_path, "read"):
                    self.logger.log_warning(f"Skipping inaccessible directory: {root_path}")
                    dirs.clear()  # Don't descend into subdirectories
                    continue
                
                for filename in filenames:
                    file_path = root_path / filename
                    
                    if self._matches_patterns(file_path, file_patterns):
                        try:
                            self.validator.validate_file_size(file_path)
                            files.append(file_path)
                        except Exception as e:
                            self.logger.log_warning(f"Skipping file {file_path}: {str(e)}")
        
        except OSError as e:
            raise FileOperationError(f"Error scanning directory {directory}: {str(e)}")
        
        return files
    
    def _scan_drive(self, drive_path: Path, recursive: bool,
                   file_patterns: Optional[List[str]] = None) -> List[Path]:
        """Scan drive for files.
        
        Args:
            drive_path: Drive path to scan
            recursive: Whether to scan recursively
            file_patterns: Optional file patterns to match
            
        Returns:
            List of file paths
        """
        if recursive:
            return self._scan_directory_recursive(drive_path, file_patterns)
        else:
            return self._scan_directory_flat(drive_path, file_patterns)
    
    def _matches_patterns(self, file_path: Path,
                         patterns: Optional[List[str]] = None) -> bool:
        """Check if file matches any of the given patterns.
        
        Args:
            file_path: File path to check
            patterns: List of patterns to match
            
        Returns:
            True if file matches any pattern or no patterns given
        """
        if not patterns:
            return True
        
        for pattern in patterns:
            if file_path.match(pattern):
                return True
        
        return False
    
    def encrypt_file(self, file_path: Path, algorithm: AlgorithmType, key: str,
                    extension: str, algorithm_params: Dict[str, Any],
                    delete_original: bool = False) -> Path:
        """Encrypt a single file.
        
        Args:
            file_path: Path to file to encrypt
            algorithm: Encryption algorithm
            key: Encryption key or password
            extension: Extension for encrypted file
            algorithm_params: Algorithm-specific parameters
            delete_original: Whether to delete original file
            
        Returns:
            Path to encrypted file
            
        Raises:
            EncryptionError: If encryption fails
        """
        try:
            # Validate inputs
            self.permission_checker.validate_permissions(str(file_path), "read")
            original_filename = file_path.name
            
            # Read file data
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Perform encryption based on algorithm
            if algorithm == AlgorithmType.AES128:
                aes_mode = AESMode(algorithm_params.get('aes_mode', 'CBC'))
                encrypted_data = self.crypto_engine.encrypt_aes(
                    data, key, aes_mode, 128, original_filename
                )
            
            elif algorithm == AlgorithmType.AES256:
                aes_mode = AESMode(algorithm_params.get('aes_mode', 'CBC'))
                encrypted_data = self.crypto_engine.encrypt_aes(
                    data, key, aes_mode, 256, original_filename
                )
            
            elif algorithm == AlgorithmType.RSA:
                key_size = algorithm_params.get('rsa_keysize', 2048)
                encrypted_data = self.crypto_engine.encrypt_rsa_hybrid(
                    data, key, key_size, original_filename
                )
            
            elif algorithm == AlgorithmType.BLOWFISH:
                key_size = algorithm_params.get('blowfish_keysize', 128)
                encrypted_data = self.crypto_engine.encrypt_blowfish(
                    data, key, key_size, original_filename
                )
            
            else:
                raise EncryptionError(f"Unsupported algorithm: {algorithm}")
            
            # Write encrypted file
            output_path = file_path.with_suffix(file_path.suffix + extension)
            self.permission_checker.validate_permissions(str(output_path.parent), "write")
            
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Delete original if requested
            if delete_original:
                self._secure_delete(file_path)
            
            self.logger.log_operation(
                operation="encrypt",
                algorithm=algorithm.value,
                input_path=str(file_path),
                output_path=str(output_path),
                status="SUCCESS",
                additional_info={
                    'file_size': len(data),
                    'encrypted_size': len(encrypted_data),
                    'original_deleted': delete_original
                }
            )
            
            return output_path
            
        except Exception as e:
            self.logger.log_operation(
                operation="encrypt",
                algorithm=algorithm.value,
                input_path=str(file_path),
                output_path="",
                status="FAILED",
                error_message=str(e)
            )
            raise EncryptionError(f"Failed to encrypt {file_path}: {str(e)}")
    
    def decrypt_file(self, file_path: Path, key: str,
                    algorithm_params: Dict[str, Any]) -> Path:
        """Decrypt a single file.
        
        Args:
            file_path: Path to encrypted file
            key: Decryption key or password
            algorithm_params: Algorithm-specific parameters
            
        Returns:
            Path to decrypted file
            
        Raises:
            DecryptionError: If decryption fails
        """
        try:
            # Validate permissions
            self.permission_checker.validate_permissions(str(file_path), "read")
            
            # Read encrypted data
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Extract metadata to determine algorithm
            metadata, _ = self.crypto_engine.metadata_manager.extract_metadata(encrypted_data)
            algorithm_name = metadata['algorithm']
            original_filename = metadata['original_filename']
            
            # Perform decryption based on algorithm
            if algorithm_name.startswith('AES'):
                parts = algorithm_name.split('-')
                key_size = int(parts[0][3:])  # Extract key size from AES128/AES256
                mode = AESMode(parts[1]) if len(parts) > 1 else AESMode.CBC
                decrypted_data, _ = self.crypto_engine.decrypt_aes(
                    encrypted_data, key, mode, key_size
                )
            
            elif algorithm_name.startswith('RSA'):
                passphrase = algorithm_params.get('passphrase')
                decrypted_data, _ = self.crypto_engine.decrypt_rsa_hybrid(
                    encrypted_data, key, passphrase
                )
            
            elif algorithm_name.startswith('Blowfish'):
                key_size = int(algorithm_name[8:]) if len(algorithm_name) > 8 else 128
                decrypted_data, _ = self.crypto_engine.decrypt_blowfish(
                    encrypted_data, key, key_size
                )
            
            else:
                raise DecryptionError(f"Unsupported algorithm: {algorithm_name}")
            
            # Determine output path
            if original_filename:
                output_path = file_path.parent / original_filename
            else:
                # Remove the custom extension to restore original
                output_path = file_path.with_suffix('')
            
            # Ensure we don't overwrite existing files
            if output_path.exists():
                counter = 1
                base_name = output_path.stem
                suffix = output_path.suffix
                while output_path.exists():
                    output_path = output_path.parent / f"{base_name}_{counter}{suffix}"
                    counter += 1
            
            # Write decrypted file
            self.permission_checker.validate_permissions(str(output_path.parent), "write")
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            self.logger.log_operation(
                operation="decrypt",
                algorithm=algorithm_name,
                input_path=str(file_path),
                output_path=str(output_path),
                status="SUCCESS",
                additional_info={
                    'encrypted_size': len(encrypted_data),
                    'decrypted_size': len(decrypted_data),
                    'original_filename': original_filename
                }
            )
            
            return output_path
            
        except Exception as e:
            self.logger.log_operation(
                operation="decrypt",
                algorithm="unknown",
                input_path=str(file_path),
                output_path="",
                status="FAILED",
                error_message=str(e)
            )
            raise DecryptionError(f"Failed to decrypt {file_path}: {str(e)}")
    
    def _secure_delete(self, file_path: Path) -> None:
        """Securely delete a file by overwriting it.
        
        Args:
            file_path: Path to file to delete
        """
        try:
            if file_path.exists():
                # Get file size
                file_size = file_path.stat().st_size
                
                # Overwrite with random data (basic secure deletion)
                with open(file_path, 'r+b') as f:
                    for _ in range(3):  # 3 passes
                        f.seek(0)
                        f.write(os.urandom(file_size))
                        f.flush()
                        os.fsync(f.fileno())
                
                # Delete the file
                file_path.unlink()
                
        except Exception as e:
            self.logger.log_warning(f"Failed to securely delete {file_path}: {str(e)}")
            # Fallback to regular deletion
            try:
                file_path.unlink()
            except:
                pass
    
    def process_files(self, path: str, mode: str, algorithm: AlgorithmType,
                     key: str, extension: str, recursive: bool,
                     delete_original: bool, algorithm_params: Dict[str, Any],
                     file_patterns: Optional[List[str]] = None) -> List[Path]:
        """Process multiple files for encryption/decryption.
        
        Args:
            path: Base path to process
            mode: Operation mode (encrypt/decrypt)
            algorithm: Encryption algorithm
            key: Encryption/decryption key
            extension: File extension for encrypted files
            recursive: Whether to process recursively
            delete_original: Whether to delete original files
            algorithm_params: Algorithm-specific parameters
            file_patterns: Optional file patterns to match
            
        Returns:
            List of processed file paths
            
        Raises:
            FileOperationError: If processing fails
        """
        try:
            files = self.get_files_to_process(path, recursive, file_patterns)
            processed_files = []
            failed_files = []
            
            self.logger.log_info(
                f"Starting {mode} operation on {len(files)} files",
                {'algorithm': algorithm.value, 'recursive': recursive}
            )
            
            for file_path in files:
                try:
                    if mode.lower() == 'encrypt':
                        result = self.encrypt_file(
                            file_path, algorithm, key, extension,
                            algorithm_params, delete_original
                        )
                    elif mode.lower() == 'decrypt':
                        result = self.decrypt_file(file_path, key, algorithm_params)
                    else:
                        raise FileOperationError(f"Invalid mode: {mode}")
                    
                    processed_files.append(result)
                    
                except Exception as e:
                    self.logger.log_error(f"Failed to process {file_path}: {str(e)}")
                    failed_files.append(str(file_path))
                    continue
            
            # Log summary
            self.logger.log_info(
                f"Operation completed: {len(processed_files)} succeeded, {len(failed_files)} failed",
                {
                    'succeeded': len(processed_files),
                    'failed': len(failed_files),
                    'failed_files': failed_files if failed_files else None
                }
            )
            
            return processed_files
            
        except Exception as e:
            error_msg = f"File processing failed: {str(e)}"
            self.logger.log_error(error_msg)
            raise FileOperationError(error_msg)