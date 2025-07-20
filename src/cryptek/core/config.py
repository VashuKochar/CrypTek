"""Configuration management for CrypTek."""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

from .constants import (
    DEFAULT_AES_KEY_SIZE, DEFAULT_RSA_KEY_SIZE, DEFAULT_BLOWFISH_KEY_SIZE,
    LogFormat, AESMode, AlgorithmType
)


@dataclass
class SecurityConfig:
    """Security configuration settings."""
    min_password_length: int = 8
    require_password_complexity: bool = True
    secure_delete_passes: int = 3
    max_file_size_mb: int = 10240  # 10GB


@dataclass
class LoggingConfig:
    """Logging configuration settings."""
    default_format: str = LogFormat.TEXT.value
    max_log_size_mb: int = 100
    log_rotation_enabled: bool = True
    verbose_by_default: bool = False


@dataclass
class AlgorithmConfig:
    """Algorithm configuration settings."""
    default_algorithm: str = AlgorithmType.AES256.value
    default_aes_mode: str = AESMode.CBC.value
    default_aes_key_size: int = DEFAULT_AES_KEY_SIZE
    default_rsa_key_size: int = DEFAULT_RSA_KEY_SIZE
    default_blowfish_key_size: int = DEFAULT_BLOWFISH_KEY_SIZE


@dataclass
class FileConfig:
    """File processing configuration settings."""
    default_extension: str = ".vault"
    enable_recursive_by_default: bool = False
    backup_original_files: bool = False
    chunk_size_kb: int = 64


@dataclass
class CrypTekConfig:
    """Main CrypTek configuration."""
    security: SecurityConfig
    logging: LoggingConfig
    algorithms: AlgorithmConfig
    files: FileConfig
    
    def __init__(self):
        """Initialize with default configurations."""
        self.security = SecurityConfig()
        self.logging = LoggingConfig()
        self.algorithms = AlgorithmConfig()
        self.files = FileConfig()


class ConfigManager:
    """Manages CrypTek configuration."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration manager.
        
        Args:
            config_path: Optional path to configuration file
        """
        if config_path:
            self.config_path = Path(config_path)
        else:
            self.config_path = self._get_default_config_path()
        
        self.config = CrypTekConfig()
        self.load_config()
    
    def _get_default_config_path(self) -> Path:
        """Get default configuration file path.
        
        Returns:
            Path to default configuration file
        """
        if os.name == 'nt':  # Windows
            config_dir = Path(os.environ.get('APPDATA', '')) / 'CrypTek'
        else:  # Unix-like
            config_dir = Path.home() / '.config' / 'cryptek'
        
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir / 'config.json'
    
    def load_config(self) -> None:
        """Load configuration from file."""
        if not self.config_path.exists():
            # Create default configuration file
            self.save_config()
            return
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            # Update configuration with loaded data
            if 'security' in config_data:
                for key, value in config_data['security'].items():
                    if hasattr(self.config.security, key):
                        setattr(self.config.security, key, value)
            
            if 'logging' in config_data:
                for key, value in config_data['logging'].items():
                    if hasattr(self.config.logging, key):
                        setattr(self.config.logging, key, value)
            
            if 'algorithms' in config_data:
                for key, value in config_data['algorithms'].items():
                    if hasattr(self.config.algorithms, key):
                        setattr(self.config.algorithms, key, value)
            
            if 'files' in config_data:
                for key, value in config_data['files'].items():
                    if hasattr(self.config.files, key):
                        setattr(self.config.files, key, value)
        
        except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
            # If config is corrupted, reset to defaults
            self.config = CrypTekConfig()
            self.save_config()
    
    def save_config(self) -> None:
        """Save configuration to file."""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            config_data = {
                'security': asdict(self.config.security),
                'logging': asdict(self.config.logging),
                'algorithms': asdict(self.config.algorithms),
                'files': asdict(self.config.files)
            }
            
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
        
        except OSError as e:
            # If we can't save config, continue with defaults
            pass
    
    def get_setting(self, section: str, key: str) -> Any:
        """Get a configuration setting.
        
        Args:
            section: Configuration section (security, logging, algorithms, files)
            key: Setting key
            
        Returns:
            Setting value or None if not found
        """
        section_obj = getattr(self.config, section, None)
        if section_obj:
            return getattr(section_obj, key, None)
        return None
    
    def set_setting(self, section: str, key: str, value: Any) -> bool:
        """Set a configuration setting.
        
        Args:
            section: Configuration section
            key: Setting key
            value: Setting value
            
        Returns:
            True if setting was updated successfully
        """
        section_obj = getattr(self.config, section, None)
        if section_obj and hasattr(section_obj, key):
            setattr(section_obj, key, value)
            return True
        return False
    
    def reset_to_defaults(self) -> None:
        """Reset configuration to defaults."""
        self.config = CrypTekConfig()
        self.save_config()
    
    def validate_config(self) -> Dict[str, list]:
        """Validate configuration settings.
        
        Returns:
            Dictionary with validation errors by section
        """
        errors = {
            'security': [],
            'logging': [],
            'algorithms': [],
            'files': []
        }
        
        # Validate security settings
        if self.config.security.min_password_length < 4:
            errors['security'].append("min_password_length must be at least 4")
        
        if self.config.security.secure_delete_passes < 1:
            errors['security'].append("secure_delete_passes must be at least 1")
        
        if self.config.security.max_file_size_mb < 1:
            errors['security'].append("max_file_size_mb must be at least 1")
        
        # Validate logging settings
        if self.config.logging.max_log_size_mb < 1:
            errors['logging'].append("max_log_size_mb must be at least 1")
        
        # Validate algorithm settings
        valid_algorithms = [alg.value for alg in AlgorithmType]
        if self.config.algorithms.default_algorithm not in valid_algorithms:
            errors['algorithms'].append(f"default_algorithm must be one of {valid_algorithms}")
        
        valid_aes_modes = [mode.value for mode in AESMode]
        if self.config.algorithms.default_aes_mode not in valid_aes_modes:
            errors['algorithms'].append(f"default_aes_mode must be one of {valid_aes_modes}")
        
        # Validate file settings
        if not self.config.files.default_extension.startswith('.'):
            errors['files'].append("default_extension must start with '.'")
        
        if self.config.files.chunk_size_kb < 1:
            errors['files'].append("chunk_size_kb must be at least 1")
        
        # Remove empty error lists
        return {k: v for k, v in errors.items() if v}


# Global configuration instance
_config_manager: Optional[ConfigManager] = None


def get_config() -> ConfigManager:
    """Get global configuration manager instance.
    
    Returns:
        Global ConfigManager instance
    """
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


def set_config_path(config_path: str) -> None:
    """Set custom configuration file path.
    
    Args:
        config_path: Path to configuration file
    """
    global _config_manager
    _config_manager = ConfigManager(config_path)