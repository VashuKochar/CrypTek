"""Command line argument parser for CrypTek."""

import argparse
from pathlib import Path

from ..core.constants import (
    AlgorithmType, AESMode, LogFormat, RSA_KEY_SIZES,
    BLOWFISH_MIN_KEY_SIZE, BLOWFISH_MAX_KEY_SIZE, VERSION
)


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the command line argument parser.
    
    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        prog='cryptek',
        description='CrypTek - Encrypt/decrypt files, folders, and drives',
        epilog='Example: cryptek --mode encrypt --path "docs" --algo AES256 '
               '--key "password" --ext ".vault" --log "audit.log"',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Version
    parser.add_argument(
        '--version', action='version', version=f'CrypTek {VERSION}'
    )
    
    # Required arguments
    required_group = parser.add_argument_group('required arguments')
    
    required_group.add_argument(
        '--mode', required=True, choices=['encrypt', 'decrypt'],
        help='Operation mode: encrypt or decrypt'
    )
    
    required_group.add_argument(
        '--path', required=True, type=str,
        help='Target file, folder, or drive path'
    )
    
    required_group.add_argument(
        '--key', required=True, type=str,
        help='Password or key file path'
    )
    
    required_group.add_argument(
        '--log', required=True, type=str,
        help='Path to audit log file'
    )
    
    # Algorithm options
    algo_group = parser.add_argument_group('algorithm options')
    
    algo_group.add_argument(
        '--algo', default='AES256',
        choices=[alg.value for alg in AlgorithmType],
        help='Encryption algorithm (default: AES256)'
    )
    
    algo_group.add_argument(
        '--aes-mode', default='CBC',
        choices=[mode.value for mode in AESMode],
        help='AES mode: CBC or GCM (default: CBC)'
    )
    
    algo_group.add_argument(
        '--rsa-keysize', type=int, default=2048,
        choices=RSA_KEY_SIZES,
        help='RSA key size in bits (default: 2048)'
    )
    
    algo_group.add_argument(
        '--blowfish-keysize', type=int, default=128,
        help=f'Blowfish key size in bits: {BLOWFISH_MIN_KEY_SIZE}-{BLOWFISH_MAX_KEY_SIZE} (default: 128)'
    )
    
    # File options
    file_group = parser.add_argument_group('file options')
    
    file_group.add_argument(
        '--ext', type=str,
        help='Custom extension for encrypted output (required for encrypt mode)'
    )
    
    file_group.add_argument(
        '--recursive', action='store_true',
        help='Process folders recursively'
    )
    
    file_group.add_argument(
        '--delete-original', action='store_true',
        help='Delete source files after encryption'
    )
    
    file_group.add_argument(
        '--patterns', nargs='+', type=str,
        help='File patterns to match (e.g., "*.txt" "*.doc")'
    )
    
    # Logging options
    log_group = parser.add_argument_group('logging options')
    
    log_group.add_argument(
        '--log-format', default='text',
        choices=[fmt.value for fmt in LogFormat],
        help='Log format: text or json (default: text)'
    )
    
    log_group.add_argument(
        '--verbose', '-v', action='store_true',
        help='Enable verbose output'
    )
    
    log_group.add_argument(
        '--quiet', '-q', action='store_true',
        help='Suppress non-error output'
    )
    
    # RSA-specific options
    rsa_group = parser.add_argument_group('RSA options')
    
    rsa_group.add_argument(
        '--passphrase', type=str,
        help='Passphrase for encrypted private key files'
    )
    
    # Security options
    security_group = parser.add_argument_group('security options')
    
    security_group.add_argument(
        '--no-password-validation', action='store_true',
        help='Skip password strength validation'
    )
    
    security_group.add_argument(
        '--force', action='store_true',
        help='Force operation even with warnings'
    )
    
    return parser


def validate_args(args: argparse.Namespace) -> None:
    """Validate parsed command line arguments.
    
    Args:
        args: Parsed arguments namespace
        
    Raises:
        argparse.ArgumentError: If validation fails
    """
    errors = []
    
    # Check if extension is provided for encryption
    if args.mode == 'encrypt' and not args.ext:
        errors.append("--ext is required for encryption mode")
    
    # Ensure extension starts with dot
    if args.ext and not args.ext.startswith('.'):
        args.ext = '.' + args.ext
    
    # Validate Blowfish key size
    if args.algo == 'Blowfish':
        if not (BLOWFISH_MIN_KEY_SIZE <= args.blowfish_keysize <= BLOWFISH_MAX_KEY_SIZE):
            errors.append(
                f"Blowfish key size must be between {BLOWFISH_MIN_KEY_SIZE} "
                f"and {BLOWFISH_MAX_KEY_SIZE} bits"
            )
    
    # Check mutually exclusive options
    if args.verbose and args.quiet:
        errors.append("--verbose and --quiet cannot be used together")
    
    # Validate paths exist
    if not Path(args.path).exists():
        errors.append(f"Path does not exist: {args.path}")
    
    # Check if key file exists (for RSA)
    if args.algo == 'RSA':
        key_path = Path(args.key)
        if key_path.is_file() and not key_path.exists():
            errors.append(f"Key file does not exist: {args.key}")
    
    # Validate log directory
    log_path = Path(args.log)
    log_dir = log_path.parent
    if not log_dir.exists():
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f"Cannot create log directory: {e}")
    
    if errors:
        error_msg = "\\n".join(f"Error: {error}" for error in errors)
        raise argparse.ArgumentError(None, error_msg)