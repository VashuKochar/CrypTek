"""Main CLI entry point for CrypTek."""

import sys
from pathlib import Path
from typing import Optional

from .parser import create_parser, validate_args
from ..core.constants import AlgorithmType, AESMode, LogFormat
from ..core.exceptions import CrypTekError
from ..utils.logger import CrypTekLogger
from ..utils.file_operations import FileOperations
from ..utils.validation import InputValidator
from ..utils.permissions import PermissionChecker


def setup_logging(log_path: str, log_format: str, verbose: bool, quiet: bool) -> CrypTekLogger:
    """Set up logging configuration.
    
    Args:
        log_path: Path to log file
        log_format: Log format (text/json)
        verbose: Enable verbose logging
        quiet: Suppress output
        
    Returns:
        Configured logger instance
    """
    logger = CrypTekLogger(log_path, LogFormat(log_format))
    
    if verbose:
        logger.logger.setLevel("DEBUG")
    elif quiet:
        logger.logger.setLevel("ERROR")
    else:
        logger.logger.setLevel("INFO")
    
    return logger


def print_output(message: str, quiet: bool = False, error: bool = False) -> None:
    """Print output message to appropriate stream.
    
    Args:
        message: Message to print
        quiet: Suppress non-error output
        error: Whether this is an error message
    """
    if error:
        print(f"Error: {message}", file=sys.stderr)
    elif not quiet:
        print(message)


def main() -> int:
    """Main CLI entry point.
    
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    try:
        # Parse arguments
        parser = create_parser()
        args = parser.parse_args()
        
        # Validate arguments
        validate_args(args)
        
        # Set up logging
        logger = setup_logging(args.log, args.log_format, args.verbose, args.quiet)
        
        # Log startup
        logger.log_info(
            f"CrypTek CLI started",
            {
                'mode': args.mode,
                'algorithm': args.algo,
                'path': args.path,
                'recursive': args.recursive
            }
        )
        
        # Print startup message
        print_output(
            f"CrypTek - {args.mode.title()} operation starting...",
            args.quiet
        )
        
        # Initialize components
        validator = InputValidator()
        permission_checker = PermissionChecker()
        file_ops = FileOperations(logger)
        
        # Validate inputs
        try:
            algorithm = validator.validate_algorithm(args.algo)
            path_obj = validator.validate_path(args.path, must_exist=True)
            
            # Validate password if not using key file
            if algorithm != AlgorithmType.RSA or not Path(args.key).is_file():
                if not args.no_password_validation:
                    validator.validate_password(args.key)
            
            # Validate extension for encryption
            if args.mode == 'encrypt':
                extension = validator.validate_extension(args.ext)
            else:
                extension = ""
            
            # Check permissions
            permission_checker.validate_permissions(args.path, "read")
            
            if permission_checker.requires_admin(args.path):
                if not permission_checker.is_admin():
                    if not args.force:
                        print_output(
                            "Administrator privileges may be required for this operation. "
                            "Use --force to continue anyway.",
                            args.quiet, error=True
                        )
                        return 1
                else:
                    print_output("Running with administrator privileges", args.quiet)
            
        except CrypTekError as e:
            print_output(str(e), args.quiet, error=True)
            logger.log_error("Input validation failed", str(e))
            return 1
        
        # Prepare algorithm parameters
        algorithm_params = {
            'aes_mode': args.aes_mode,
            'rsa_keysize': args.rsa_keysize,
            'blowfish_keysize': args.blowfish_keysize,
            'passphrase': args.passphrase
        }
        
        # Process files
        try:
            print_output(f"Processing files in: {args.path}", args.quiet)
            
            processed_files = file_ops.process_files(
                path=args.path,
                mode=args.mode,
                algorithm=algorithm,
                key=args.key,
                extension=extension,
                recursive=args.recursive,
                delete_original=args.delete_original,
                algorithm_params=algorithm_params,
                file_patterns=args.patterns
            )
            
            # Report results
            print_output(
                f"Operation completed successfully!",
                args.quiet
            )
            print_output(
                f"Processed {len(processed_files)} files",
                args.quiet
            )
            
            if args.verbose and not args.quiet:
                print("Processed files:")
                for file_path in processed_files:
                    print(f"  {file_path}")
            
            logger.log_info(
                f"CLI operation completed successfully",
                {
                    'files_processed': len(processed_files),
                    'mode': args.mode,
                    'algorithm': args.algo
                }
            )
            
            return 0
            
        except CrypTekError as e:
            error_msg = f"Operation failed: {str(e)}"
            print_output(error_msg, args.quiet, error=True)
            logger.log_error("CLI operation failed", str(e))
            return 1
    
    except KeyboardInterrupt:
        print_output("Operation cancelled by user", False, error=True)
        return 130  # Standard exit code for SIGINT
    
    except Exception as e:
        print_output(f"Unexpected error: {str(e)}", False, error=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())