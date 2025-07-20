"""CLI module for CrypTek."""

from .main import main as cli_main
from .parser import create_parser

__all__ = ["cli_main", "create_parser"]