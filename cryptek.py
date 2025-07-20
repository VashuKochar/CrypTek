#!/usr/bin/env python3
"""
CrypTek CLI - New organized version
Entry point for the command line interface
"""

import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from cryptek.cli.main import main

if __name__ == "__main__":
    sys.exit(main())