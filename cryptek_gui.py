#!/usr/bin/env python3
"""
CrypTek GUI - Graphical User Interface
Entry point for the Tkinter-based GUI
"""

import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from cryptek.gui.main import main

if __name__ == "__main__":
    sys.exit(main())