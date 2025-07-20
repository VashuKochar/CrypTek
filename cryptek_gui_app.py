#!/usr/bin/env python3
"""
CrypTek GUI Entry Point - For PyInstaller
Direct import without path manipulation
"""

if __name__ == "__main__":
    import sys
    try:
        from src.cryptek.gui.main import main
        sys.exit(main())
    except ImportError:
        # Fallback for installed package
        from cryptek.gui.main import main
        sys.exit(main())