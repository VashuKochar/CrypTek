#!/usr/bin/env python3
"""
Enhanced build script for CrypTek with the new organized structure.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
import argparse


class CrypTekBuilder:
    """CrypTek build system."""
    
    def __init__(self, project_root: Path):
        """Initialize builder.
        
        Args:
            project_root: Root directory of the project
        """
        self.project_root = project_root
        self.src_dir = project_root / "src"
        self.dist_dir = project_root / "dist"
        self.build_dir = project_root / "build"
        self.scripts_dir = project_root / "scripts"
    
    def clean(self) -> None:
        """Clean build artifacts."""
        print("Cleaning build artifacts...")
        
        dirs_to_clean = [self.dist_dir, self.build_dir]
        for dir_path in dirs_to_clean:
            if dir_path.exists():
                shutil.rmtree(dir_path)
                print(f"  Removed {dir_path}")
        
        # Remove .spec files
        for spec_file in self.project_root.glob("*.spec"):
            spec_file.unlink()
            print(f"  Removed {spec_file}")
        
        # Remove __pycache__ directories
        for pycache in self.project_root.rglob("__pycache__"):
            shutil.rmtree(pycache)
            print(f"  Removed {pycache}")
    
    def install_dependencies(self) -> bool:
        """Install required dependencies."""
        print("Installing dependencies...")
        
        try:
            # Upgrade pip
            subprocess.run([
                sys.executable, "-m", "pip", "install", "--upgrade", "pip"
            ], check=True)
            
            # Install build dependencies
            subprocess.run([
                sys.executable, "-m", "pip", "install", ".[build]"
            ], check=True, cwd=self.project_root)
            
            print("Dependencies installed successfully!")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Failed to install dependencies: {e}")
            return False
    
    def build_cli(self) -> bool:
        """Build CLI executable."""
        print("Building CrypTek CLI executable...")
        
        entry_script = self.project_root / "cryptek_new.py"
        if not entry_script.exists():
            print(f"Entry script not found: {entry_script}")
            return False
        
        cmd = [
            "pyinstaller",
            "--onefile",
            "--name", "cryptek",
            "--distpath", str(self.dist_dir),
            "--workpath", str(self.build_dir),
            "--specpath", str(self.project_root),
            "--clean",
            "--add-data", f"{self.src_dir};src",
            "--hidden-import", "cryptography",
            "--hidden-import", "pycryptodome",
            str(entry_script)
        ]
        
        # Add Windows-specific options
        if sys.platform == "win32":
            cmd.extend([
                "--console",
                # "--icon", "assets/icon.ico",  # Add if icon exists
            ])
        
        try:
            subprocess.run(cmd, check=True, cwd=self.project_root)
            print("CLI build completed successfully!")
            return True
        except subprocess.CalledProcessError as e:
            print(f"CLI build failed: {e}")
            return False
    
    def build_gui(self) -> bool:
        """Build GUI executable."""
        print("Building CrypTek GUI executable...")
        
        # Use existing GUI entry script
        gui_script = self.project_root / "cryptek_gui.py"
        if not gui_script.exists():
            self._create_gui_entry_script(gui_script)
        
        cmd = [
            "pyinstaller",
            "--onefile",
            "--windowed",
            "--name", "cryptek-gui",
            "--distpath", str(self.dist_dir),
            "--workpath", str(self.build_dir),
            "--specpath", str(self.project_root),
            "--clean",
            "--add-data", f"{self.src_dir};src",
            "--hidden-import", "cryptography",
            "--hidden-import", "pycryptodome",
            "--hidden-import", "tkinter",
            str(gui_script)
        ]
        
        # Add Windows-specific options
        if sys.platform == "win32":
            cmd.extend([
                # "--icon", "assets/icon.ico",  # Add if icon exists
            ])
        
        try:
            subprocess.run(cmd, check=True, cwd=self.project_root)
            print("GUI build completed successfully!")
            return True
        except subprocess.CalledProcessError as e:
            print(f"GUI build failed: {e}")
            return False
    
    def _create_gui_entry_script(self, gui_script: Path) -> None:
        """Create GUI entry script."""
        # Use the existing GUI script
        existing_gui = self.project_root / "cryptek_gui.py"
        if existing_gui.exists():
            return
        
        content = '''#!/usr/bin/env python3
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
'''
        gui_script.write_text(content)
    
    def build_package(self) -> bool:
        """Build Python package."""
        print("Building Python package...")
        
        try:
            # Build wheel and source distribution
            subprocess.run([
                sys.executable, "-m", "build"
            ], check=True, cwd=self.project_root)
            
            print("Package build completed successfully!")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Package build failed: {e}")
            return False
    
    def run_tests(self) -> bool:
        """Run test suite."""
        print("Running tests...")
        
        try:
            subprocess.run([
                sys.executable, "-m", "pytest", "-v"
            ], check=True, cwd=self.project_root)
            
            print("All tests passed!")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Tests failed: {e}")
            return False
    
    def build_all(self) -> bool:
        """Build all targets."""
        print("=" * 60)
        print("CrypTek Enhanced Build System")
        print("=" * 60)
        
        steps = [
            ("Installing dependencies", self.install_dependencies),
            ("Running tests", self.run_tests),
            ("Building CLI executable", self.build_cli),
            ("Building GUI executable", self.build_gui),
            ("Building Python package", self.build_package),
        ]
        
        for step_name, step_func in steps:
            print(f"\\n{step_name}...")
            if not step_func():
                print(f"Build failed at step: {step_name}")
                return False
        
        print("\\n" + "=" * 60)
        print("Build completed successfully!")
        print("=" * 60)
        
        # List build artifacts
        if self.dist_dir.exists():
            print("\\nBuild artifacts:")
            for artifact in self.dist_dir.iterdir():
                print(f"  {artifact}")
        
        return True


def main():
    """Main build function."""
    parser = argparse.ArgumentParser(description="CrypTek build system")
    parser.add_argument("--clean", action="store_true", help="Clean build artifacts")
    parser.add_argument("--cli-only", action="store_true", help="Build CLI only")
    parser.add_argument("--gui-only", action="store_true", help="Build GUI only")
    parser.add_argument("--package-only", action="store_true", help="Build package only")
    parser.add_argument("--test-only", action="store_true", help="Run tests only")
    parser.add_argument("--no-tests", action="store_true", help="Skip tests")
    
    args = parser.parse_args()
    
    project_root = Path(__file__).parent.parent
    builder = CrypTekBuilder(project_root)
    
    if args.clean:
        builder.clean()
        return
    
    success = True
    
    if args.test_only:
        success = builder.run_tests()
    elif args.cli_only:
        if not args.no_tests:
            success = builder.run_tests()
        if success:
            success = builder.build_cli()
    elif args.gui_only:
        if not args.no_tests:
            success = builder.run_tests()
        if success:
            success = builder.build_gui()
    elif args.package_only:
        if not args.no_tests:
            success = builder.run_tests()
        if success:
            success = builder.build_package()
    else:
        # Build all
        success = builder.build_all()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()