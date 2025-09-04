#!/usr/bin/env python3
"""
PyInstaller build script for Mesh Network Application
Creates standalone executable with all dependencies
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

def clean_build_dirs():
    """Clean previous build directories"""
    dirs_to_clean = ['build', 'dist', '__pycache__']
    
    for dir_name in dirs_to_clean:
        if os.path.exists(dir_name):
            print(f"Cleaning {dir_name}...")
            shutil.rmtree(dir_name)

def create_spec_file():
    """Create PyInstaller spec file with custom configuration"""
    spec_content = '''
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

# Data files to include
added_files = [
    ('assets/*', 'assets'),  # Include any asset files
    ('config/*', 'config'),  # Include config files if any
]

a = Analysis(
    ['mesh_network_app.py'],
    pathex=[],
    binaries=[],
    datas=added_files,
    hiddenimports=[
        'tkinter',
        'tkinter.ttk',
        'tkinter.messagebox',
        'tkinter.filedialog',
        'tkinter.simpledialog',
        'tkinter.font',
        'threading',
        'json',
        'datetime',
        'pathlib',
        'subprocess',
        'platform',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',
        'numpy',
        'PIL',
        'PyQt5',
        'PyQt6',
        'PySide2',
        'PySide6',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='MeshNetwork',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Set to True for debugging
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/icon.ico' if os.path.exists('assets/icon.ico') else None,
)

# For directory distribution (alternative to single file)
# coll = COLLECT(
#     exe,
#     a.binaries,
#     a.zipfiles,
#     a.datas,
#     strip=False,
#     upx=True,
#     upx_exclude=[],
#     name='MeshNetwork'
# )
'''
    
    with open('mesh_network.spec', 'w') as f:
        f.write(spec_content.strip())
    
    print("Created mesh_network.spec file")

def build_executable():
    """Build the executable using PyInstaller"""
    print("Building executable...")
    
    try:
        # Run PyInstaller with the spec file
        result = subprocess.run([
            sys.executable, '-m', 'PyInstaller',
            '--clean',
            'mesh_network.spec'
        ], check=True, capture_output=True, text=True)
        
        print("Build completed successfully!")
        print(result.stdout)
        
    except subprocess.CalledProcessError as e:
        print(f"Build failed: {e}")
        print(f"Error output: {e.stderr}")
        return False
    
    return True

def create_installer_script():
    """Create an NSIS installer script for Windows"""
    nsis_script = '''
; Mesh Network Installer Script for NSIS

!define APP_NAME "Mesh Network"
!define APP_VERSION "1.0.0"
!define APP_PUBLISHER "Your Company"
!define APP_EXE "MeshNetwork.exe"

; Modern UI
!include "MUI2.nsh"

; General settings
Name "${APP_NAME}"
OutFile "MeshNetworkInstaller.exe"
InstallDir "$PROGRAMFILES\\${APP_NAME}"
InstallDirRegKey HKCU "Software\\${APP_NAME}" ""
RequestExecutionLevel admin

; Interface Settings
!define MUI_ABORTWARNING
!define MUI_ICON "assets\\icon.ico"
!define MUI_UNICON "assets\\icon.ico"

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; Languages
!insertmacro MUI_LANGUAGE "English"

; Installation
Section "Main Application" SecMain
    SetOutPath "$INSTDIR"
    File "dist\\${APP_EXE}"
    File /r "dist\\*"
    
    ; Create shortcuts
    CreateDirectory "$SMPROGRAMS\\${APP_NAME}"
    CreateShortCut "$SMPROGRAMS\\${APP_NAME}\\${APP_NAME}.lnk" "$INSTDIR\\${APP_EXE}"
    CreateShortCut "$DESKTOP\\${APP_NAME}.lnk" "$INSTDIR\\${APP_EXE}"
    
    ; Registry
    WriteRegStr HKCU "Software\\${APP_NAME}" "" $INSTDIR
    WriteUninstaller "$INSTDIR\\Uninstall.exe"
SectionEnd

; Uninstallation
Section "Uninstall"
    Delete "$INSTDIR\\${APP_EXE}"
    Delete "$INSTDIR\\Uninstall.exe"
    RMDir /r "$INSTDIR"
    
    Delete "$SMPROGRAMS\\${APP_NAME}\\${APP_NAME}.lnk"
    Delete "$DESKTOP\\${APP_NAME}.lnk"
    RMDir "$SMPROGRAMS\\${APP_NAME}"
    
    DeleteRegKey HKCU "Software\\${APP_NAME}"
SectionEnd
'''
    
    with open('installer.nsi', 'w') as f:
        f.write(nsis_script.strip())
    
    print("Created installer.nsi file")

def create_build_requirements():
    """Create requirements.txt for build dependencies"""
    requirements = """# Build requirements for Mesh Network Application
pyinstaller>=5.13.0
auto-py-to-exe>=2.40.0  # Optional GUI for PyInstaller

# Runtime requirements (these will be bundled)
# Add your mesh network dependencies here when implemented
# cryptography>=41.0.0  # For encryption
# socket  # Built-in
# threading  # Built-in
# json  # Built-in
"""
    
    with open('requirements-build.txt', 'w') as f:
        f.write(requirements.strip())
    
    print("Created requirements-build.txt")

def create_batch_scripts():
    """Create convenient batch scripts for Windows"""
    
    # Build script
    build_bat = '''@echo off
echo Building Mesh Network Application...
echo.

REM Activate virtual environment if it exists
if exist venv\\Scripts\\activate.bat (
    echo Activating virtual environment...
    call venv\\Scripts\\activate.bat
)

REM Install build requirements
echo Installing build requirements...
pip install -r requirements-build.txt

REM Clean and build
echo Cleaning previous builds...
python build.py

echo.
echo Build complete! Check the dist/ folder for your executable.
pause
'''
    
    with open('build.bat', 'w') as f:
        f.write(build_bat)
    
    # Quick run script
    run_bat = '''@echo off
echo Running Mesh Network Application...
if exist dist\\MeshNetwork.exe (
    cd dist
    MeshNetwork.exe
) else (
    echo Executable not found! Please build first using build.bat
    pause
)
'''
    
    with open('run.bat', 'w') as f:
        f.write(run_bat)
    
    print("Created build.bat and run.bat")

def create_linux_scripts():
    """Create build script for Linux/Mac"""
    
    build_sh = '''#!/bin/bash
echo "Building Mesh Network Application..."
echo

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
fi

# Install build requirements
echo "Installing build requirements..."
pip install -r requirements-build.txt

# Clean and build
echo "Cleaning previous builds..."
python3 build.py

echo
echo "Build complete! Check the dist/ folder for your executable."
'''
    
    with open('build.sh', 'w') as f:
        f.write(build_sh)
    
    # Make executable
    os.chmod('build.sh', 0o755)
    
    print("Created build.sh")

def setup_assets_folder():
    """Create assets folder with placeholder files"""
    assets_dir = Path('assets')
    assets_dir.mkdir(exist_ok=True)
    
    # Create a simple README for assets
    readme_content = """# Assets Folder

Place your application assets here:

- icon.ico: Application icon (256x256 recommended)
- splash.png: Splash screen image (optional)
- sounds/: Sound files (optional)
- themes/: Custom theme files (optional)

The build script will automatically include these files in the executable.
"""
    
    with open(assets_dir / 'README.md', 'w') as f:
        f.write(readme_content.strip())
    
    print("Created assets/ folder")

def main():
    """Main build orchestration"""
    print("=== Mesh Network Application - PyInstaller Setup ===")
    print()
    
    # Check if PyInstaller is installed
    try:
        import PyInstaller
        print(f"PyInstaller version: {PyInstaller.__version__}")
    except ImportError:
        print("PyInstaller not found. Installing...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pyinstaller'])
    
    # Create all necessary files
    clean_build_dirs()
    create_spec_file()
    create_installer_script()
    create_build_requirements()
    create_batch_scripts()
    create_linux_scripts()
    setup_assets_folder()
    
    print()
    print("Setup complete! Next steps:")
    print()
    print("1. Install build requirements:")
    print("   pip install -r requirements-build.txt")
    print()
    print("2. Build the executable:")
    print("   Windows: build.bat")
    print("   Linux/Mac: ./build.sh")
    print("   Or manually: python build.py")
    print()
    print("3. Find your executable in the dist/ folder")
    print()
    
    # Optionally build immediately
    build_now = input("Build executable now? (y/n): ").lower().strip()
    if build_now == 'y':
        if build_executable():
            print()
            print("✓ Build successful!")
            print(f"✓ Executable created: dist/MeshNetwork{'.exe' if os.name == 'nt' else ''}")
            print()
            
            # Show file size
            exe_name = 'MeshNetwork.exe' if os.name == 'nt' else 'MeshNetwork'
            exe_path = Path('dist') / exe_name
            if exe_path.exists():
                size_mb = exe_path.stat().st_size / (1024 * 1024)
                print(f"Executable size: {size_mb:.1f} MB")

if __name__ == "__main__":
    main()
    