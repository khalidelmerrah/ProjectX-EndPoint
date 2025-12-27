# -*- mode: python ; coding: utf-8 -*-

"""
FILE: ProjectX_Secure.spec
================================================================================
PROJECT:        ProjectX Endpoint Protection Platform
PURPOSE:        PyInstaller Build Specification
AUTHOR:         ProjectX Development Team (Academic)
DATE:           2025-12-27
================================================================================

ACADEMIC NOTE:
--------------
This file defines how the Python interpreter acts as a "Linker" to bundle 
script files, binary dependencies (DLLs), and data assets into a single 
executable (ProjectX_Secure.exe).

We use `Analysis` to find imports, `PYZ` to compress Python bytecode, 
and `EXE` to package it all with the Bootloader.

HIDDEN IMPORTS:
---------------
Dynamic imports (e.g., `importlib.import_module`) are often missed by 
static analysis. We explicitly list them here:
- `engineio.async_drivers.threading`: Required for SocketIO (if used).
- `keyring.backends.Windows`: Platform-specific backend for secrets.
- `win32timezone`: Required by `wmi` datetime parsing.
"""

block_cipher = None

a = Analysis(
    ['app.py'],
    pathex=['C:\\ProjectX-Desktop'],
    binaries=[],
    datas=[
        # (Source, Destination)
        ('config.json', '.'), 
        ('bin/osqueryi.exe', 'bin'), # Bundling the Sidecar Binary
        ('projectx_docs.html', '.')  # Bundling the Documentation
    ],
    hiddenimports=[
        'engineio.async_drivers.threading',
        'keyring.backends.Windows',
        'win32timezone',
        'wmi',
        'yara',
        'requests',
        'psutil'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    name='ProjectX_Secure',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False, # FALSE = No Popup Terminal (GUI Mode)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='resources/icon.ico' # Placeholder icon path
)
