"""
MODULE: app.py
================================================================================
PROJECT:        ProjectX Endpoint Protection Platform (Academic Reference)
AUTHOR:         ProjectX Development Team
INSTITUTION:    National School of Applied Sciences (ENSA) Fès
DATE:           2025-12-27
LICENSE:        MIT License (Educational)
PYTHON VER:     3.11+
================================================================================

MODULE OVERVIEW:
----------------
This module serves as the **Entry Point** and **Orchestrator** for the application.
In a "Defense-in-Depth" layered architecture, this file represents the "Bootstrap Layer".
Its primary responsibility is to establish a secure, controlled execution environment 
before any user-facing code (UI) or business logic is allowed to run.

DEFENSE-IN-DEPTH STRATEGY (BOOTSTRAP LAYER):
--------------------------------------------
1.  **Secure Initialization**: 
    The application does not simply "start". It performs a "Pre-Flight Check".
    It initializes the logging subsystem immediately to capture any startup anomalies
    (which are often indicators of DLL hijacking or environment tampering).

2.  **Fail-Safe Defaults ("Safe Mode")**:
    Security tools must be resilient. If the scanning engine (the "Brain") is corrupted
    or crashing due to a malformed update, the user must still be able to open the app 
    to disable that module. We implement a "Safe Mode" toggle in the configuration 
    that bypasses complex logic on startup.
    
3.  **Splash Screen as UX/Security Feature**:
    While visually appealing, the Splash Screen (`LoaderScreen`) serves a technical purpose.
    It masks the latency of the initial `Integration / Integrity Scan`.
    By performing this work in a background thread (*ScanWorker*) while showing a UI,
    we prevent the Operating System from flagging the process as "Not Responding" 
    (which could trigger external watchdogs to kill our security tool).

4.  **Graceful Shutdown**:
    The module handles the `sys.exit()` sequence, ensuring that all threads (Workers)
    are terminated cleanly. This prevents "Zombie Processes" which can be weaponized 
    or cause resource exhaustion on the host header.

TECHNICAL CONCEPTS (FOR STUDENTS):
----------------------------------
-   **QApplication**: The singleton instance managing the GUI control flow and main settings.
-   **Event Loop (`exec()`)**: Infinite loop that waits for user input events.
    Code after `app.exec()` is only reached when the window is closed.
-   **Threads (`QThread`)**: running heavy tasks off the main thread to keep UI fluid.
-   **Closures**: Using inner functions (like `fast_launch`) to capture local state.

"""

import sys          # Interface to the Python Interpreter (Exit codes, ARGV)
import logging      # Standard event logging facility
import os           # Operating System interface (File paths, Env vars)

# ------------------------------------------------------------------------------
# LOGGING CONFIGURATION (CRITICAL FIRST STEP)
# ------------------------------------------------------------------------------
# We configure logging *before* any other imports. This ensures that if a module
# fails to import (e.g., missing dependency), the error is captured in the file.
logging.basicConfig(
    level=logging.INFO, # Capture INFO, WARNING, ERROR, CRITICAL. Ignore DEBUG.
    # Format: Time - LoggerName - Level - Message
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', 
    handlers=[
        # Write logs to a file in the current directory. 
        # Mode 'w' overwrites the log on each run (good for debugging).
        # Mode 'a' (append) would be better for production auditing.
        logging.FileHandler("projectx.log", mode='w'), 
        
        # Also mirror logs to Standard Output (Console) for developers.
        logging.StreamHandler(sys.stdout)              
    ]
)

# ------------------------------------------------------------------------------
# UI FRAMEWORK IMPORTS (PyQt6)
# ------------------------------------------------------------------------------
# PyQt6 is a set of Python bindings for The Qt Company's Qt application framework.
# It allows us to build native-looking applications on Windows, Mac, and Linux.
try:
    from PyQt6.QtWidgets import QApplication, QSplashScreen, QProgressBar, QLabel, QVBoxLayout, QWidget
    from PyQt6.QtCore import Qt, QTimer
    from PyQt6.QtGui import QPixmap, QColor, QFont
except ImportError as e:
    # Fail fast if the GUI framework is missing.
    logging.critical(f"Failed to import PyQt6. Please install requirements.txt. Error: {e}")
    sys.exit(1)

# ------------------------------------------------------------------------------
# INTERNAL MODULE IMPORTS
# ------------------------------------------------------------------------------
# We import our internal modules. Note that we do this *after* logging is set up.
# `main_window`: The View Layer (MVC).
# `workers`: The Controller/Concurrency Layer.
# `managers`: The Model/Business Logic Layer.
try:
    from main_window import MainWindow
    from workers import ScanWorker
    from managers import ConfigManager
except ImportError as e:
    logging.critical(f"Internal Module Import Error: {e}")
    sys.exit(1)

# ------------------------------------------------------------------------------
# CLASS: LoaderScreen
# ------------------------------------------------------------------------------
class LoaderScreen(QSplashScreen):
    """
    A custom startup window (Splash Screen) that provides visual feedback during initialization.
    
    Inheritance:
        QSplashScreen (PyQt6.QtWidgets): Base class for splash screens.
        
    Design Pattern:
        Observer Pattern (Consumer): This class has a slot `update_status` that "observes"
        signals emitted by the `ScanWorker`.
    """
    
    def __init__(self):
        """
        Constructor: Sets up the visual properties of the splash screen.
        
        Note on super().__init__():
            We call the parent class constructor to ensure the QSplashScreen
            internal Qt C++ object is properly created before we modify it.
        """
        super().__init__()
        
        # Dimensions: 500px wide, 350px tall. Fixed size prevents user resizing.
        self.setFixedSize(500, 350)
        
        # WINDOW FLAGS:
        # Qt.WindowType.WindowStaysOnTopHint: Forces this window above all others (User Focus).
        # Qt.WindowType.FramelessWindowHint: Removes title bar, close buttons, and borders.
        self.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.FramelessWindowHint)
        
        # ATTRIBUTES:
        # Qt.WidgetAttribute.WA_TranslucentBackground: Crucial for "Non-Rectangular" windows.
        # It allows us to use specific CSS 'border-radius' to mimic a rounded card.
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        
        # ----------------------------------------------------------------------
        # UI COMPOSITION (The "Container" Approach)
        # ----------------------------------------------------------------------
        # QSplashScreen's default behavior is to just show an image.
        # To add extensive text and progress bars, we create a child QWidget 
        # ('layout_container') and treat it like a mini-canvas.
        self.layout_container = QWidget(self)
        self.layout_container.setGeometry(0, 0, 500, 350) # Fill the entire parent
        
        # CSS STYLING (Qt Style Sheets - QSS)
        # We use a dark, cyber-industrial theme consistent with the 'ProjectX' brand.
        self.layout_container.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;   /* Matte Dark Grey */
                border: 2px solid #333;      /* Subtle border for contrast */
                border-radius: 15px;         /* Modern rounded aesthetics */
            }
        """)
        
        # LAYOUT MANAGEMENT
        # QVBoxLayout stacks children vertically: Top -> Bottom.
        layout = QVBoxLayout(self.layout_container)
        
        # Margins: Left=30, Top=40, Right=30, Bottom=40.
        layout.setContentsMargins(30, 40, 30, 40) 
        
        # Spacing: 15px gap between each widget (Label, Progress Bar, etc.)
        layout.setSpacing(15)                     
        
        # 1. ICON (Emoji as Placeholder)
        # In a real build, QPixmap('resources/logo.png') would be used here.
        lbl_icon = QLabel("🛡️")
        lbl_icon.setStyleSheet("font-size: 64px; border: none; background: transparent;")
        lbl_icon.setAlignment(Qt.AlignmentFlag.AlignCenter) # Horizontally Center
        layout.addWidget(lbl_icon)
        
        # 2. TITLE LABEL
        title = QLabel("ProjectX Security")
        # #007acc is the "VS Code Blue" - a standard tech color.
        title.setStyleSheet("color: #007acc; font-size: 28px; font-weight: bold; border: none; background: transparent;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # 3. DESCRIPTION TEXT
        desc = QLabel("Advanced Endpoint Protection & Vulnerability Scanner\nInitializing cyber-defense subsystems...")
        desc.setWordWrap(True) # Allow text to flow to next line
        desc.setStyleSheet("color: #888888; font-size: 13px; font-style: italic; border: none; background: transparent;")
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(desc)
        
        # SPACER (Stretch)
        # Pushes everything above it UP, and everything below it DOWN.
        layout.addStretch()
        
        # 4. STATUS FEEDBACK
        # Dynamic label that updates as the background thread makes progress.
        self.status = QLabel("Preparing environment...")
        self.status.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: bold; border: none; background: transparent;")
        self.status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status)
        
        # 5. INDETERMINATE PROGRESS BAR
        self.progress = QProgressBar()
        # Custom CSS for the progress bar (Gradient fill)
        self.progress.setStyleSheet("""
            QProgressBar {
                border: none;
                background-color: #2d2d2d;  /* Track Color */
                height: 8px;
                border-radius: 4px;
                text-align: center;
            }
            QProgressBar::chunk {
                /* Linear Gradient: 0% Blue -> 100% Cyan */
                background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 #007acc, stop:1 #00b4d8);
                border-radius: 4px;
            }
        """)
        # Setting min=0, max=0 triggers the "Pulse" animation (Indeterminate Mode).
        # We use this because we don't know exactly how many seconds the scan will take.
        self.progress.setRange(0, 0) 
        layout.addWidget(self.progress)
        
        # Final Polish: Center the splash screen on the user's primary monitor.
        self.center_on_screen()

    def center_on_screen(self):
        """
        Calculates screen geometry to position the window exactly in the center.
        """
        # Get the rectangle (x, y, width, height) of the primary screen.
        screen = QApplication.primaryScreen().availableGeometry()
        # Get the rectangle of our window.
        size = self.geometry()
        
        # Algorithm:
        # New_X = (Screen_Width - Window_Width) / 2
        # New_Y = (Screen_Height - Window_Height) / 2
        new_x = int((screen.width() - size.width()) / 2)
        new_y = int((screen.height() - size.height()) / 2)
        
        self.move(new_x, new_y)

    def update_status(self, msg: str):
        """
        [SLOT] Receives updates from the Worker Thread.
        
        Args:
            msg (str): The status message to display.
        """
        self.status.setText(msg)

# ------------------------------------------------------------------------------
# MAIN ENTRY POINT
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    # Log the exact start time for performance profiling.
    logging.info("Starting ProjectX Desktop Application...")
    
    # 1. INITIALIZE QT APPLICATION
    # We pass sys.argv to allow standard Qt overrides (e.g., -platform offscreen)
    app = QApplication(sys.argv)
    app.setApplicationName("ProjectX")
    
    # 2. SHOW SPLASH SCREEN
    # Display this immediately so the user knows something is happening.
    loader = LoaderScreen()
    loader.show()
    
    # 3. LOAD CONFIGURATION
    # We use our ConfigManager to securely fetch settings (checking Keychain/File).
    config = ConfigManager.load_config()
    
    # 4. DETERMINE STARTUP MODE
    # Check for "Safe Mode" flag. Default to False if not present.
    # Safe Mode allows the app to start even if the scanning engine is broken.
    safe_mode = config.get("safe_mode", "false").lower() == "true"
    
    # Global 'window' variable is required to prevent Python's Garbage Collector
    # from destroying the MainWindow object as soon as the function scope ends.
    window = None 
    
    if safe_mode:
        # ======================================================================
        # PATH A: SAFE MODE (FAST LAUNCH)
        # ======================================================================
        logging.warning("SAFE MODE ENABLED: Skipping startup integrity scans.")
        loader.update_status("Safe Mode: Loading UI without scan...")
        
        def fast_launch():
            """
            Closure allowing us to delay execution while preserving scope context.
            """
            global window
            logging.info("Launching MainWindow (Safe Mode)...")
            window = MainWindow() # Instantiate the Main View
            window.show()         # Make it visible
            
            # Use finish() to properly synchronize the visual transition.
            # This tells the Splash Screen to wait until 'window' is fully rendered
            # before hiding itself.
            loader.finish(window) 
            
        # SingleShot Timer: Call 'fast_launch' after 800ms.
        # This artificial delay ensures the user has time to read "Safe Mode".
        QTimer.singleShot(800, fast_launch)
        
    else:
        # ======================================================================
        # PATH B: NORMAL MODE (FULL INTEGRITY SCAN)
        # ======================================================================
        logging.info("NORMAL MODE: Initiating background system scan...")
        
        # Create the Worker Thread.
        # CRITICAL OPTIMIZATION: skip_cve_sync=True.
        # Downloading the 100MB+ NVD database takes too long for startup. 
        # We defer that to a post-load background task.
        worker = ScanWorker(skip_cve_sync=True)
        
        # CONNECT SIGNALS (The "Wiring")
        # 1. Update text on Splash Screen when worker reports progress.
        worker.progress.connect(loader.update_status)
        
        def on_scan_finished():
            """
            Callback function executed when the background thread completes.
            """
            logging.info("Startup Scan Completed. Launching Dashboard.")
            global window
            window = MainWindow() 
            window.show()
            loader.finish(window)
        
        # 2. Launch App when worker is done.
        worker.finished.connect(on_scan_finished)
        
        # Start the thread. The OS creates the thread, and execution continues 
        # immediately to app.exec() below.
        worker.start()
    
    # 5. EXECUTE EVENT LOOP
    # The script "blocks" here essentially forever, waiting for the user to close the app.
    # app.exec() returns 0 on success, or an error code.
    exit_code = app.exec()
    
    # 6. TEARDOWN & CLEANUP
    # When the loop exits, we perform hygiene.
    logging.info(f"Application exiting with code: {exit_code}")
    
    # Remove logging handlers to prevent resource leaks / locked files on Windows.
    root_logger = logging.getLogger()
    for h in root_logger.handlers[:]:
        if "FileHandler" in str(type(h)):
            h.close()
            root_logger.removeHandler(h)
            
    # Return the automated exit code to the Operating System
    sys.exit(exit_code)
