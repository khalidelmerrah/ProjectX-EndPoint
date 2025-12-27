"""
MODULE: app.py
ProjectX Endpoint Protection - Application Entry Point & Orchestrator

PURPOSE:
This file serves as the "Main Function" for the ProjectX desktop application.
It is responsible for:
1.  Initializing the Qt Application Framework (QApplication).
2.  Configuring the global logging system to capture runtime events.
3.  Displaying a "LoaderScreen" (Splash Screen) to give immediate visual feedback.
4.  Determining the startup mode ("Safe Mode" vs. "Full Scan Mode").
5.  Launching the MainWindow (the primary UI) once initialization is complete.
6.  Handling the top-level Event Loop execution and clean exit.

ARCHITECTURAL ROLE:
-------------------
[Orchestrator] -> [Loader UI] -> [Worker Threads] -> [Main Window]

This module acts as the conductor. It does not contain business logic (like finding vulnerabilities) 
or deep data persistence code. Instead, it coordinates the startup sequence ensuring that
heavy operations (like the initial system scan) happen in background threads (Workers)
so the UI does not freeze (an "Application Not Responding" state).

SECURITY THEORY:
----------------
1.  **Fail-Safe Defaults**: The application includes a "Safe Mode" that creates a fallback path
    allows the app to run even if the scanning engine fails or crashes on startup.
2.  **Least Privilege (Logging)**: We log to a local file but sanitize (in principle) sensitive data
    before writing, preventing PII leakage in debug logs.

DEPENDENCIES:
-------------
- sys: Used for accessing command-line arguments and exit codes.
- logging: The standard Python logging facility for tracking events.
- os: File system path operations.
- PyQt6 (QtWidgets, QtCore, QtGui): The GUI framework used to render windows.
- main_window: Our custom MainWindow class (The Dashboard).
- managers: Specifically ConfigManager for reading startup preferences.
- workers: Specifically ScanWorker for performing the threaded startup scan.

AUTHOR: ProjectX Team
DATE: 2025-12-27
"""

import sys          # Standard library for interacting with the Python interpreter
import logging      # Standard library for logging events (Info, Debug, Error)
import os           # Standard library for Operating System interface

# ---------------------------------------------------------
# LOGGING CONFIGURATION
# ---------------------------------------------------------
# We configure logging *immediately* upon script start.
# This ensures that even import errors or early crashes are captured in 'projectx.log'.
logging.basicConfig(
    level=logging.INFO, # Capture everything from INFO level and up (INFO, WARNING, ERROR, CRITICAL)
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', # ISO-like time format
    handlers=[
        logging.FileHandler("projectx.log", mode='w'), # Write to file (overwrite mode 'w' for fresh log per run)
        logging.StreamHandler(sys.stdout)              # Also print to the console (stdout) for development
    ]
)

# ---------------------------------------------------------
# IMPORTS
# ---------------------------------------------------------
# We import PyQt6 components *after* standard libs. 
# PyQt is a wrapper around the C++ Qt framework, providing native-looking UIs.
from PyQt6.QtWidgets import QApplication, QSplashScreen, QProgressBar, QLabel, QVBoxLayout, QWidget
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPixmap, QColor, QFont

# Import our custom modules
from main_window import MainWindow
from workers import ScanWorker

# ---------------------------------------------------------
# CLASS: LoaderScreen
# ---------------------------------------------------------
class LoaderScreen(QSplashScreen):
    """
    A custom splash screen that appears during application startup.

    Inheritance:
        QSplashScreen (PyQt6.QtWidgets): A specialized widget for startup images.
        
    Purpose:
        To provide immediate visual feedback to the user that the application is launching,
        masking the latency of setting up databases and scanning the system.
    """
    
    def __init__(self):
        """
        Initializes the splash screen UI.
        
        This constructor builds the visual layout programmatically (using code)
        rather than loading a .ui file, giving us runtime control over styles.
        """
        super().__init__() # Initialize the parent QSplashScreen class
        
        # Set a fixed size for the splash window (Width, Height)
        self.setFixedSize(500, 350)
        
        # Window Flags configure how the window system treats this widget.
        # WindowStaysOnTopHint: Keeps it above other windows so the user sees it.
        # FramelessWindowHint: Removes the title bar and X button for a clean "App-like" look.
        self.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.FramelessWindowHint)
        
        # Enable transparency support (required for rounded corners to look right)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        
        # ---------------------------------------------------------
        # UI LAYOUT CONSTRUCTION
        # ---------------------------------------------------------
        # We need a container widget to hold our layout because QSplashScreen 
        # is normally just an image. We treat it like a normal Window here.
        self.layout_container = QWidget(self)
        self.layout_container.setGeometry(0, 0, 500, 350) # Match parent size
        
        # STYLESHEET (CSS-like)
        # We use QSS (Qt Style Sheets) to style the widget.
        # This is very similar to web CSS.
        self.layout_container.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;   /* Dark Grey Background */
                border: 2px solid #333;      /* Subtle border */
                border-radius: 15px;         /* Rounded Corners */
            }
        """)
        
        # Vertical Box Layout (QVBoxLayout)
        # Stacks widgets vertically: [Icon] -> [Title] -> [Description] -> [Status] -> [Progress]
        layout = QVBoxLayout(self.layout_container)
        layout.setContentsMargins(30, 40, 30, 40) # Padding: Left, Top, Right, Bottom
        layout.setSpacing(15)                     # Space between elements
        
        # 1. Icon Widget
        # Using an emoji as a lightweight text-based icon. 
        # In a production app, QPixmap("logo.png") would be used.
        lbl_icon = QLabel("🛡️")
        # Direct styling on the widget overrides the parent stylesheet
        lbl_icon.setStyleSheet("font-size: 64px; border: none; background: transparent;")
        lbl_icon.setAlignment(Qt.AlignmentFlag.AlignCenter) # Center horizontally
        layout.addWidget(lbl_icon)
        
        # 2. Title Widget
        title = QLabel("ProjectX Security")
        title.setStyleSheet("color: #007acc; font-size: 28px; font-weight: bold; border: none; background: transparent;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # 3. Description Widget
        desc = QLabel("Advanced Endpoint Protection & Vulnerability Scanner\nInitializing system inventory, network interception, and threat feeds...")
        desc.setWordWrap(True) # Wraps text to next line if it's too long
        desc.setStyleSheet("color: #888888; font-size: 13px; font-style: italic; border: none; background: transparent;")
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(desc)
        
        # Spacer
        # Adds "spring-like" flexible space to push bottom elements down
        layout.addStretch()
        
        # 4. Process Status Label
        # This label will be updated dynamically via signals (e.g. "Scanning C: drive...")
        self.status = QLabel("Preparing enviroment...")
        self.status.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: bold; border: none; background: transparent;")
        self.status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status)
        
        # 5. Progress Bar
        self.progress = QProgressBar()
        self.progress.setStyleSheet("""
            QProgressBar {
                border: none;
                background-color: #2d2d2d;  /* Track Color */
                height: 8px;
                border-radius: 4px;
                text-align: center;
            }
            QProgressBar::chunk {
                /* Gradient Fill for a premium look */
                background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 #007acc, stop:1 #00b4d8);
                border-radius: 4px;
            }
        """)
        # Setting Range(0,0) creates an "Indeterminate" state (Infinite Pulse)
        # This is used when we don't know exactly how long a task will take.
        self.progress.setRange(0, 0) 
        layout.addWidget(self.progress)

        # Center this window on the user's screen
        self.center_on_screen()

    def center_on_screen(self):
        """
        Helper method to center the window logic.
        
        Logic:
        1. Get the geometry (Resolution) of the primary monitor.
        2. Calculate the center x/y coordinates.
        3. Move the window to those coordinates.
        """
        screen = QApplication.primaryScreen().availableGeometry()
        size = self.geometry()
        # Integer division (//) could also be used here
        self.move(int((screen.width() - size.width()) / 2), 
                  int((screen.height() - size.height()) / 2))

    def update_status(self, msg):
        """
        Slot to receive status updates.
        
        Args:
            msg (str): The text message to display (e.g., "Scan Complete").
            
        This method is typically connected to a Worker Thread's signal.
        """
        self.status.setText(msg)

# ---------------------------------------------------------
# MAIN EXECUTION BLOCK
# ---------------------------------------------------------
# This block runs only if this file is executed directly (python app.py)
# It is the standard entry point pattern in Python.
if __name__ == "__main__":
    logging.info("Starting ProjectX Desktop...")
    
    # 1. Initialize the Qt Application (The Event Loop Manager)
    # sys.argv is passed so Qt can handle standard command-line flags (like -platform offscreen)
    app = QApplication(sys.argv)
    app.setApplicationName("ProjectX")
    
    # 2. Show the Splash Screen immediately
    # We do this before creating the heavy MainWindow to give instant feedback.
    loader = LoaderScreen()
    loader.show()
    
    # 3. Load Configuration
    # We defer this import to avoid circular dependencies and only load when needed.
    from managers import ConfigManager
    config = ConfigManager.load_config()
    
    # Determine Startup Mode
    # 'Safe Mode' is a common pattern in security tools to allow troubleshooting
    # if the main engine is crashing the system.
    safe_mode = config.get("safe_mode", "false").lower() == "true"
    
    if safe_mode:
        # -----------------------------------------------------
        # PATH A: FAST START (Safe Mode)
        # -----------------------------------------------------
        logging.info("Safe Mode (Fast Load) Enabled. Skipping initial scan.")
        loader.update_status("Fast Load: Retrieving cached data...")
        
        def fast_launch():
            """
            Closure to launch the main window after a short delay.
            We use a closure so it can capture 'loader' and 'window' variables.
            """
            logging.info("Fast Launching Dashboard.")
            global window # Global reference keeps the window object alive
            window = MainWindow()
            window.show()
            loader.close() # Hide/Destroy the splash screen
            
        # QTimer.singleShot executes the function after N milliseconds (800ms)
        # This non-blocking delay gives the user time to read the status text.
        QTimer.singleShot(800, fast_launch)
        
    else:
        # -----------------------------------------------------
        # PATH B: FULL START (Normal Mode)
        # -----------------------------------------------------
        logging.info("Full Mode. Starting initial scan...")
        
        # We start the ScanWorker.
        # CRITICAL: We pass skip_cve_sync=True to avoid a very long network call 
        # on startup, making the app feel faster. CVE sync can happen later.
        worker = ScanWorker(skip_cve_sync=True)
        
        # Connect the worker's 'progress' signal (emitting strings)
        # to the loader's 'update_status' method (accepting strings).
        # This implements the Signal-Slot pattern (Observer Pattern).
        worker.progress.connect(loader.update_status)
        
        def on_scan_finished():
            """Called automatically when thread finishes."""
            logging.info("Initial Scan Complete. Launching Dashboard.")
            global window
            window = MainWindow() # DB connection happens inside here
            window.show()
            loader.close()
            
        # Connect the finished signal to our launch function
        worker.finished.connect(on_scan_finished)
        
        # Start the background thread. code execution continues immediately below,
        # but the worker runs in parallel.
        worker.start()
    
    # 4. ENTER THE EVENT LOOP
    # app.exec() blocks here and waits for user interaction (clicks, keys).
    # It returns an exit code (0 for success, other for error) when the app closes.
    exit_code = app.exec()
    
    # 5. CLEANUP
    # When the event loop ends (app closed), we perform manual cleanup if needed.
    
    # Detach custom Qt log handlers to prevent memory leaks or crashes on shutdown
    root_logger = logging.getLogger()
    for h in root_logger.handlers[:]:
        if "QtLogHandler" in str(type(h)):
            root_logger.removeHandler(h)
    
    # Return the exit code to the OS
    sys.exit(exit_code)
