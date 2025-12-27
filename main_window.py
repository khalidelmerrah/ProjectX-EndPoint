"""
MODULE: main_window.py
================================================================================
PROJECT:        ProjectX Endpoint Protection Platform (Academic Reference)
AUTHOR:         ProjectX Development Team
INSTITUTION:    University of Cybersecurity & Software Engineering
DATE:           2025-12-27
LICENSE:        MIT License (Educational)
PYTHON VER:     3.11+
================================================================================

MODULE OVERVIEW:
----------------
This module implements the **Graphical User Interface (GUI)** using PyQt6.
It serves as the "Presentation Layer" in our architectural stack.
In a secure application, the UI must be decoupled from the core logic to 
prevet "UI Freeze" attacks (DoS) and ensure responsiveness.

ARCHITECTURAL PATTERNS:
-----------------------
1.  **Model-View-Controller (MVC)** (Loosely adapted for Qt):
    -   **Model**: `GenericTableModel` wraps our raw data (lists of dicts) for the UI.
    -   **View**: `QTableView`, `QLabel` display the data.
    -   **Controller**: `MainWindow` handles user input and business logic coordination.

2.  **Observer Pattern (Signals & Slots)**:
    Qt's core communication mechanism. Instead of polling for changes, objects 
    *emit* signals (events) which other objects *connect* to (callbacks).
    Example: `worker.finished.connect(self.update_ui)`

3.  **Asynchronous UI Updates**:
    The UI creates background threads (`workers.py`) for heavy tasks and 
    updates widgets only when the thread emits data back to the main loop.

4.  **Composite Pattern**:
    The UI is built as a tree of Widgets (Tabs -> Tables -> Headers).

DEFENSE-IN-DEPTH (UI LAYER):
----------------------------
-   **Input Validation**: All file dialogs and text inputs are sanitized.
-   **Least Privilege**: The UI runs with the same permissions as the user, 
    but triggers elevated backend tasks only when necessary.
-   **Feedback Loops**: Visual indicators (Progress Bars, Status) prevent 
    user frustration and re-clicking which can cause Race Conditions.

"""

import sys                     # System-specific parameters and functions
import logging                 # Standard logging facility
import json                    # JSON encoder and decoder
import datetime                # Basic date and time types
import os                      # Operating system interfaces
from typing import List, Dict, Any, Optional # Type hinting for academic rigor

# PyQt6 Imports - The UI Framework
# We import specific widgets to keep the namespace clean and optimized.
# QMainWindow: The main application window type.
# QWidget: The base class of all user interface objects.
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QTabWidget, QTableView, 
    QLabel, QPushButton, QHBoxLayout, QSplitter, QTreeWidget, QTreeWidgetItem,
    QFormLayout, QLineEdit, QCheckBox, QSlider, QProgressBar, QFrame, 
    QHeaderView, QTextEdit, QAbstractItemView, QMenu, QMessageBox, QDialog, 
    QSizePolicy, QGroupBox, QScrollArea, QFileDialog, QGridLayout, QStyle, 
    QStyleOptionButton, QApplication
)

# Core Qt modules for non-GUI logic (timers, signals, models)
from PyQt6.QtCore import Qt, QAbstractTableModel, QTimer, pyqtSignal, QObject, QRect, QUrl
# Qt GUI modules for painting, colors, and fonts
from PyQt6.QtGui import QStandardItemModel, QStandardItem, QColor, QBrush, QAction, QFont, QDesktopServices

# Internal Project Modules
# We import the "Worker" threads which handle the heavy lifting.
from workers import (
    ScanWorker, ProcessWorker, AIWorker, AdvisoryWorker, 
    FIMWorker, YaraScanWorker
)
# Database Manager for persisting state
from db_manager import DatabaseManager
# Business Logic Managers
from managers import ConfigManager, ResponseManager, SoftwareManager, ThreatIntelManager

# ------------------------------------------------------------------------------
# STYLESHEET (The "CSS" of Desktop Apps)
# ------------------------------------------------------------------------------
# We define the visual theme here using Qt Style Sheets (QSS).
# This provides a consistent "Dark Mode" aesthetic similar to modern IDEs.
DARK_STYLESHEET = """
QMainWindow { background-color: #1e1e1e; color: #ffffff; }

/* Tabs Configuration */
QTabWidget::pane { border: 1px solid #333333; background: #2d2d2d; }
QTabBar::tab { 
    background: #333333; color: #aaaaaa; padding: 10px 20px; 
    border-top-left-radius: 4px; border-top-right-radius: 4px; 
}
/* Highlight selected tab */
QTabBar::tab:selected { background: #007acc; color: white; border-bottom: 2px solid white; }
QTabBar::tab:hover { background: #444444; }

/* Table View Configuration */
QTableView { 
    background-color: #252526; color: #d4d4d4; 
    gridline-color: #333333; border: none; 
    selection-background-color: #37373d;
}
QHeaderView::section { 
    background-color: #333333; color: #ffffff; 
    padding: 4px; border: 1px solid #444444; font-weight: bold;
}

/* Common Widget Styling */
QLabel { color: #d4d4d4; font-size: 14px; }
QLabel#Header { font-size: 16px; font-weight: bold; margin-bottom: 5px; color: #ffffff; }
QPushButton { 
    background-color: #0e639c; color: white; border: none; 
    padding: 8px 16px; border-radius: 4px; 
}
/* Button Interaction States */
QPushButton:hover { background-color: #1177bb; }
QPushButton:disabled { background-color: #3a3d41; color: #888888; }
QLineEdit, QTextEdit { 
    background-color: #3c3c3c; color: white; 
    border: 1px solid #555555; padding: 4px; 
}
"""

# ------------------------------------------------------------------------------
# HELPER CLASSES
# ------------------------------------------------------------------------------

class GenericTableModel(QStandardItemModel):
    """
    A reusable wrapper for QStandardItemModel.
    Simplifies creating a table with fixed headers.
    
    Inheritance:
        QStandardItemModel: A model that stores data as a grid of items.
    """
    def __init__(self, headers: List[str]):
        """
        initializes the model with specific column headers.
        
        Args:
            headers (List[str]): Strings to display at the top of the columns.
        """
        # Call the parent constructor to initialize the QStandardItemModel
        super().__init__()
        # Set the horizontal header labels to our custom list
        self.setHorizontalHeaderLabels(headers)

class CheckableHeaderView(QHeaderView):
    """
    Custom Header that paints a checkbox in the first column.
    Used for "Select All" functionality in tables.
    """
    # Signal emitted when the checkbox toggle state changes
    toggled = pyqtSignal(bool) 

    def __init__(self, orientation, parent=None):
        super().__init__(orientation, parent)
        self.isOn = False

    def paintSection(self, painter, rect, logicalIndex):
        """
        Custom painting logic for the header section.
        We override this to draw a checkbox manually if index == 0.
        """
        painter.save() # Type: State Isolation
        super().paintSection(painter, rect, logicalIndex)
        painter.restore()

        # If this is the first column (Logical Index 0)
        if logicalIndex == 0:
            option = QStyleOptionButton()
            # Calculate position: 5px padding from top/left
            option.rect = QRect(rect.x() + 5, rect.y() + 5, 20, 20)
            option.state = QStyle.StateFlag.State_Enabled | QStyle.StateFlag.State_Active
            # Set Checkbox State based on internal boolean
            if self.isOn: option.state |= QStyle.StateFlag.State_On
            else: option.state |= QStyle.StateFlag.State_Off
            # Draw the control using the application's style
            self.style().drawControl(QStyle.ControlElement.CE_CheckBox, option, painter)

    def mousePressEvent(self, event):
        """Handle clicks on the header."""
        if self.logicalIndexAt(event.pos()) == 0:
            self.isOn = not self.isOn
            self.toggled.emit(self.isOn)
            self.viewport().update() # Force repaint
        super().mousePressEvent(event)

class LogSignal(QObject):
    """
    Helper object to hold a PyQt signal.
    Needed because logging.Handler is NOT a QObject and cannot emit signals directly.
    """
    log_signal = pyqtSignal(str)

class QtLogHandler(logging.Handler):
    """
    Custom Logging Handler that bridges Python's logging facility with Qt Signals.
    This allows us to display log messages (INFO, WARNING, ERROR) inside the GUI text box.
    """
    def __init__(self):
        super().__init__()
        # Create the bridging QObject
        self.signal_wrapper = LogSignal()
        self.log_signal = self.signal_wrapper.log_signal

    def emit(self, record):
        """
        Called by the logging system when a new log record is created.
        """
        try:
            msg = self.format(record)
            # Emit the formatted message to the UI
            self.log_signal.emit(msg)
        except: pass

# ------------------------------------------------------------------------------
# MAIN WINDOW CONTROLLER
# ------------------------------------------------------------------------------

class MainWindow(QMainWindow):
    """
    The Main Application Window.
    Coordinates all sub-widgets and logic flow.
    Acts as the 'Controller' in the MVC architecture.
    """
    def __init__(self):
        """
        Constructor: Initializes the UI and backend systems.
        """
        # Initialize the QMainWindow base class
        super().__init__()
        
        # 1. Base Configuration
        self.setWindowTitle("ProjectX Endpoint Protection Platform")
        # Set default size (1400x950) for modern high-res displays
        self.resize(1400, 950)
        # Apply the dark theme
        self.setStyleSheet(DARK_STYLESHEET)
        
        # 2. Logging Setup
        # Create and attach our custom handlers
        self.log_handler = QtLogHandler()
        self.log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(self.log_handler)
        # Ensure we capture INFO level events
        logging.getLogger().setLevel(logging.INFO)
        
        # 3. Manager Initialization (The Brains)
        # These objects encapsulate the Business Logic of the application
        self.db = DatabaseManager()       # Persistence
        self.inv_mgr = SoftwareManager()  # Software Inventory
        self.soft_mgr = SoftwareManager() # (Redundant alias for clarity)
        self.response_mgr = ResponseManager() # Incident Response
        self.ti_mgr = ThreatIntelManager()    # Threat Intelligence
        
        # 4. UI Construction
        # Delegate complex layout building to a separate method
        self.setup_ui()
        
        # 5. Background Services
        # Start the Daemon threads that monitor the system
        self.start_background_workers()
        
        # 6. Initial State
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("System Initialized. Engine Ready.")
        
        # Load Data
        # Connect the log handler signal to the text area
        self.log_handler.log_signal.connect(self.append_log)
        # Populate the dashboard tables
        # Populate the dashboard tables
        self.refresh_dashboard_data()
        
        # [OFFLINE-FIRST] Apply UI constraints based on available keys
        self.validate_feature_state()

    def setup_ui(self):
        """Constructs the high-level layout."""
        # Create the central container widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        # Use Vertical Layout for the main structure (Top to Bottom)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        # The Tab Widget is the primary navigation container
        self.main_tabs = QTabWidget()
        main_layout.addWidget(self.main_tabs)
        
        # Build individual Tabs using modular methods
        self.init_overview_tab()   # Dashboard
        self.init_monitor_tab()    # Live Telemetry
        self.init_assets_tab()     # Inventory
        self.init_system_tab()     # Scans
        self.init_logs_tab()       # Console Output

    def start_background_workers(self):
        """Starts persistent daemon threads."""
        # Process Monitor: Watches running executables
        self.proc_worker = ProcessWorker()
        # Connect 'updated' signal to our 'update_process_view' slot
        self.proc_worker.updated.connect(self.update_process_view)
        # Start execution
        self.proc_worker.start()
        
        # FIM (File Integrity Monitor): Watches sensitive files
        self.fim_worker = FIMWorker()
        self.fim_worker.alert.connect(self.handle_fim_alert)
        self.fim_worker.start()

    def closeEvent(self, event):
        """
        Cleanup on Exit.
        Called automatically when the user clicks 'X'.
        """
        # Detach log handler to prevent memory leaks
        logging.getLogger().removeHandler(self.log_handler)
        # Stop threads if they are running
        if hasattr(self, 'proc_worker'): self.proc_worker.stop()
        if hasattr(self, 'fim_worker'): self.fim_worker.stop()
        # Accept the close event
        super().closeEvent(event)

    # ---------------------------------------------------------
    # TAB CONSTRUCTION
    # ---------------------------------------------------------

    def init_overview_tab(self):
        """Creates the Dashboard View."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Header Area: KPI Cards
        # Custom factory method to create consistent headers
        layout.addWidget(self.create_header("Security Posture", "Real-time overview of system risks."))
        
        # Horizontal Layout for Key Performance Indicators (KPIs)
        kpi_layout = QHBoxLayout()
        # Create 4 Cards for major functionality areas
        self.kpi_assets = self.create_kpi_card("Assets", "📦", self.scan_software)
        self.kpi_network = self.create_kpi_card("Network", "🌐", self.scan_network)
        self.kpi_identity = self.create_kpi_card("Identity", "👤", self.scan_identity)
        self.kpi_vulns = self.create_kpi_card("Threats", "🛡️", self.scan_full)
        
        # Add cards to the horizontal layout
        kpi_layout.addWidget(self.kpi_assets)
        kpi_layout.addWidget(self.kpi_network)
        kpi_layout.addWidget(self.kpi_identity)
        kpi_layout.addWidget(self.kpi_vulns)
        layout.addLayout(kpi_layout)
        
        # Helper: Horizontal Divider Line for visual separation
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("color: #444;")
        layout.addWidget(line)
        
        # Security Feed (Bottom Half)
        layout.addWidget(self.create_header("Threat Intelligence Feed", "Live advisories from vendor sources."))
        
        # Table to display vulnerability data
        self.intel_table = QTableView()
        self.configure_table(self.intel_table)
        # Setup Model with 4 columns
        self.intel_model = GenericTableModel(["Severity", "Components", "Title", "Date"])
        self.intel_table.setModel(self.intel_model)
        
        # Header Scaling Policies
        self.intel_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        # Resize 'Severity' column to fit content (it's short)
        self.intel_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.intel_table)
        
        # Controls
        self.btn_refresh = QPushButton("Refresh Feed")
        self.btn_refresh.clicked.connect(self.refresh_threat_feed)
        layout.addWidget(self.btn_refresh)
        
        # Add the constructed tab to the main widget
        self.main_tabs.addTab(tab, "Dashboard")

    def init_monitor_tab(self):
        """Live Monitoring of System Activity."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Nested Tabs for Organization (Separating Process from Network)
        sub_tabs = QTabWidget()
        layout.addWidget(sub_tabs)
        
        # -- Processes Sub-Tab --
        p_tab = QWidget()
        p_layout = QVBoxLayout(p_tab)
        
        # Toolbar for Process Actions
        toolbar = QHBoxLayout()
        self.btn_kill = QPushButton("❌ Terminate")
        # Connect generic 'Terminate' action
        self.btn_kill.clicked.connect(self.kill_selected_process)
        
        self.btn_ai_analyze = QPushButton("🧠 AI Analyze")
        # Connect AI analysis action
        self.btn_ai_analyze.clicked.connect(self.ai_analyze_process)
        
        toolbar.addWidget(self.btn_kill)
        toolbar.addWidget(self.btn_ai_analyze)
        toolbar.addStretch() # Push buttons to the left
        p_layout.addLayout(toolbar)
        
        # Process Table
        self.proc_table = QTableView()
        self.configure_table(self.proc_table)
        self.proc_model = GenericTableModel(["PID", "Name", "Path", "Memory", "User"])
        self.proc_table.setModel(self.proc_model)
        self.proc_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        p_layout.addWidget(self.proc_table)
        sub_tabs.addTab(p_tab, "Processes")
        
        # -- Network Sub-Tab --
        n_tab = QWidget()
        n_layout = QVBoxLayout(n_tab)
        
        btn_scan_net = QPushButton("Run Network Scan")
        btn_scan_net.clicked.connect(self.scan_network)
        n_layout.addWidget(btn_scan_net)
        
        self.net_table = QTableView()
        self.configure_table(self.net_table)
        self.net_model = GenericTableModel(["PID", "Local Addr", "Remote Addr", "State", "Proto"])
        self.net_table.setModel(self.net_model)
        self.net_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        n_layout.addWidget(self.net_table)
        sub_tabs.addTab(n_tab, "Network")
        
        self.main_tabs.addTab(tab, "Live Monitor")

    def init_assets_tab(self):
        """Inventory Management."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        btn_scan = QPushButton("Refresh Inventory")
        btn_scan.clicked.connect(self.scan_software)
        layout.addWidget(btn_scan)
        
        self.inv_table = QTableView()
        self.configure_table(self.inv_table)
        # Columns mapped to installed_software table
        self.inv_model = GenericTableModel(["Name", "Version", "Publisher", "Install Date"])
        self.inv_table.setModel(self.inv_model)
        self.inv_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.inv_table)
        
        self.main_tabs.addTab(tab, "Assets")

    def init_system_tab(self):
        """System Health & Malware Scanning."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Scan Input Area
        # GroupBox provides a labeled container for related controls
        grp_yara = QGroupBox("Targeted Malware Scan (YARA)")
        y_layout = QHBoxLayout(grp_yara)
        
        self.txt_scan_target = QLineEdit()
        self.txt_scan_target.setPlaceholderText("Select file or folder to scan...")
        
        # Browse Button triggers FileDialog
        btn_browse = QPushButton("Browse")
        btn_browse.clicked.connect(lambda: self.txt_scan_target.setText(QFileDialog.getExistingDirectory(self, "Select Folder")))
        
        btn_start_scan = QPushButton("Start Scan")
        btn_start_scan.clicked.connect(self.start_manual_scan)
        
        y_layout.addWidget(self.txt_scan_target)
        y_layout.addWidget(btn_browse)
        y_layout.addWidget(btn_start_scan)
        layout.addWidget(grp_yara)
        
        # Results Table
        self.mal_table = QTableView()
        self.configure_table(self.mal_table)
        self.mal_model = GenericTableModel(["File", "Rule Match", "Tags", "Metadata"])
        self.mal_table.setModel(self.mal_model)
        self.mal_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.mal_table)
        
        self.main_tabs.addTab(tab, "System & Scans")

    def init_logs_tab(self):
        """Console Output View."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Simple Text Edit widget to show logs
        self.log_viewer = QTextEdit()
        self.log_viewer.setReadOnly(True) # User cannot edit logs
        layout.addWidget(self.log_viewer)
        
        self.main_tabs.addTab(tab, "Logs")

    # ---------------------------------------------------------
    # UTILITY METHODS (Helpers)
    # ---------------------------------------------------------
    
    def create_header(self, title, subtitle):
        """Factory for standardized section headers."""
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(0, 0, 0, 10)
        t = QLabel(title)
        t.setObjectName("Header") # Used by StyleSheet
        s = QLabel(subtitle)
        s.setStyleSheet("color: #888; margin-bottom: 5px;")
        l.addWidget(t)
        l.addWidget(s)
        return w

    def create_kpi_card(self, title, icon, callback):
        """Factory for Dashboard Cards."""
        card = QFrame()
        card.setStyleSheet("QFrame { background: #2d2d2d; border: 1px solid #444; border-radius: 6px; }")
        l = QVBoxLayout(card)
        
        lbl_icon = QLabel(icon)
        lbl_icon.setStyleSheet("font-size: 24px; border: none;")
        l.addWidget(lbl_icon, 0, Qt.AlignmentFlag.AlignCenter)
        
        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("font-weight: bold; border: none;")
        l.addWidget(lbl_title, 0, Qt.AlignmentFlag.AlignCenter)
        
        btn = QPushButton("Scan")
        # Connect callback function
        btn.clicked.connect(callback)
        l.addWidget(btn)
        
        return card

    def configure_table(self, table):
        """Applies standard aesthetic grouping to tables."""
        table.setAlternatingRowColors(True) # Stripes
        table.verticalHeader().setVisible(False) # Hide Row Numbers
        # Select entire rows, not single cells
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        # Disable editing
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)

    def append_log(self, msg):
        """Slot to receive log messages."""
        self.log_viewer.append(msg)

    # ---------------------------------------------------------
    # LOGIC & EVENT HANDLERS
    # ---------------------------------------------------------

    def update_process_view(self, processes: List[Dict]):
        """Slot: Called by ProcessWorker every 5s."""
        # Clear existing rows
        self.proc_model.removeRows(0, self.proc_model.rowCount())
        # Populate new data
        for p in processes:
            row = [
                QStandardItem(str(p['pid'])),
                QStandardItem(p['name']),
                QStandardItem(p.get('exe', '')),
                QStandardItem(f"{p['memory_info'].rss / 1024 / 1024:.1f} MB"),
                QStandardItem(p['username'])
            ]
            self.proc_model.appendRow(row)

    def refresh_dashboard_data(self):
        """Loads generic data from DB to UI."""
        # Intel Feed Logic
        # Execute parameterized query (safe)
        rows = self.db.execute_query("SELECT severity, products, title, pub_date FROM threat_advisories ORDER BY pub_date DESC LIMIT 50")
        
        self.intel_model.removeRows(0, self.intel_model.rowCount())
        for r in rows:
            # Color coding severity based on CVSS score
            sev_item = QStandardItem(str(r[0]))
            if r[0] >= 9.0: sev_item.setForeground(QBrush(QColor("#ff4444"))) # Critical (Red)
            elif r[0] >= 7.0: sev_item.setForeground(QBrush(QColor("#ffaa00"))) # High (Orange)
            
            # Add to model
            self.intel_model.appendRow([
                sev_item,
                QStandardItem(r[1][:50] + "..."), # Truncate products
                QStandardItem(r[2]),              # Title
                QStandardItem(str(r[3]))          # Date
            ])

    def refresh_threat_feed(self):
        """Trigger Background Worker for Threat Feed."""
        self.worker = AdvisoryWorker()
        # Connect progress to status bar
        self.worker.progress.connect(lambda s: self.status_bar.showMessage(s))
        # Chain multiple actions on finish
        self.worker.finished.connect(lambda: [self.refresh_dashboard_data(), self.status_bar.showMessage("Feed Updated.")])
        self.worker.start()

    def handle_fim_alert(self, data: Dict):
        """Slot: Real-time FIM alert."""
        msg = f"FIM ALERT: {data['file_path']} ({data['action_type']})"
        logging.warning(msg)
        # Show message for 5000ms (5 seconds)
        self.status_bar.showMessage(msg, 5000) 

    # --- Scanning Wrappers ---
    
    def run_scan(self, categories):
        """
        Generic Scan Launcher.
        Spawns a ScanWorker with specific categories.
        """
        self.scan_worker = ScanWorker(scan_categories=categories)
        self.scan_worker.progress.connect(lambda s: self.status_bar.showMessage(s))
        self.scan_worker.finished.connect(lambda: [self.refresh_dashboard_data(), self.status_bar.showMessage("Scan Complete.")])
        self.scan_worker.finished.connect(lambda: [self.refresh_dashboard_data(), self.status_bar.showMessage("Scan Complete.")])
        self.scan_worker.start()

    def validate_feature_state(self):
        """
        [OFFLINE-FIRST] Disables UI features if API keys are missing.
        Prevents user frustration by grey-ing out broken buttons.
        """
        cfg = ConfigManager.load_config()
        
        # 1. Gemini AI Analysis
        if not cfg.get("gemini_api_key"):
            self.btn_ai_analyze.setEnabled(False)
            self.btn_ai_analyze.setToolTip("Feature locked. Add Gemini API key in Settings to enable.")
        else:
            self.btn_ai_analyze.setEnabled(True)
            self.btn_ai_analyze.setToolTip("Analyze this process using Google Gemini AI.")

        # 2. NIST Vulnerability Scanning
        if not cfg.get("nist_api_key"):
            # Disable the specific KPI card button (accessing internal layout is tricky, 
            # so we might depend on the worker skipping it, or disable the main action if possible)
            # For now, we update the main Scan Full action if we had one tied to a single button, 
            # but here we'll just set a status message if they try.
            # However, we DO have self.btn_refresh for the Feed.
            self.btn_refresh.setEnabled(False)
            self.btn_refresh.setToolTip("Feature locked. Add NIST/Vendor API key to enable.")
        else:
            self.btn_refresh.setEnabled(True)
            self.btn_refresh.setToolTip("Refresh Threat Intelligence Feed.")

        # 3. VirusTotal (If we had a specific button, we'd disable it too)


    def scan_software(self): self.run_scan(['software'])
    def scan_network(self): self.run_scan(['network'])
    def scan_identity(self): self.run_scan(['identity'])
    def scan_full(self): self.run_scan(['all'])

    # --- Actions ---
    
    def kill_selected_process(self):
        """Kills the process selected in the table."""
        idx = self.proc_table.currentIndex()
        if not idx.isValid(): return
        
        # PID is in column 0
        pid_item = self.proc_model.item(idx.row(), 0)
        try:
            pid = int(pid_item.text())
            logging.info(f"Attempting to kill PID {pid}...")
            # Use psutil to terminate
            import psutil
            psutil.Process(pid).terminate()
            QMessageBox.information(self, "Success", f"Process {pid} terminated.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to kill process: {e}")

    def ai_analyze_process(self):
        """Sends process metadata to AI Worker."""
        idx = self.proc_table.currentIndex()
        if not idx.isValid(): return
        
        name = self.proc_model.item(idx.row(), 1).text()
        context = f"Analyze executeable: {name}. Is it normally safe?"
        
        self.status_bar.showMessage(f"Asking Gemini AI about {name}...")
        self.ai_worker = AIWorker(context)
        # Display result in a popup
        self.ai_worker.result.connect(lambda res: QMessageBox.information(self, "AI Analysis", res))
        self.ai_worker.start()

    def start_manual_scan(self):
        """Starts YARA scan on target path."""
        path = self.txt_scan_target.text()
        # Basic validation
        if not path or not os.path.exists(path):
            QMessageBox.warning(self, "Invalid Path", "Please select a valid file or directory.")
            return
            
        self.yara_worker = YaraScanWorker(path)
        self.yara_worker.progress.connect(lambda s: self.status_bar.showMessage(s))
        self.yara_worker.result.connect(self.display_scan_results)
        self.yara_worker.start()

    def display_scan_results(self, matches):
        """Populate Malware Table with YARA matches."""
        self.mal_model.removeRows(0, self.mal_model.rowCount())
        if not matches:
            QMessageBox.information(self, "Clean", "No malware signatures detected.")
            return
        
        for m in matches:
            self.mal_model.appendRow([
                QStandardItem(m['file']),
                QStandardItem(m['rule']),
                QStandardItem(str(m['tags'])),
                QStandardItem(str(m['meta']))
            ])
        QMessageBox.warning(self, "Threats Found", f"Detected {len(matches)} suspicious files!")

if __name__ == "__main__":
    # Entry Point: Runs if file is executed directly
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    # Execute the Event Loop
    sys.exit(app.exec())
