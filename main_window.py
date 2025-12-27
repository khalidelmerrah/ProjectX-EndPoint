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
    The UI is built as a tree of Widgets (Tabs check Table checks Header...).

"""

import sys
import logging
import json
import datetime
import os
from typing import List, Dict, Any, Optional

# PyQt6 Imports
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QTabWidget, QTableView, 
    QLabel, QPushButton, QHBoxLayout, QSplitter, QTreeWidget, QTreeWidgetItem,
    QFormLayout, QLineEdit, QCheckBox, QSlider, QProgressBar, QFrame, 
    QHeaderView, QTextEdit, QAbstractItemView, QMenu, QMessageBox, QDialog, 
    QSizePolicy, QGroupBox, QScrollArea, QFileDialog, QGridLayout, QStyle, 
    QStyleOptionButton, QApplication
)
from PyQt6.QtCore import Qt, QAbstractTableModel, QTimer, pyqtSignal, QObject, QRect, QUrl
from PyQt6.QtGui import QStandardItemModel, QStandardItem, QColor, QBrush, QAction, QFont, QDesktopServices

# Internal Project Modules
from workers import (
    ScanWorker, ProcessWorker, AIWorker, AdvisoryWorker, 
    FIMWorker, YaraScanWorker
)
from db_manager import DatabaseManager
from managers import ConfigManager, ResponseManager, SoftwareManager, ThreatIntelManager

# ------------------------------------------------------------------------------
# STYLESHEET (The "CSS" of Desktop Apps)
# ------------------------------------------------------------------------------
DARK_STYLESHEET = """
QMainWindow { background-color: #1e1e1e; color: #ffffff; }

/* Tabs */
QTabWidget::pane { border: 1px solid #333333; background: #2d2d2d; }
QTabBar::tab { 
    background: #333333; color: #aaaaaa; padding: 10px 20px; 
    border-top-left-radius: 4px; border-top-right-radius: 4px; 
}
QTabBar::tab:selected { background: #007acc; color: white; border-bottom: 2px solid white; }
QTabBar::tab:hover { background: #444444; }

/* Tables */
QTableView { 
    background-color: #252526; color: #d4d4d4; 
    gridline-color: #333333; border: none; 
    selection-background-color: #37373d;
}
QHeaderView::section { 
    background-color: #333333; color: #ffffff; 
    padding: 4px; border: 1px solid #444444; font-weight: bold;
}

/* Common Widgets */
QLabel { color: #d4d4d4; font-size: 14px; }
QLabel#Header { font-size: 16px; font-weight: bold; margin-bottom: 5px; color: #ffffff; }
QPushButton { 
    background-color: #0e639c; color: white; border: none; 
    padding: 8px 16px; border-radius: 4px; 
}
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
    """
    def __init__(self, headers: List[str]):
        super().__init__()
        self.setHorizontalHeaderLabels(headers)

class CheckableHeaderView(QHeaderView):
    """
    Custom Header that paints a checkbox in the first column.
    Used for "Select All" functionality in tables.
    """
    toggled = pyqtSignal(bool) # Output signal

    def __init__(self, orientation, parent=None):
        super().__init__(orientation, parent)
        self.isOn = False

    def paintSection(self, painter, rect, logicalIndex):
        painter.save()
        super().paintSection(painter, rect, logicalIndex)
        painter.restore()

        if logicalIndex == 0:
            option = QStyleOptionButton()
            option.rect = QRect(rect.x() + 5, rect.y() + 5, 20, 20)
            option.state = QStyle.StateFlag.State_Enabled | QStyle.StateFlag.State_Active
            if self.isOn: option.state |= QStyle.StateFlag.State_On
            else: option.state |= QStyle.StateFlag.State_Off
            self.style().drawControl(QStyle.ControlElement.CE_CheckBox, option, painter)

    def mousePressEvent(self, event):
        if self.logicalIndexAt(event.pos()) == 0:
            self.isOn = not self.isOn
            self.toggled.emit(self.isOn)
            self.viewport().update()
        super().mousePressEvent(event)

class LogSignal(QObject):
    """Redirects logging to Qt Signals."""
    log_signal = pyqtSignal(str)

class QtLogHandler(logging.Handler):
    """Integrates Python's logging module with PyQt."""
    def __init__(self):
        super().__init__()
        self.signal_wrapper = LogSignal()
        self.log_signal = self.signal_wrapper.log_signal

    def emit(self, record):
        try:
            msg = self.format(record)
            self.log_signal.emit(msg)
        except: pass

# ------------------------------------------------------------------------------
# MAIN WINDOW CONTROLLER
# ------------------------------------------------------------------------------

class MainWindow(QMainWindow):
    """
    The Main Application Window.
    Coordinates all sub-widgets and logic flow.
    """
    def __init__(self):
        super().__init__()
        
        # 1. Base Configuration
        self.setWindowTitle("ProjectX Endpoint Protection Platform")
        self.resize(1400, 950)
        self.setStyleSheet(DARK_STYLESHEET)
        
        # 2. Logging Setup
        self.log_handler = QtLogHandler()
        self.log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(self.log_handler)
        logging.getLogger().setLevel(logging.INFO)
        
        # 3. Manager Initialization (The Brains)
        self.db = DatabaseManager()
        self.inv_mgr = SoftwareManager()
        self.soft_mgr = SoftwareManager()
        self.response_mgr = ResponseManager()
        self.ti_mgr = ThreatIntelManager()
        
        # 4. UI Construction
        self.setup_ui()
        
        # 5. Background Services
        self.start_background_workers()
        
        # 6. Initial State
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("System Initialized. Engine Ready.")
        
        # Load Data
        self.log_handler.log_signal.connect(self.append_log)
        self.refresh_dashboard_data()

    def setup_ui(self):
        """Constructs the high-level layout."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        # The Tab Widget is the primary navigation container
        self.main_tabs = QTabWidget()
        main_layout.addWidget(self.main_tabs)
        
        # Build individual Tabs
        self.init_overview_tab()
        self.init_monitor_tab()
        self.init_assets_tab()
        self.init_system_tab()
        self.init_logs_tab()

    def start_background_workers(self):
        """Starts persistent daemon threads."""
        # Process Monitor
        self.proc_worker = ProcessWorker()
        self.proc_worker.updated.connect(self.update_process_view)
        self.proc_worker.start()
        
        # FIM (File Integrity Monitor)
        self.fim_worker = FIMWorker()
        self.fim_worker.alert.connect(self.handle_fim_alert)
        self.fim_worker.start()

    def closeEvent(self, event):
        """Cleanup on Exit."""
        logging.getLogger().removeHandler(self.log_handler)
        if hasattr(self, 'proc_worker'): self.proc_worker.stop()
        if hasattr(self, 'fim_worker'): self.fim_worker.stop()
        super().closeEvent(event)

    # ---------------------------------------------------------
    # TAB CONSTRUCTION
    # ---------------------------------------------------------

    def init_overview_tab(self):
        """Creates the Dashboard View."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Header Area: KPI Cards
        layout.addWidget(self.create_header("Security Posture", "Real-time overview of system risks."))
        
        kpi_layout = QHBoxLayout()
        self.kpi_assets = self.create_kpi_card("Assets", "📦", self.scan_software)
        self.kpi_network = self.create_kpi_card("Network", "🌐", self.scan_network)
        self.kpi_identity = self.create_kpi_card("Identity", "👤", self.scan_identity)
        self.kpi_vulns = self.create_kpi_card("Threats", "🛡️", self.scan_full)
        
        kpi_layout.addWidget(self.kpi_assets)
        kpi_layout.addWidget(self.kpi_network)
        kpi_layout.addWidget(self.kpi_identity)
        kpi_layout.addWidget(self.kpi_vulns)
        layout.addLayout(kpi_layout)
        
        # Helper: Horizontal Divider
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("color: #444;")
        layout.addWidget(line)
        
        # Security Feed (Bottom Half)
        layout.addWidget(self.create_header("Threat Intelligence Feed", "Live advisories from vendor sources."))
        
        self.intel_table = QTableView()
        self.configure_table(self.intel_table)
        self.intel_model = GenericTableModel(["Severity", "Components", "Title", "Date"])
        self.intel_table.setModel(self.intel_model)
        self.intel_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.intel_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents) # Severity
        layout.addWidget(self.intel_table)
        
        # Controls
        btn_refresh = QPushButton("Refresh Feed")
        btn_refresh.clicked.connect(self.refresh_threat_feed)
        layout.addWidget(btn_refresh)
        
        self.main_tabs.addTab(tab, "Dashboard")

    def init_monitor_tab(self):
        """Live Monitoring of System Activity."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Nested Tabs for Organization
        sub_tabs = QTabWidget()
        layout.addWidget(sub_tabs)
        
        # -- Processes --
        p_tab = QWidget()
        p_layout = QVBoxLayout(p_tab)
        
        # Toolbar
        toolbar = QHBoxLayout()
        self.btn_kill = QPushButton("❌ Terminate")
        self.btn_kill.clicked.connect(self.kill_selected_process)
        self.btn_ai_analyze = QPushButton("🧠 AI Analyze")
        self.btn_ai_analyze.clicked.connect(self.ai_analyze_process)
        toolbar.addWidget(self.btn_kill)
        toolbar.addWidget(self.btn_ai_analyze)
        toolbar.addStretch()
        p_layout.addLayout(toolbar)
        
        # Table
        self.proc_table = QTableView()
        self.configure_table(self.proc_table)
        self.proc_model = GenericTableModel(["PID", "Name", "Path", "Memory", "User"])
        self.proc_table.setModel(self.proc_model)
        self.proc_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        p_layout.addWidget(self.proc_table)
        sub_tabs.addTab(p_tab, "Processes")
        
        # -- Network --
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
        grp_yara = QGroupBox("Targeted Malware Scan (YARA)")
        y_layout = QHBoxLayout(grp_yara)
        
        self.txt_scan_target = QLineEdit()
        self.txt_scan_target.setPlaceholderText("Select file or folder to scan...")
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
        
        self.log_viewer = QTextEdit()
        self.log_viewer.setReadOnly(True)
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
        t.setObjectName("Header")
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
        btn.clicked.connect(callback)
        l.addWidget(btn)
        
        return card

    def configure_table(self, table):
        """Applies standard aesthetic grouping to tables."""
        table.setAlternatingRowColors(True)
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)

    def append_log(self, msg):
        self.log_viewer.append(msg)

    # ---------------------------------------------------------
    # LOGIC & EVENT HANDLERS
    # ---------------------------------------------------------

    def update_process_view(self, processes: List[Dict]):
        """Slot: Called by ProcessWorker every 5s."""
        self.proc_model.removeRows(0, self.proc_model.rowCount())
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
        rows = self.db.execute_query("SELECT severity, products, title, pub_date FROM advisories ORDER BY pub_date DESC LIMIT 50")
        self.intel_model.removeRows(0, self.intel_model.rowCount())
        for r in rows:
            # Color coding severity
            sev_item = QStandardItem(str(r[0]))
            if r[0] >= 9.0: sev_item.setForeground(QBrush(QColor("#ff4444"))) # Critical
            elif r[0] >= 7.0: sev_item.setForeground(QBrush(QColor("#ffaa00"))) # High
            
            self.intel_model.appendRow([
                sev_item,
                QStandardItem(r[1][:50] + "..."),
                QStandardItem(r[2]),
                QStandardItem(str(r[3]))
            ])

    def refresh_threat_feed(self):
        """Trigger Background Worker."""
        self.worker = AdvisoryWorker()
        self.worker.progress.connect(lambda s: self.status_bar.showMessage(s))
        self.worker.finished.connect(lambda: [self.refresh_dashboard_data(), self.status_bar.showMessage("Feed Updated.")])
        self.worker.start()

    def handle_fim_alert(self, data: Dict):
        """Slot: Real-time FIM alert."""
        msg = f"FIM ALERT: {data['file_path']} ({data['action_type']})"
        logging.warning(msg)
        self.status_bar.showMessage(msg, 5000) # Show for 5s

    # --- Scanning Wrappers ---
    
    def run_scan(self, categories):
        """Generic Scan Launcher."""
        self.scan_worker = ScanWorker(scan_categories=categories)
        self.scan_worker.progress.connect(lambda s: self.status_bar.showMessage(s))
        self.scan_worker.finished.connect(lambda: [self.refresh_dashboard_data(), self.status_bar.showMessage("Scan Complete.")])
        self.scan_worker.start()

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
        self.ai_worker.result.connect(lambda res: QMessageBox.information(self, "AI Analysis", res))
        self.ai_worker.start()

    def start_manual_scan(self):
        """Starts YARA scan on target path."""
        path = self.txt_scan_target.text()
        if not path or not os.path.exists(path):
            QMessageBox.warning(self, "Invalid Path", "Please select a valid file or directory.")
            return
            
        self.yara_worker = YaraScanWorker(path)
        self.yara_worker.progress.connect(lambda s: self.status_bar.showMessage(s))
        self.yara_worker.result.connect(self.display_scan_results)
        self.yara_worker.start()

    def display_scan_results(self, matches):
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
    # Entry Point
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
