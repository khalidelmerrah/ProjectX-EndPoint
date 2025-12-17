import sys
import logging
import json
import datetime
from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QTabWidget, QTableView, 
                             QLabel, QPushButton, QHBoxLayout, QSplitter, QTreeWidget, QTreeWidgetItem,
                             QFormLayout, QLineEdit, QCheckBox, QSlider, QProgressBar, QFrame, QHeaderView, QTextEdit,
                             QAbstractItemView, QMenu, QMessageBox, QDialog, QSizePolicy, QGroupBox, QScrollArea, QFileDialog, QGridLayout, QStyle, QStyleOptionButton)
from PyQt6.QtCore import Qt, QAbstractTableModel, QTimer, pyqtSignal, QObject, QRect
from PyQt6.QtGui import QStandardItemModel, QStandardItem, QColor, QBrush, QAction, QFont
from workers import ScanWorker, ProcessWorker, AIWorker, AdvisoryWorker, FIMWorker, YaraScanWorker, ReputationWorker
from db_manager import DatabaseManager
from managers import ConfigManager, ResponseManager, InventoryManager
import psutil

# Dark Theme Style
DARK_STYLESHEET = """
QMainWindow { background-color: #1e1e1e; color: #ffffff; }
QTabWidget::pane { border: 1px solid #333333; background: #2d2d2d; }
QTabBar::tab { 
    background: #333333; 
    color: #aaaaaa; 
    padding: 10px 20px; 
    margin-right: 5px; 
    border-top-left-radius: 4px; 
    border-top-right-radius: 4px; 
}
QTabBar::tab:selected { background: #007acc; color: white; }
QTableView { background-color: #252526; color: #d4d4d4; gridline-color: #333333; border: none; }
QHeaderView::section { background-color: #333333; color: #ffffff; padding: 4px; border: 1px solid #444444; }
QLabel { color: #d4d4d4; font-size: 14px; }
QLabel#Header { font-size: 16px; font-weight: bold; margin-bottom: 5px; color: #ffffff; }
QLabel#Desc { font-size: 12px; color: #aaaaaa; margin-bottom: 10px; }
QPushButton { background-color: #0e639c; color: white; border: none; padding: 8px 16px; border-radius: 4px; }
QPushButton:hover { background-color: #1177bb; }
QLineEdit { background-color: #3c3c3c; color: white; border: 1px solid #555555; padding: 4px; }
QTextEdit { background-color: #1e1e1e; color: #cccccc; font-family: Consolas, monospace; border: 1px solid #333333; }
QDialog { background-color: #2d2d2d; color: white; }
QGroupBox { border: 1px solid #444444; margin-top: 20px; font-weight: bold; }
QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 3px; }
"""

class GenericTableModel(QStandardItemModel):
    def __init__(self, headers):
        super().__init__()
        self.setHorizontalHeaderLabels(headers)

class CheckableHeaderView(QHeaderView):
    toggled = pyqtSignal(bool)

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
            if self.isOn:
                option.state |= QStyle.StateFlag.State_On
            else:
                option.state |= QStyle.StateFlag.State_Off
            self.style().drawControl(QStyle.ControlElement.CE_CheckBox, option, painter)

    def mousePressEvent(self, event):
        if self.logicalIndexAt(event.pos()) == 0:
            self.isOn = not self.isOn
            self.toggled.emit(self.isOn)
            self.viewport().update()
        super().mousePressEvent(event)

class LogSignal(QObject):
    log_signal = pyqtSignal(str)

class QtLogHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.signal_wrapper = LogSignal()
        self.log_signal = self.signal_wrapper.log_signal

    def emit(self, record):
        try:
            msg = self.format(record)
            self.log_signal.emit(msg)
        except RuntimeError:
            pass
        except Exception:
            pass

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ProjectX Desktop - Security Dashboard")
        self.resize(1400, 950)
        self.setStyleSheet(DARK_STYLESHEET)
        
        # Setup Logging Handler
        self.log_handler = QtLogHandler()
        self.log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(self.log_handler)
        logging.getLogger().setLevel(logging.INFO)
        
        self.db = DatabaseManager()
        self.inv_mgr = InventoryManager()
        
        # Main Layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20) 
        
        # Tabs
        self.main_tabs = QTabWidget()
        self.main_tabs.setTabPosition(QTabWidget.TabPosition.North)
        main_layout.addWidget(self.main_tabs)
        
        # Initialize Groups
        self.init_overview_tab()
        self.init_monitor_tab()
        self.init_assets_tab()
        self.init_system_tab()
        self.init_config_tab()
        
        # Status Bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")
        
        # Connect Log Signal
        self.log_handler.log_signal.connect(self.append_log)
        
        # Start Process Monitor Worker
        self.proc_worker = ProcessWorker()
        self.proc_worker.updated.connect(self.update_process_view)
        self.proc_worker.start()

        # Start FIM Worker
        self.fim_worker = FIMWorker()
        self.fim_worker.alert.connect(self.handle_fim_alert)
        self.fim_worker.start()
        
        # Initial Data Refresh & Load Config
        self.load_api_keys()
        self.refresh_dashboard_data()
        
        # Initial Feed Fetch
        self.refresh_threat_feed()
    
    def closeEvent(self, event):
        logging.getLogger().removeHandler(self.log_handler)
        if hasattr(self, 'proc_worker'):
            self.proc_worker.stop()
        if hasattr(self, 'fim_worker'):
            self.fim_worker.stop()
        super().closeEvent(event)

    def append_log(self, msg):
        self.log_viewer.append(msg)
        cursor = self.log_viewer.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.log_viewer.setTextCursor(cursor)

    def configure_table(self, table):
        """Helper to set common table constraints (Real Read-Only)"""
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setWordWrap(True)
        table.setTextElideMode(Qt.TextElideMode.ElideNone)
        table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setStretchLastSection(True)

    def format_date_str(self, date_str):
        if not date_str or len(date_str) < 8: return date_str
        try:
            raw = str(date_str).replace('-', '').strip()
            if len(raw) == 8:
                dt = datetime.datetime.strptime(raw, "%Y%m%d")
            else:
                 dt = datetime.datetime.fromisoformat(date_str)
            
            day_name = dt.strftime("%A")
            formatted_date = dt.strftime("%d-%m-%Y")
            delta = (datetime.datetime.now() - dt).days
            ago = f"({delta} days ago)" if delta >= 0 else ""
            return f"{day_name}, {formatted_date} {ago}"
        except Exception:
            return date_str

    # --- Scanning & Workers ---

    def run_partial_scan(self, categories):
        """Runs a scan for specific categories."""
        cat_str = ", ".join(categories) if categories else "All"
        logging.info(f"Starting Scan: {cat_str}")
        self.status_bar.showMessage(f"Scanning: {cat_str}...")
        
        # Disable buttons? (Optional, skipping for simplicity)
        self.scan_progress.show()
        self.scan_progress.setRange(0, 0) # Indeterminate
        
        self.scan_worker = ScanWorker(scan_categories=categories)
        self.scan_worker.progress.connect(self.update_scan_status)
        self.scan_worker.finished.connect(self.on_scan_finished)
        self.scan_worker.start()

    def update_scan_status(self, msg):
        self.status_bar.showMessage(msg)
        logging.info(f"Scan Progress: {msg}")

    def on_scan_finished(self):
        self.scan_progress.hide()
        self.status_bar.showMessage("Scan Complete")
        logging.info("Scan Finished.")
        # Reload ALL data from DB (Cheap operation) to ensure UI is up to date
        self.refresh_dashboard_data()
        
        # Re-enable main scan button if it was disabled
        if hasattr(self, 'btn_scan'): self.btn_scan.setEnabled(True)

    # --- Tab Groups ---

    def init_overview_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        sub_tabs = QTabWidget()
        layout.addWidget(sub_tabs)
        
        # Dashboard
        dash_tab = QWidget()
        d_layout = QVBoxLayout(dash_tab)
        d_layout.addWidget(self.create_header("Risk Dashboard", "High-level overview of system security posture."))
        
        top_row = QWidget()
        top_layout = QVBoxLayout(top_row)
        
        # New KPI Cards Layout
        self.kpi_grid = QGridLayout()
        top_layout.addLayout(self.kpi_grid)
        
        # 1. Assets
        self.kpi_assets = self.create_kpi_card("Assets", "📦")
        self.kpi_assets.btn_scan.clicked.connect(lambda: self.run_partial_scan(['software', 'updates']))
        self.kpi_grid.addWidget(self.kpi_assets, 0, 0)
        
        # 2. Network
        self.kpi_network = self.create_kpi_card("Network", "🌐")
        self.kpi_network.btn_scan.clicked.connect(lambda: self.run_partial_scan(['network', 'exposure', 'persistence']))
        self.kpi_grid.addWidget(self.kpi_network, 0, 1)
        
        # 3. Identity
        self.kpi_identity = self.create_kpi_card("Identity", "👤")
        self.kpi_identity.btn_scan.clicked.connect(lambda: self.run_partial_scan(['identity']))
        self.kpi_grid.addWidget(self.kpi_identity, 0, 2)
        
        # 4. Health
        self.kpi_health = self.create_kpi_card("Health", "❤️")
        self.kpi_health.btn_scan.clicked.connect(lambda: self.run_partial_scan(['health']))
        self.kpi_grid.addWidget(self.kpi_health, 1, 0)
        
        # 5. Vulnerabilities
        self.kpi_vulns = self.create_kpi_card("Vulnerabilities", "🐞", "#e51400") # Red accent
        self.kpi_vulns.btn_scan.clicked.connect(lambda: self.run_partial_scan(['software'])) # Trigger re-check
        self.kpi_grid.addWidget(self.kpi_vulns, 1, 1)
        
        # 6. Changes
        self.kpi_changes = self.create_kpi_card("Changes", "📝", "#f0a30a") # Orange accent
        self.kpi_changes.btn_scan.clicked.connect(lambda: self.run_partial_scan(['all']))
        self.kpi_grid.addWidget(self.kpi_changes, 1, 2)
        
        d_layout.addWidget(top_row)
        
        ctrl_layout = QHBoxLayout()
        self.btn_scan = QPushButton("🔄 Full System Scan")
        self.btn_scan.clicked.connect(lambda: self.run_partial_scan(['all']))
        ctrl_layout.addWidget(self.btn_scan)
        ctrl_layout.addStretch()
        d_layout.addLayout(ctrl_layout)
        
        self.scan_progress = QProgressBar()
        self.scan_progress.hide()
        d_layout.addWidget(self.scan_progress)

        d_layout.addWidget(self.create_header("Top Risks", "Services running on exposed ports with high risk."))
        self.risk_table = QTableView()
        self.configure_table(self.risk_table)
        self.risk_model = GenericTableModel(["Port", "Protocol", "Process", "Risk Score"])
        self.risk_table.setModel(self.risk_model)
        self.risk_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.risk_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.risk_table.customContextMenuRequested.connect(lambda pos: self.show_context_menu(pos, self.risk_table, "risk"))
        d_layout.addWidget(self.risk_table)
        d_layout.addWidget(self.risk_table)

        d_layout.addWidget(self.create_header("FIM Alerts", "File Integrity Monitoring events."))
        self.fim_table = QTableView()
        self.configure_table(self.fim_table)
        self.fim_model = GenericTableModel(["Time", "File", "Action", "Severity"])
        self.fim_table.setModel(self.fim_model)
        self.fim_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.fim_table.setMaximumHeight(200)
        d_layout.addWidget(self.fim_table)
        sub_tabs.addTab(dash_tab, "Dashboard")
        
        # Threat Intelligence
        intel_tab = QWidget()
        i_layout = QVBoxLayout(intel_tab)
        i_layout.addWidget(self.create_header("Threat Intelligence Feed", "Latest security advisories."))
        
        self.feed_offset = 0
        
        i_ctrl = QHBoxLayout()
        btn_refresh_intel = QPushButton("🔄 Refresh Feed (Reset)")
        btn_refresh_intel.clicked.connect(self.refresh_threat_feed)
        
        self.btn_fetch_more_intel = QPushButton("⏬ Fetch More (Older)")
        self.btn_fetch_more_intel.clicked.connect(self.fetch_more_intel)
        
        i_ctrl.addWidget(btn_refresh_intel)
        i_ctrl.addWidget(self.btn_fetch_more_intel)
        i_ctrl.addStretch()
        i_layout.addLayout(i_ctrl)
        self.intel_table = QTableView()
        self.configure_table(self.intel_table)
        self.intel_model = GenericTableModel(["Date", "Severity", "Title", "Impact", "CVEs"])
        self.intel_table.setModel(self.intel_model)
        self.intel_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.intel_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.intel_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.intel_table.customContextMenuRequested.connect(lambda pos: self.show_context_menu(pos, self.intel_table, "intel"))
        i_layout.addWidget(self.intel_table)
        sub_tabs.addTab(intel_tab, "Threat Intelligence")
        
        self.main_tabs.addTab(tab, "Overview")

    def init_monitor_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        sub_tabs = QTabWidget()
        layout.addWidget(sub_tabs)
        
        # Processes
        proc_tab = QWidget()
        p_layout = QVBoxLayout(proc_tab)
        p_layout.addWidget(self.create_header("Running Processes", "Real-time list of active processes."))
        
        # Bulk Actions Toolbar
        self.btn_proc_term, self.btn_proc_ai, self.btn_proc_vt = self.create_toolbar(p_layout)
        self.btn_proc_term.clicked.connect(lambda: self.run_bulk_action("terminate", self.proc_model, "proc"))
        self.btn_proc_vt.clicked.connect(lambda: self.run_bulk_action("vt", self.proc_model, "proc"))
        self.btn_proc_ai.clicked.connect(lambda: self.run_bulk_action("ai", self.proc_model, "proc"))

        ctrl_layout = QHBoxLayout()
        self.chk_autorefresh = QCheckBox("Auto-refresh (5s)")
        self.chk_autorefresh.stateChanged.connect(self.toggle_process_monitor)
        ctrl_layout.addWidget(self.chk_autorefresh)
        p_layout.addLayout(ctrl_layout)
        self.proc_table = QTableView()
        self.configure_table(self.proc_table)
        # Added Checkbox column at index 0
        self.proc_model = GenericTableModel(["", "PID", "Name", "Path", "Mem (MB)", "CPU %", "User"])
        self.proc_table.setModel(self.proc_model)
        
        # Checkable Header
        self.proc_header = CheckableHeaderView(Qt.Orientation.Horizontal, self.proc_table)
        self.proc_table.setHorizontalHeader(self.proc_header)
        self.proc_header.toggled.connect(self.toggle_all_processes)
        
        self.proc_model.itemChanged.connect(lambda item: self.update_toolbar_state(self.proc_model, [self.btn_proc_term, self.btn_proc_ai, self.btn_proc_vt]))
        
        self.proc_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        # Fix checkbox column width
        self.proc_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.proc_table.setColumnWidth(0, 30)
        self.proc_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.proc_table.customContextMenuRequested.connect(lambda pos: self.show_context_menu(pos, self.proc_table, "proc"))
        p_layout.addWidget(self.proc_table)
        sub_tabs.addTab(proc_tab, "Processes")
        
        # Network
        net_tab = QWidget()
        n_layout = QVBoxLayout(net_tab)
        n_layout.addWidget(self.create_header("Network Activity", "All active TCP/UDP connections."))
        
        n_ctrl = QHBoxLayout()
        btn_scan_net = QPushButton("🔄 Scan Network")
        btn_scan_net.clicked.connect(lambda: self.run_partial_scan(['network']))
        n_ctrl.addWidget(btn_scan_net)
        n_ctrl.addStretch()
        n_layout.addLayout(n_ctrl)

        self.net_table = QTableView()
        self.configure_table(self.net_table)
        self.net_model = GenericTableModel(["PID", "L. Addr", "R. Addr", "State", "Proto"])
        self.net_table.setModel(self.net_model)
        self.net_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.net_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.net_table.customContextMenuRequested.connect(lambda pos: self.show_context_menu(pos, self.net_table, "net"))
        n_layout.addWidget(self.net_table)
        
        n_layout.addWidget(self.create_header("Hosts File", "Static hostname mappings."))
        self.hosts_table = QTableView()
        self.configure_table(self.hosts_table)
        self.hosts_model = GenericTableModel(["Hostname", "IP Address"])
        self.hosts_table.setModel(self.hosts_model)
        self.hosts_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.hosts_table.setMaximumHeight(150)
        n_layout.addWidget(self.hosts_table)
        sub_tabs.addTab(net_tab, "Network")
        
        # Exposure
        exp_tab = QWidget()
        e_layout = QVBoxLayout(exp_tab)
        e_layout.addWidget(self.create_header("Exposure Monitor", "Services listening on open ports."))
        
        e_ctrl = QHBoxLayout()
        btn_scan_exp = QPushButton("🔄 Scan Services")
        btn_scan_exp.clicked.connect(lambda: self.run_partial_scan(['exposure']))
        e_ctrl.addWidget(btn_scan_exp)
        e_ctrl.addStretch()
        e_layout.addLayout(e_ctrl)

        self.exposure_table = QTableView()
        self.configure_table(self.exposure_table)
        self.exposure_model = GenericTableModel(["Port", "Protocol", "Process", "User", "Path"])
        self.exposure_table.setModel(self.exposure_model)
        self.exposure_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        e_layout.addWidget(self.exposure_table)
        sub_tabs.addTab(exp_tab, "Exposure")

        self.main_tabs.addTab(tab, "Live Monitor")

    def init_assets_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        sub_tabs = QTabWidget()
        layout.addWidget(sub_tabs)
        
        # Software
        soft_tab = QWidget()
        s_layout = QVBoxLayout(soft_tab)
        s_layout.addWidget(self.create_header("Installed Software", "List of detected applications."))
        
        s_ctrl = QHBoxLayout()
        btn_scan_soft = QPushButton("🔄 Scan Software")
        btn_scan_soft.clicked.connect(lambda: self.run_partial_scan(['software'])) 
        s_ctrl.addWidget(btn_scan_soft)
        s_ctrl.addStretch()
        s_layout.addLayout(s_ctrl)

        self.inv_table = QTableView()
        self.configure_table(self.inv_table)
        self.inv_model = GenericTableModel(["Name", "Version", "Vendor", "Install Date", "Latest Version", "Update Available"])
        self.inv_table.setModel(self.inv_model)
        s_layout.addWidget(self.inv_table)
        sub_tabs.addTab(soft_tab, "Software")
        
        # Drivers
        drv_tab = QWidget()
        drv_layout = QVBoxLayout(drv_tab)
        drv_layout.addWidget(self.create_header("System Drivers", "Installed Kernel Drivers."))
        
        dr_ctrl = QHBoxLayout()
        btn_scan_drv = QPushButton("🔄 Scan Drivers")
        btn_scan_drv.clicked.connect(lambda: self.run_partial_scan(['drivers']))
        dr_ctrl.addWidget(btn_scan_drv)
        dr_ctrl.addStretch()
        drv_layout.addLayout(dr_ctrl)

        self.drv_table = QTableView()
        self.configure_table(self.drv_table)
        self.drv_model = GenericTableModel(["Name", "Description", "Provider", "Status", "Signed"])
        self.drv_table.setModel(self.drv_model)
        drv_layout.addWidget(self.drv_table)
        sub_tabs.addTab(drv_tab, "Drivers")

        # Extensions
        ext_tab = QWidget()
        ext_layout = QVBoxLayout(ext_tab)
        ext_layout.addWidget(self.create_header("Browser Extensions", "Installed Chrome/Firefox Extensions."))
        
        ex_ctrl = QHBoxLayout()
        btn_scan_ext = QPushButton("🔄 Scan Extensions")
        btn_scan_ext.clicked.connect(lambda: self.run_partial_scan(['extensions']))
        ex_ctrl.addWidget(btn_scan_ext)
        ex_ctrl.addStretch()
        ext_layout.addLayout(ex_ctrl)

        self.ext_table = QTableView()
        self.configure_table(self.ext_table)
        self.ext_model = GenericTableModel(["Name", "Browser", "Version", "ID", "Status"])
        self.ext_table.setModel(self.ext_model)
        ext_layout.addWidget(self.ext_table)
        sub_tabs.addTab(ext_tab, "Extensions")

        # Certificates
        cert_tab = QWidget()
        c_layout = QVBoxLayout(cert_tab)
        c_layout.addWidget(self.create_header("Certificates", "System Root and Intermediate Certificates."))
        
        c_ctrl = QHBoxLayout()
        btn_scan_cert = QPushButton("🔄 Scan Certificates")
        btn_scan_cert.clicked.connect(lambda: self.run_partial_scan(['certificates']))
        c_ctrl.addWidget(btn_scan_cert)
        c_ctrl.addStretch()
        c_layout.addLayout(c_ctrl)

        self.cert_table = QTableView()
        self.configure_table(self.cert_table)
        self.cert_model = GenericTableModel(["Subject", "Issuer", "Expiry", "Root?"])
        self.cert_table.setModel(self.cert_model)
        self.cert_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        c_layout.addWidget(self.cert_table)
        sub_tabs.addTab(cert_tab, "Certificates")
        
        # Identity
        id_tab = QWidget()
        i_layout = QVBoxLayout(id_tab)
        i_layout.addWidget(self.create_header("User Accounts", "Local user accounts and login sessions."))
        
        id_ctrl = QHBoxLayout()
        btn_scan_id = QPushButton("🔄 Scan Users")
        btn_scan_id.clicked.connect(lambda: self.run_partial_scan(['identity']))
        id_ctrl.addWidget(btn_scan_id)
        id_ctrl.addStretch()
        i_layout.addLayout(id_ctrl)

        self.user_table = QTableView()
        self.configure_table(self.user_table)
        self.user_model = GenericTableModel(["Username", "UID", "Description", "Last Login"])
        self.user_table.setModel(self.user_model)
        self.user_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        i_layout.addWidget(self.user_table)
        sub_tabs.addTab(id_tab, "Identity")
        
        # Malware Scanner
        mal_tab = QWidget()
        m_layout = QVBoxLayout(mal_tab)
        m_layout.addWidget(self.create_header("YARA Malware Scanner", "Scan files or directories against YARA rules."))

        m_ctrl = QHBoxLayout()
        self.txt_scan_path = QLineEdit()
        self.txt_scan_path.setPlaceholderText("Select directory or file to scan...")
        btn_browse = QPushButton("Browse")
        btn_browse.clicked.connect(self.browse_scan_path)
        self.btn_yara_scan = QPushButton("Start Scan")
        self.btn_yara_scan.clicked.connect(self.start_yara_scan)
        
        m_ctrl.addWidget(self.txt_scan_path)
        m_ctrl.addWidget(btn_browse)
        m_ctrl.addWidget(self.btn_yara_scan)
        m_layout.addLayout(m_ctrl)
        
        self.lbl_scan_status = QLabel("")
        m_layout.addWidget(self.lbl_scan_status)

        self.mal_table = QTableView()
        self.configure_table(self.mal_table)
        self.mal_model = GenericTableModel(["File", "Rule", "Tags", "Meta"])
        self.mal_table.setModel(self.mal_model)
        self.mal_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        m_layout.addWidget(self.mal_table)
        
        sub_tabs.addTab(mal_tab, "Malware Scanner")

        self.main_tabs.addTab(tab, "Assets")

    def init_system_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        sub_tabs = QTabWidget()
        layout.addWidget(sub_tabs)
        
        # Health Dashboard Tab
        health_tab = QWidget()
        h_layout = QVBoxLayout(health_tab)
        
        # 1. Overall System Health Widgets
        h_layout.addWidget(self.create_header("System Health Monitor", "Real-time performance metrics."))
        
        health_metrics = QHBoxLayout()
        health_metrics.setSpacing(20)
        
        # CPU
        cpu_grp = QGroupBox("CPU Usage")
        cpu_l = QVBoxLayout(cpu_grp)
        self.lbl_cpu_val = QLabel("0%")
        self.lbl_cpu_val.setStyleSheet("font-size: 24px; font-weight: bold; color: #00ffff;")
        self.prog_cpu = QProgressBar()
        self.prog_cpu.setTextVisible(False)
        self.prog_cpu.setStyleSheet("QProgressBar::chunk { background-color: #00ffff; }")
        cpu_l.addWidget(self.lbl_cpu_val, 0, Qt.AlignmentFlag.AlignCenter)
        cpu_l.addWidget(self.prog_cpu)
        health_metrics.addWidget(cpu_grp)
        
        # RAM
        ram_grp = QGroupBox("Memory Usage")
        ram_l = QVBoxLayout(ram_grp)
        self.lbl_ram_val = QLabel("0 / 0 GB")
        self.lbl_ram_val.setStyleSheet("font-size: 16px; font-weight: bold; color: #ff00ff;")
        self.prog_ram = QProgressBar()
        self.prog_ram.setTextVisible(False)
        self.prog_ram.setStyleSheet("QProgressBar::chunk { background-color: #ff00ff; }")
        ram_l.addWidget(self.lbl_ram_val, 0, Qt.AlignmentFlag.AlignCenter)
        ram_l.addWidget(self.prog_ram)
        health_metrics.addWidget(ram_grp)
        
        # Disk
        disk_grp = QGroupBox("Disk Status")
        self.disk_layout = QVBoxLayout(disk_grp) # Dynamic population
        health_metrics.addWidget(disk_grp)
        
        h_layout.addLayout(health_metrics)
        
        # 2. Scorecard Grid
        h_layout.addWidget(self.create_header("Detailed Scorecard", "System health heuristic analysis."))
        
        score_grid = QGridLayout()
        score_grid.setSpacing(15)
        
        # Define cards (Title, ID)
        self.health_cards = {} # Store references to update later {key: (lbl_val, lbl_status)}
        
        cards = [
            ("Hardware Age", "hw_card"),
            ("OS Freshness", "os_card"),
            ("Vuln Density", "vuln_card"),
            ("Persistence Rate", "pers_card"),
            ("Stale Users", "user_card"),
            ("Driver Compliance", "drv_card")
        ]
        
        for i, (title, key) in enumerate(cards):
            card = QFrame()
            card.setStyleSheet("""
                QFrame {
                    background-color: #333333;
                    border-radius: 8px;
                    border: 1px solid #444;
                }
            """)
            c_layout = QVBoxLayout(card)
            
            lbl_title = QLabel(title)
            lbl_title.setStyleSheet("color: #aaaaaa; font-size: 12px; border: none;")
            
            lbl_val = QLabel("--")
            lbl_val.setStyleSheet("color: white; font-size: 18px; font-weight: bold; border: none;")
            
            lbl_status = QLabel("Unknown")
            lbl_status.setStyleSheet("color: #888; font-size: 10px; border: none;")
            
            c_layout.addWidget(lbl_title)
            c_layout.addWidget(lbl_val)
            c_layout.addWidget(lbl_status)
            
            self.health_cards[key] = (lbl_val, lbl_status, card)
            
            row = i // 3
            col = i % 3
            score_grid.addWidget(card, row, col)
            
        h_layout.addLayout(score_grid)
        
        # 2. Split Tables
        h_layout.addWidget(self.create_header("System Events", "Security services and stability events."))
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left: Security Center
        sec_widget = QWidget()
        sec_l = QVBoxLayout(sec_widget)
        sec_l.setContentsMargins(0, 0, 0, 0)
        sec_l.addWidget(QLabel("<b>Security Center</b>"))
        self.sec_table = QTableView()
        self.configure_table(self.sec_table)
        self.sec_model = GenericTableModel(["Service", "Status", "State"])
        self.sec_table.setModel(self.sec_model)
        self.sec_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        sec_l.addWidget(self.sec_table)
        splitter.addWidget(sec_widget)
        
        # Right: Crashes
        crash_widget = QWidget()
        crash_l = QVBoxLayout(crash_widget)
        crash_l.setContentsMargins(0, 0, 0, 0)
        crash_l.addWidget(QLabel("<b>Recent Crashes</b>"))
        self.crash_table = QTableView()
        self.configure_table(self.crash_table)
        self.crash_model = GenericTableModel(["Module", "Path", "Type", "Time"])
        self.crash_table.setModel(self.crash_model)
        self.crash_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        crash_l.addWidget(self.crash_table)
        splitter.addWidget(crash_widget)
        
        splitter.setSizes([500, 500])
        h_layout.addWidget(splitter)
        
        sub_tabs.addTab(health_tab, "Health")
        
        # Updates
        upd_tab = QWidget()
        u_layout = QVBoxLayout(upd_tab)
        u_layout.addWidget(self.create_header("Windows Updates", "Recent system patches and hotfixes."))
        
        u_ctrl = QHBoxLayout()
        btn_scan_upd = QPushButton("🔄 Scan Updates")
        btn_scan_upd.clicked.connect(lambda: self.run_partial_scan(['updates']))
        u_ctrl.addWidget(btn_scan_upd)
        u_ctrl.addStretch()
        u_layout.addLayout(u_ctrl)
        
        self.upd_table = QTableView()
        self.configure_table(self.upd_table)
        self.upd_model = GenericTableModel(["Hotfix ID", "Description", "Installed On", "By"])
        self.upd_table.setModel(self.upd_model)
        self.upd_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        u_layout.addWidget(self.upd_table)
        sub_tabs.addTab(upd_tab, "Updates")
        
        # Persistence
        pers_tab = QWidget()
        p_layout = QVBoxLayout(pers_tab)
        p_layout.addWidget(self.create_header("Persistence Mechanisms", "Startup items and scheduled tasks."))
        
        p_ctrl = QHBoxLayout()
        btn_scan_pers = QPushButton("🔄 Scan Startup")
        btn_scan_pers.clicked.connect(lambda: self.run_partial_scan(['startup']))
        p_ctrl.addWidget(btn_scan_pers)
        p_ctrl.addStretch()
        p_layout.addLayout(p_ctrl)
        
        self.startup_table = QTableView()
        self.configure_table(self.startup_table)
        self.startup_model = GenericTableModel(["Name", "Path", "Location"])
        self.startup_table.setModel(self.startup_model)
        self.startup_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        p_layout.addWidget(self.startup_table)
        sub_tabs.addTab(pers_tab, "Persistence")

        # Vulnerabilities
        vuln_tab = QWidget()
        v_layout = QVBoxLayout(vuln_tab)
        v_layout.addWidget(self.create_header("Software Vulnerabilities", "CVEs detected in installed applications."))
        
        # Bulk Actions
        self.btn_vuln_term, self.btn_vuln_ai, self.btn_vuln_vt = self.create_toolbar(v_layout)
        self.btn_vuln_term.hide()
        self.btn_vuln_vt.hide() 
        self.btn_vuln_ai.clicked.connect(lambda: self.run_bulk_action("ai", self.vuln_model, "cve"))
        
        self.vuln_table = QTableView()
        self.configure_table(self.vuln_table)
        self.vuln_model = GenericTableModel(["", "Software", "CVE ID", "Description", "Confidence", "Status"])
        self.vuln_table.setModel(self.vuln_model)
        
        # Checkable Header
        self.vuln_header = CheckableHeaderView(Qt.Orientation.Horizontal, self.vuln_table)
        self.vuln_table.setHorizontalHeader(self.vuln_header)
        # Generic toggle logic? Or lambda
        self.vuln_header.toggled.connect(lambda c: [self.vuln_model.item(r,0).setCheckState(Qt.CheckState.Checked if c else Qt.CheckState.Unchecked) for r in range(self.vuln_model.rowCount())])
        self.vuln_model.itemChanged.connect(lambda item: self.update_toolbar_state(self.vuln_model, [self.btn_vuln_ai]))

        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.vuln_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.vuln_table.setColumnWidth(0, 30)
        self.vuln_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.vuln_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.vuln_table.customContextMenuRequested.connect(lambda pos: self.show_context_menu(pos, self.vuln_table, "cve"))
        v_layout.addWidget(self.vuln_table)
        sub_tabs.addTab(vuln_tab, "Vulnerabilities")
        
        self.main_tabs.addTab(tab, "System")

    def init_config_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        sub_tabs = QTabWidget()
        layout.addWidget(sub_tabs)
        
        set_tab = QWidget()
        form_layout = QFormLayout(set_tab)
        lbl = QLabel("API Configuration")
        lbl.setStyleSheet("font-size: 16px; font-weight: bold; margin-bottom: 10px;")
        form_layout.addRow(lbl)
        self.api_nist = QLineEdit()
        self.api_gemini = QLineEdit()
        form_layout.addRow("NIST API Key:", self.api_nist)
        form_layout.addRow("Gemini API Key:", self.api_gemini)
        
        self.chk_safe_mode = QCheckBox("Safe Mode (Skip startup scans)")
        self.chk_safe_mode.setToolTip("If enabled, the application will load cached data immediately on startup instead of scanning.")
        form_layout.addRow(self.chk_safe_mode)
        
        btn_save = QPushButton("Save Configuration")
        btn_save.clicked.connect(self.save_api_keys)
        form_layout.addRow(btn_save)
        sub_tabs.addTab(set_tab, "Settings")
        
        log_tab = QWidget()
        l_layout = QVBoxLayout(log_tab)
        self.log_viewer = QTextEdit()
        self.log_viewer.setReadOnly(True)
        l_layout.addWidget(self.log_viewer)
        sub_tabs.addTab(log_tab, "Logs")
        
        self.main_tabs.addTab(tab, "Configuration")

    # --- Helpers ---
    
    def create_kpi_card(self, title, icon, color="#007acc"):
        """Creates a standardized KPI card."""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: #2d2d2d;
                border-left: 4px solid {color};
                border-radius: 4px;
            }}
            QLabel {{ border: none; background: transparent; }}
        """)
        card.setFrameShape(QFrame.Shape.StyledPanel)
        
        layout = QVBoxLayout(card)
        
        # Header
        h_layout = QHBoxLayout()
        l_icon = QLabel(icon)
        l_icon.setFont(QFont("Segoe UI Emoji", 18))
        l_title = QLabel(title)
        l_title.setStyleSheet("font-weight: bold; font-size: 14px; color: #cccccc;")
        h_layout.addWidget(l_icon)
        h_layout.addWidget(l_title)
        h_layout.addStretch()
        layout.addLayout(h_layout)
        
        # Value
        l_val = QLabel("Loading...")
        l_val.setStyleSheet("font-size: 24px; font-weight: bold; color: white; margin: 5px 0;")
        l_val.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(l_val)
        
        # Description
        l_desc = QLabel("Waiting for data...")
        l_desc.setStyleSheet("color: #888888; font-size: 11px;")
        l_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        l_desc.setWordWrap(True)
        layout.addWidget(l_desc)
        
        # Scan Button (Hidden by default)
        btn = QPushButton("Scan Now")
        btn.setStyleSheet("""
            QPushButton {
                background-color: #333333;
                border: 1px solid #555555;
                font-size: 10px;
                padding: 4px;
            }
            QPushButton:hover { background-color: #444444; }
        """)
        btn.hide()
        layout.addWidget(btn)
        
        # Store references for updates
        card.lbl_val = l_val
        card.lbl_desc = l_desc
        card.btn_scan = btn
        
        return card

    def create_header(self, title, desc):
        container = QWidget()
        lay = QVBoxLayout(container)
        lay.setContentsMargins(0,0,0,0)
        l_title = QLabel(title)
        l_title.setObjectName("Header")
        l_desc = QLabel(desc)
        l_desc.setObjectName("Desc")
        lay.addWidget(l_title)
        lay.addWidget(l_desc)
        return container

    # --- Logic ---

    def load_api_keys(self):
        config = ConfigManager.load_config()
        self.api_nist.setText(config.get("nist_api_key", ""))
        self.api_gemini.setText(config.get("gemini_api_key", ""))
        self.chk_safe_mode.setChecked(config.get("safe_mode", "false").lower() == "true")
        logging.info("Configuration loaded.")

    def save_api_keys(self):
        data = {
            "nist_api_key": self.api_nist.text(),
            "gemini_api_key": self.api_gemini.text(),
            "safe_mode": "true" if self.chk_safe_mode.isChecked() else "false"
        }
        ConfigManager.save_config(data)
        logging.info("Configuration saved successfully.")
        self.status_bar.showMessage("Settings Saved")

    def refresh_threat_feed(self):
        logging.info("Refreshing Threat Intel Feed (Reset)...")
        self.feed_offset = 0
        self.adv_worker = AdvisoryWorker(start_index=0, limit=50)
        self.adv_worker.progress.connect(self.update_scan_status)
        self.adv_worker.finished.connect(self.on_threat_feed_finished)
        self.adv_worker.start()

    def fetch_more_intel(self):
        self.feed_offset += 50
        logging.info(f"Fetching More Intel (Offset {self.feed_offset})...")
        self.status_bar.showMessage(f"Fetching older advisories (Offset {self.feed_offset})...")
        
        self.adv_worker = AdvisoryWorker(start_index=self.feed_offset, limit=50)
        self.adv_worker.progress.connect(self.update_scan_status)
        # Reuse same finish handler as it reloads the table from DB
        self.adv_worker.finished.connect(self.on_threat_feed_finished)
        self.adv_worker.start()

    def on_threat_feed_finished(self):
        self.status_bar.showMessage("Feed Updated")
        self.refresh_dashboard_data()

    def toggle_process_monitor(self, state):
        if state == 2:
            logging.info("Starting Process Monitor...")
            self.proc_worker.start()
        else:
            logging.info("Stopping Process Monitor...")
            self.proc_worker.stop()

    def update_process_view(self, data):
        self.proc_model.setRowCount(0)
        for p in data:
            self.proc_model.appendRow([
                QStandardItem(str(p['pid'])),
                QStandardItem(str(p['name'])),
                QStandardItem(str(p['path'])),
                QStandardItem(f"{p['memory']:.2f}"),
                QStandardItem(f"{p['cpu']:.1f}"),
                QStandardItem(str(p['username']))
            ])
            
        pass

    # --- Modular Loaders ---

    def load_table_software(self):
        rows = self.db.execute_query("SELECT name, version, publisher, install_date FROM installed_software")
        self.inv_model.setRowCount(0)
        for row in rows:
            self.inv_model.appendRow([QStandardItem(str(f)) for f in row])
        self.inv_model.setRowCount(0)
        for row in rows:
            self.inv_model.appendRow([QStandardItem(str(f)) for f in row])

    def load_table_exposure(self):
        rows = self.db.execute_query("SELECT port, protocol, process_name, username, binary_path FROM exposed_services")
        self.exposure_model.setRowCount(0)
        for row in rows:
            self.exposure_model.appendRow([QStandardItem(str(f)) for f in row])
        self.exposure_model.setRowCount(0)
        for row in rows:
            self.exposure_model.appendRow([QStandardItem(str(f)) for f in row])
        
    def load_table_risk(self):
        rows = self.db.execute_query("SELECT port, protocol, process_name, risk_score FROM exposed_services ORDER BY risk_score DESC")
        self.risk_model.setRowCount(0)
        for row in rows:
            items = [QStandardItem(str(f)) for f in row]
            if row[3] and int(row[3]) > 60:
                for item in items:
                    item.setForeground(QBrush(QColor("#ff4444")))
            self.risk_model.appendRow(items)

    def load_table_certs(self):
        rows = self.db.execute_query("SELECT subject, issuer, expiry_date, is_root FROM certificates")
        self.cert_model.setRowCount(0)
        for row in rows:
                self.cert_model.appendRow([QStandardItem(str(f)) for f in row])

    def load_table_startup(self):
        rows = self.db.execute_query("SELECT name, path, location FROM startup_items")
        self.startup_model.setRowCount(0)
        for row in rows:
            self.startup_model.appendRow([QStandardItem(str(f)) for f in row])

    def load_table_network(self):
        rows = self.db.execute_query("SELECT pid, local_addr, remote_addr, state, protocol FROM telemetry_network LIMIT 200")
        self.net_model.setRowCount(0)
        for row in rows:
            self.net_model.appendRow([QStandardItem(str(f)) for f in row])
        
        # Also Load Hosts
        h_rows = self.db.execute_query("SELECT hostnames, ip_address FROM telemetry_hosts")
        self.hosts_model.setRowCount(0)
        for row in h_rows:
             self.hosts_model.appendRow([QStandardItem(str(f)) for f in row])

    def load_table_identity(self):
        rows = self.db.execute_query("SELECT username, uid, description, last_login FROM user_accounts")
        self.user_model.setRowCount(0)
        for row in rows:
            self.user_model.appendRow([QStandardItem(str(f)) for f in row])

    def load_table_intel(self):
        rows = self.db.execute_query("SELECT pub_date, severity, title, impact, cve_ids, description FROM advisories ORDER BY pub_date DESC")
        self.intel_model.setRowCount(0)
        for row in rows:
            date_str = str(row[0]).split(' ')[0]
            severity = float(row[1]) if row[1] else 0.0
            items = [
                QStandardItem(date_str),
                QStandardItem(str(severity)),
                QStandardItem(str(row[2])),
                QStandardItem(str(row[3])),
                QStandardItem(str(row[4]))
            ]
            items[0].setData(row[5], Qt.ItemDataRole.UserRole)
            if severity >= 7.0:
                color = "#ff4444" if severity >= 9.0 else "#ff8800"
                for item in items: item.setForeground(QBrush(QColor(color)))
            self.intel_model.appendRow(items)

    def load_table_drivers(self):
        rows = self.db.execute_query("SELECT name, description, provider, status, signed FROM telemetry_drivers")
        self.drv_model.setRowCount(0)
        for row in rows:
            self.drv_model.appendRow([QStandardItem(str(f)) for f in row])

    def load_table_extensions(self):
        rows = self.db.execute_query("SELECT name, browser, version, identifier, status FROM telemetry_browser_extensions")
        self.ext_model.setRowCount(0)
        for row in rows:
            self.ext_model.appendRow([QStandardItem(str(f)) for f in row])

    def load_table_health(self):
        # 1. System Metrics
        try:
            health = self.inv_mgr.get_system_health()
            
            # CPU
            cpu_p = health['cpu'].get('percent', 0)
            self.lbl_cpu_val.setText(f"{cpu_p}%")
            self.prog_cpu.setValue(int(cpu_p))
            
            # RAM
            ram = health['ram']
            total_gb = ram.get('total', 0) / (1024**3)
            used_gb = (ram.get('total', 0) - ram.get('available', 0)) / (1024**3)
            self.lbl_ram_val.setText(f"{used_gb:.1f} / {total_gb:.1f} GB")
            self.prog_ram.setValue(int(ram.get('percent', 0)))
            
            # Disk (Clear and Rebuild)
            while self.disk_layout.count():
                item = self.disk_layout.takeAt(0)
                widget = item.widget()
                if widget:
                    widget.deleteLater()
            
            for d in health.get('disk', []):
                d_widget = QWidget()
                d_l = QHBoxLayout(d_widget)
                d_l.setContentsMargins(0, 0, 0, 0)
                d_lbl = QLabel(f"{d['device']} ({d['percent']}%)")
                d_lbl.setStyleSheet("color: white;")
                d_prog = QProgressBar()
                d_prog.setFixedHeight(10)
                d_prog.setTextVisible(False)
                d_prog.setValue(int(d['percent']))
                if d['percent'] > 80:
                    d_prog.setStyleSheet("QProgressBar::chunk { background-color: #ff4444; }")
                else:
                     d_prog.setStyleSheet("QProgressBar::chunk { background-color: #00ff00; }")
                d_l.addWidget(d_lbl)
                d_l.addWidget(d_prog)
                self.disk_layout.addWidget(d_widget)
                
        except Exception as e:
            logging.error(f"Error loading system health: {e}")

        # 2. Update Scorecard
        try:
            # Helper to set card
            def set_card(key, value, text, color="#00ff00"):
                if key in self.health_cards:
                    lbl_val, lbl_stat, card = self.health_cards[key]
                    lbl_val.setText(str(value))
                    lbl_stat.setText(text)
                    lbl_stat.setStyleSheet(f"color: {color}; font-size: 10px; border: none;")
                    card.setStyleSheet(f"background-color: #333333; border: 1px solid {color}; border-radius: 8px;")

            # Hardware Age
            hw = int(self.db.get_metadata("hw_age_days") or -1)
            if hw == -1: set_card("hw_card", "N/A", "Unknown", "#888")
            else:
                 color = "#00ff00"
                 status = "Good"
                 if hw > 1825: # 5 years
                     color = "#ff4444"
                     status = "End of Life"
                 elif hw > 1095: # 3 years
                     color = "#ff8800"
                     status = "Aging"
                 set_card("hw_card", f"{hw} Days", status, color)

            # OS Freshness
            os_days = int(self.db.get_metadata("os_freshness_days") or -1)
            if os_days == -1: set_card("os_card", "N/A", "Unknown", "#888")
            else:
                 color = "#00ff00"
                 status = "Fresh"
                 if os_days > 1095: # 3 years
                     color = "#ff4444" 
                     status = "Re-Imaging Rec."
                 elif os_days > 730: # 2 years
                     color = "#ff8800"
                     status = "Consider Update"
                 set_card("os_card", f"{os_days} Days", status, color)

            # Vuln Density
            vd = float(self.db.get_metadata("vuln_density") or 0)
            color = "#00ff00"
            if vd > 20: color = "#ff4444"
            elif vd > 10: color = "#ff8800"
            set_card("vuln_card", f"{vd:.1f}%", "Vuln/App Ratio", color)

            # Persistence
            pd = float(self.db.get_metadata("persistence_density") or 0)
            color = "#00ff00"
            if pd > 15: color = "#ff4444" # Abnormally high startup
            elif pd > 8: color = "#ff8800"
            set_card("pers_card", f"{pd:.1f}%", "Startup/Proc Ratio", color)
            
            # Stale Users
            su = int(self.db.get_metadata("stale_user_count") or 0)
            color = "#00ff00"
            if su > 2: color = "#ff4444"
            elif su > 0: color = "#ff8800"
            set_card("user_card", str(su), "Inactive > 90d", color)
            
            # Driver Compliance
            ud = int(self.db.get_metadata("unsigned_drivers") or 0)
            color = "#00ff00"
            if ud > 0: color = "#ff4444"
            set_card("drv_card", str(ud), "Unsigned Drivers", color)

        except Exception as e:
            logging.error(f"Scorecard Update Error: {e}")

        # 3. Security Center
        sec_rows = self.db.execute_query("SELECT service, status, state FROM telemetry_security_center")
        self.sec_model.setRowCount(0)
        for row in sec_rows:
            self.sec_model.appendRow([QStandardItem(str(f)) for f in row])

        # 3. Crashes
        crash_rows = self.db.execute_query("SELECT module, path, type, crash_time FROM telemetry_crashes ORDER BY crash_time DESC LIMIT 50")
        self.crash_model.setRowCount(0)
        for row in crash_rows:
            self.crash_model.appendRow([QStandardItem(str(f)) for f in row])

    def load_table_updates(self):
        rows = self.db.execute_query("SELECT hotfix_id, description, installed_on, installed_by FROM telemetry_windows_updates")
        self.upd_model.setRowCount(0)
        for row in rows:
             self.upd_model.appendRow([QStandardItem(str(f)) for f in row])
             
    def load_table_vulns(self):
         rows = self.db.execute_query("""
            SELECT s.name, m.cve_id, 'Description Unavailable', m.confidence, m.status 
            FROM vulnerability_matches m
            JOIN installed_software s ON m.software_id = s.id
         """)
         # Note: Description removed from schema? Or mock? 
         # In original code, desc match was hardcoded or from CVE db. 
         # For now, minimal query.
         self.vuln_model.setRowCount(0)
         
         for row in rows:
             item_chk = QStandardItem("")
             item_chk.setCheckable(True)
             parts = [item_chk] + [QStandardItem(str(f)) for f in row]
             self.vuln_model.appendRow(parts)
             
         # Update Vulnerability Plot
         detected = len([r for r in rows if r[4] == 'Detected'])
         resolved = len([r for r in rows if r[4] == 'Resolved' or r[4] == 'Patched'])
         # If no resolved data, maybe simulate simply
         if resolved == 0 and detected == 0:
             # Fallback query if 'status' field is empty
              resolved = 0
         
         # self.bar_risk.setOpts(height=[detected, resolved])

    def load_fim_alerts(self):
        rows = self.db.execute_query("SELECT timestamp, file_path, action_type, severity FROM telemetry_fim_alerts ORDER BY id DESC LIMIT 50")
        self.fim_model.setRowCount(0)
        for row in rows:
            self.fim_model.appendRow([QStandardItem(str(f)) for f in row])

    def refresh_dashboard_data(self):
        """Refreshes all dashboard data."""
        logging.info("Refreshing Dashboard Data (UI Side)...")
        
        try:
            # 1. Update KPI Cards
            
            # --- ASSETS ---
            app_count = self.db.execute_query("SELECT count(*) FROM installed_software")[0][0] or 0
            if app_count == 0:
                self.kpi_assets.lbl_val.setText("No Data")
                self.kpi_assets.lbl_desc.setText("Click Scan to enumerate apps.")
                self.kpi_assets.btn_scan.show()
                self.kpi_assets.setStyleSheet(self.kpi_assets.styleSheet() + "QFrame { border-left-color: #555; }")
            else:
                 self.kpi_assets.lbl_val.setText(f"{app_count} Apps")
                 self.kpi_assets.lbl_desc.setText("Installed Applications detected.")
                 self.kpi_assets.btn_scan.hide()
                 self.kpi_assets.setStyleSheet(self.kpi_assets.styleSheet() + "QFrame { border-left-color: #007acc; }")

            # --- NETWORK ---
            port_count = self.db.execute_query("SELECT count(*) FROM exposed_services")[0][0] or 0
            conn_count = self.db.execute_query("SELECT count(*) FROM telemetry_network")[0][0] or 0
            if port_count == 0 and conn_count == 0:
                self.kpi_network.lbl_val.setText("No Data")
                self.kpi_network.lbl_desc.setText("Scan to see network activity.")
                self.kpi_network.btn_scan.show()
                self.kpi_network.setStyleSheet(self.kpi_network.styleSheet() + "QFrame { border-left-color: #555; }")
            else:
                self.kpi_network.lbl_val.setText(f"{port_count} Ports / {conn_count} Conns")
                self.kpi_network.lbl_desc.setText("Listening ports and active connections.")
                self.kpi_network.btn_scan.hide()
                self.kpi_network.setStyleSheet(self.kpi_network.styleSheet() + "QFrame { border-left-color: #007acc; }")
                
            # --- IDENTITY ---
            user_count = self.db.execute_query("SELECT count(*) FROM user_accounts")[0][0] or 0
            if user_count == 0:
                self.kpi_identity.lbl_val.setText("No Data")
                self.kpi_identity.lbl_desc.setText("Scan Identity to see users.")
                self.kpi_identity.btn_scan.show()
                self.kpi_identity.setStyleSheet(self.kpi_identity.styleSheet() + "QFrame { border-left-color: #555; }")
            else:
                self.kpi_identity.lbl_val.setText(f"{user_count} Users")
                self.kpi_identity.lbl_desc.setText("Local user accounts present.")
                self.kpi_identity.btn_scan.hide()
                self.kpi_identity.setStyleSheet(self.kpi_identity.styleSheet() + "QFrame { border-left-color: #007acc; }")
                
            # --- HEALTH ---
            crash_count = self.db.execute_query("SELECT count(*) FROM telemetry_crashes")[0][0] or 0
            if crash_count == 0:
                 self.kpi_health.lbl_val.setText("Good")
                 self.kpi_health.lbl_desc.setText("No recent system crashes detected.")
                 self.kpi_health.btn_scan.hide()
                 self.kpi_health.setStyleSheet(self.kpi_health.styleSheet() + "QFrame { border-left-color: #00ff00; }")
            else:
                 self.kpi_health.lbl_val.setText(f"{crash_count} Crashes")
                 self.kpi_health.lbl_desc.setText("Recent application crashes found.")
                 self.kpi_health.btn_scan.hide()
                 self.kpi_health.setStyleSheet(self.kpi_health.styleSheet() + "QFrame { border-left-color: #ff8800; }")
            
            # --- VULNERABILITIES ---
            vuln_count = self.db.execute_query("SELECT count(*) FROM vulnerability_matches WHERE status='Detected'")[0][0] or 0
            crit_count = self.db.execute_query("SELECT count(*) FROM vulnerability_matches m JOIN cves c ON m.cve_id = c.cve_id WHERE c.cvss_score >= 9.0 AND m.status='Detected'")[0][0] or 0
            
            if vuln_count == 0:
                self.kpi_vulns.lbl_val.setText("Safe")
                self.kpi_vulns.lbl_desc.setText("No vulnerabilities detected (or not scanned).")
                self.kpi_vulns.setStyleSheet(self.kpi_vulns.styleSheet() + "QFrame { border-left-color: #00ff00; }")
            else:
                 self.kpi_vulns.lbl_val.setText(f"{vuln_count} CVEs")
                 desc = f"{crit_count} Critical." if crit_count > 0 else "No Critical Issues."
                 self.kpi_vulns.lbl_desc.setText(desc)
                 if crit_count > 0:
                     self.kpi_vulns.setStyleSheet(self.kpi_vulns.styleSheet() + "QFrame { border-left-color: #e51400; }")
                 else:
                     self.kpi_vulns.setStyleSheet(self.kpi_vulns.styleSheet() + "QFrame { border-left-color: #f0a30a; }")

            # --- CHANGES ---
            # Get latest delta sum
            try:
                # Get sum of absolute deltas from the last 5 minutes? Or just last entries?
                # Let's get the standard "items changed since last run" - simply sum 'delta_count' of strict latest run per category?
                # User asked: "Items changed since last scan". simple approach: show the last non-zero delta.
                res = self.db.execute_query("SELECT category, delta_count, timestamp FROM scan_summaries WHERE delta_count != 0 ORDER BY timestamp DESC LIMIT 1")
                if res:
                    cat, delta, ts = res[0]
                    sign = "+" if delta > 0 else ""
                    self.kpi_changes.lbl_val.setText(f"{sign}{delta} Items")
                    self.kpi_changes.lbl_desc.setText(f"{cat} changed at {ts[-8:]}")
                    self.kpi_changes.setStyleSheet(self.kpi_changes.styleSheet() + "QFrame { border-left-color: #f0a30a; }")
                else:
                    self.kpi_changes.lbl_val.setText("No Changes")
                    self.kpi_changes.lbl_desc.setText("System state is stable.")
                    self.kpi_changes.setStyleSheet(self.kpi_changes.styleSheet() + "QFrame { border-left-color: #00ff00; }")
            except: pass

            # 2. Reload Tables
            self.load_table_software()
            self.load_table_exposure()
            self.load_table_risk()
            self.load_table_certs()
            self.load_table_startup()
            self.load_table_network()
            self.load_table_identity()
            self.load_table_intel()
            self.load_table_drivers()
            self.load_table_extensions()
            self.load_table_health()
            self.load_table_updates()
            self.load_table_vulns()
            self.load_fim_alerts()
            logging.info("UI Refresh Complete.")
        except Exception as e:
            logging.error(f"Error refreshing dashboard: {e}", exc_info=True)

    def load_table_fim(self):
         # Placeholder if needed, handled by alert signal usually
         pass

    def handle_fim_alert(self, data):
        # Insert into DB
        try:
            query = "INSERT INTO telemetry_fim_alerts (timestamp, file_path, action_type, severity) VALUES (?, ?, ?, ?)"
            
            # Update UI
            items = [
                QStandardItem(data['timestamp']),
                QStandardItem(data['file_path']),
                QStandardItem(data['action_type']),
                QStandardItem(data['severity'])
            ]
            self.fim_model.insertRow(0, items)
            if self.fim_model.rowCount() > 50:
                self.fim_model.removeRow(50)
                
            # Show notification or log
            logging.warning(f"FIM Alert: {data['action_type']} on {data['file_path']}")
            
        except Exception as e:
            logging.error(f"Failed to handle FIM alert: {e}")

    # --- Malware Scanner ---
    def browse_scan_path(self):
        path = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if path:
            self.txt_scan_path.setText(path)

    def start_yara_scan(self):
        path = self.txt_scan_path.text()
        if not path:
             return
        
        self.btn_yara_scan.setEnabled(False)
        self.mal_model.setRowCount(0)
        self.lbl_scan_status.setText("Scanning...")
        
        self.yara_worker = YaraScanWorker(path)
        self.yara_worker.progress.connect(lambda msg: self.lbl_scan_status.setText(msg))
        self.yara_worker.result.connect(self.on_yara_result)
        self.yara_worker.finished.connect(self.on_yara_finished)
        self.yara_worker.start()

    def on_yara_result(self, matches):
        for m in matches:
             self.mal_model.appendRow([
                 QStandardItem(m['file']),
                 QStandardItem(m['rule']),
                 QStandardItem(str(m['tags'])),
                 QStandardItem(str(m['meta']))
             ])
    
    def on_yara_finished(self):
        self.lbl_scan_status.setText(f"Scan Finished. Matches: {self.mal_model.rowCount()}")
        self.btn_yara_scan.setEnabled(True)

    # --- AI Features ---

    # --- AI Features ---

    def show_context_menu(self, pos, table, context_type):
        index = table.indexAt(pos)
        if not index.isValid():
            return
        
        row = index.row()
        menu = QMenu(self)
        analyze_act = QAction("✨ AI Analyze / Explain", self)
        menu.addAction(analyze_act)
        
        # Reputation Check for specific tables
        if context_type in ["proc", "net"]:
            rep_act = QAction("✨ Check Reputation (VT)", self)
            menu.addAction(rep_act)
            rep_act.triggered.connect(lambda: self.check_reputation(row, table, context_type))

        # Active Response
        if context_type == "proc":
             kill_act = QAction("🚫 Terminate Process", self)
             menu.addAction(kill_act)
             kill_act.triggered.connect(lambda: self.terminate_process_action(row))
        elif context_type == "net":
             block_act = QAction("🚫 Block Remote IP", self)
             menu.addAction(block_act)
             block_act.triggered.connect(lambda: self.block_ip_action(row))

        # Action handling
        action = menu.exec(table.viewport().mapToGlobal(pos))
        if action == analyze_act:
             # Prepare Context Data based on table type
            context_data = {}
            if context_type == "risk":
                # Model: Port, Protocol, Process, Risk Score
                context_data = {
                    "type": "exposure",
                    "port": self.risk_model.item(row, 0).text(),
                    "protocol": self.risk_model.item(row, 1).text(),
                    "process_name": self.risk_model.item(row, 2).text(),
                    "risk_score": self.risk_model.item(row, 3).text(),
                    "risk_reasons": "High risk score detected on exposed port."
                }
            elif context_type == "intel":
                 # Model: Date, Severity, Title, Impact, CVEs
                 context_data = {
                     "type": "cve",
                     "title": self.intel_model.item(row, 2).text(),
                     "severity": self.intel_model.item(row, 1).text(),
                     "description": self.intel_model.item(row, 0).data(Qt.ItemDataRole.UserRole)
                 }
            elif context_type == "cve":
                 # Model: Software, CVE ID, Desc, Score, Confidence
                 context_data = {
                     "type": "cve",
                     "title": f"{self.vuln_model.item(row, 1).text()} in {self.vuln_model.item(row, 0).text()}",
                     "description": self.vuln_model.item(row, 2).text(),
                     "severity": self.vuln_model.item(row, 3).text()
                 }
            
            if context_data:
                self.trigger_ai_analysis(context_data)
            else:
                self.show_ai_result("Context not supported for AI explanation yet.")

    def check_reputation(self, row, table, context_type):
        path = ""
        try:
            if context_type == "proc":
                # Model: PID, Name, Path, Mem, CPU, User. Path is index 2.
                path = self.proc_model.item(row, 2).text()
            elif context_type == "net":
                # Model: PID, L. Addr, R. Addr, State, Proto.
                # Need to find path from PID
                pid_str = self.net_model.item(row, 0).text()
                if pid_str:
                    import psutil
                    try:
                        proc = psutil.Process(int(pid_str))
                        path = proc.exe()
                    except:
                        path = ""
            
            if not path or not os.path.exists(path):
                QMessageBox.warning(self, "Error", f"Invalid File Path: {path}")
                return

            self.status_bar.showMessage(f"Checking Reputation: {path}...")
            self.rep_worker = ReputationWorker(path)
            self.rep_worker.finished.connect(self.on_reputation_result)
            self.rep_worker.start()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start reputation check: {e}")

    def on_reputation_result(self, result):
        self.status_bar.showMessage("Reputation Check Complete")
        if "error" in result:
             QMessageBox.warning(self, "Reputation Result", f"Error: {result['error']}")
        else:
             vt = result.get("vt", {})
             if "malicious" in vt:
                 msg = f"Hash: {result.get('hash')}\n\nVirusTotal Analysis:\n"
                 msg += f"🔴 Malicious: {vt.get('malicious', 0)}\n"
                 msg += f"🟠 Suspicious: {vt.get('suspicious', 0)}\n"
                 msg += f"🟢 Harmless: {vt.get('harmless', 0)}\n"
                 msg += f"⚪ Undetected: {vt.get('undetected', 0)}\n"
                 
                 icon = QMessageBox.Icon.Warning if vt.get('malicious', 0) > 0 else QMessageBox.Icon.Information
                 QMessageBox.information(self, "Reputation Result", msg) # Using info dialog but custom icon relies on more code, default is fine.
             else:
                 QMessageBox.warning(self, "Reputation Result", f"Unexpected VT response: {vt}")


    def trigger_ai_analysis(self, context_data):
        self.status_bar.showMessage("Asking Gemini AI...")
        self.ai_worker = AIWorker(context_data)
        self.ai_worker.result.connect(self.show_ai_result)
        self.ai_worker.start()

    def show_ai_result(self, text):
        self.status_bar.showMessage("AI Analysis Complete")
        dlg = QDialog(self)
        dlg.setWindowTitle("Gemini AI Analysis")
        dlg.resize(600, 500)
        lay = QVBoxLayout(dlg)
        
        txt = QTextEdit()
        txt.setMarkdown(text)
        txt.setReadOnly(True)
        lay.addWidget(txt)
        
        btn = QPushButton("Close")
        btn.clicked.connect(dlg.accept)
        lay.addWidget(btn)
        
        dlg.exec()

    def create_toolbar(self, layout):
        toolbar = QHBoxLayout()
        btn_terminate = QPushButton("Terminate Process")
        btn_ai = QPushButton("AI Analysis")
        btn_vt = QPushButton("VirusTotal Scan")
        
        btn_terminate.setEnabled(False)
        btn_ai.setEnabled(False)
        btn_vt.setEnabled(False)
        
        # Style
        btn_terminate.setStyleSheet("background-color: #8B0000;") # Dark Red

        toolbar.addWidget(btn_terminate)
        toolbar.addWidget(btn_ai)
        toolbar.addWidget(btn_vt)
        toolbar.addStretch()
        
        layout.addLayout(toolbar)
        return btn_terminate, btn_ai, btn_vt

    def run_bulk_action(self, action, model, table_type):
        """
        Executes bulk action on checked rows in model.
        table_type: 'proc', 'vuln', 'intel'
        """
        checked_rows = []
        for row in range(model.rowCount()):
            item = model.item(row, 0)
            if item.checkState() == Qt.CheckState.Checked:
                checked_rows.append(row)
        
        if not checked_rows:
            QMessageBox.warning(self, "Bulk Action", "No items selected.")
            return

        self.status_bar.showMessage(f"Processing {len(checked_rows)} items...")
        
        if not hasattr(self, 'bulk_workers'):
            self.bulk_workers = []

        count = 0
        for row in checked_rows:
            # Get Context Data
            if table_type == 'proc':
                # PID is col 1 (since 0 is checkbox)
                pid = model.item(row, 1).text()
                path = model.item(row, 3).text()
                
                if action == 'terminate':
                    self.response_mgr.terminate_process(int(pid))
                    count += 1
                elif action == 'vt':
                    if path and os.path.exists(path):
                        if count == 0: self.status_bar.showMessage(f"Queuing VT scans...")
                        worker = ReputationWorker(path)
                        worker.finished.connect(self.on_bulk_vt_result)
                        worker.start()
                        self.bulk_workers.append(worker)
                        count += 1
            
            elif table_type == 'cve':
                 # Vuln logic (AI Analysis)
                 # Running 50 AI calls is expensive/slow.
                 # Maybe limit or queue?
                 pass

        self.status_bar.showMessage(f"Bulk Action '{action}' Queued/Done for {count} items.")
        
        if action == 'terminate':
            QMessageBox.information(self, "Bulk Terminate", f"Terminated {count} processes.")
            self.run_partial_scan(['processes'])
            
    def on_bulk_vt_result(self, result):
        if "error" in result:
             logging.error(f"Bulk VT Error: {result['error']}")
        else:
             vt = result.get("vt", {})
             f_hash = result.get("hash", "Unknown")
             logging.info(f"Bulk VT Result for {f_hash}: {vt}")
             if vt.get("malicious", 0) > 0:
                 self.status_bar.showMessage(f"⚠️ Malicious file detected: {f_hash}")

    def toggle_all_processes(self, checked):
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        for row in range(self.proc_model.rowCount()):
             self.proc_model.item(row, 0).setCheckState(state)

    def update_toolbar_state(self, model, buttons):
        # Enable buttons if any row is checked
        has_checked = False
        for row in range(model.rowCount()):
            if model.item(row, 0).checkState() == Qt.CheckState.Checked:
                has_checked = True
                break
        
        for btn in buttons:
            btn.setEnabled(has_checked)

    def update_process_view(self, data):
        """Updates the process table with new data."""
        self.proc_model.setRowCount(0)
        
        for p in data:
            # Checkbox Item
            item_chk = QStandardItem("")
            item_chk.setCheckable(True)
            
            pid = str(p.get('pid', ''))
            name = str(p.get('name', ''))
            path = str(p.get('path', '')) or ""
            mem = f"{p.get('memory', 0.0):.1f}"
            cpu = f"{p.get('cpu', 0.0):.1f}"
            user = str(p.get('username', ''))
            
            items = [
                item_chk,
                QStandardItem(pid),
                QStandardItem(name),
                QStandardItem(path),
                QStandardItem(mem),
                QStandardItem(cpu),
                QStandardItem(user)
            ]
            
            # Highlight high resource usage
            if float(cpu) > 50.0:
                 items[5].setForeground(QBrush(QColor("#ff4444"))) # Red
                 
            self.proc_model.appendRow(items)
        
        # Restore checkbox states? 
        # For now, refreshing clears selection. Ideally, we should persist selection by ID.
        # But since processes change, simple clear is acceptable for V1.
