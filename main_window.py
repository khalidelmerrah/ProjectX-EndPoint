import sys
import logging
import json
import datetime
from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QTabWidget, QTableView, 
                             QLabel, QPushButton, QHBoxLayout, QSplitter, QTreeWidget, QTreeWidgetItem,
                             QFormLayout, QLineEdit, QCheckBox, QSlider, QProgressBar, QFrame, QHeaderView, QTextEdit,
                             QAbstractItemView, QMenu, QMessageBox, QDialog, QSizePolicy, QGroupBox, QScrollArea)
from PyQt6.QtCore import Qt, QAbstractTableModel, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QStandardItemModel, QStandardItem, QColor, QBrush, QAction
from workers import ScanWorker, ProcessWorker, AIWorker, AdvisoryWorker
from db_manager import DatabaseManager
from managers import ConfigManager

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
        
        self.db = DatabaseManager()
        
        # Setup Logging Handler
        self.log_handler = QtLogHandler()
        self.log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(self.log_handler)
        
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
        
        # Initial Data Refresh & Load Config
        self.load_api_keys()
        self.refresh_dashboard_data()
        
        # Initial Feed Fetch
        self.refresh_threat_feed()
    
    def closeEvent(self, event):
        logging.getLogger().removeHandler(self.log_handler)
        if hasattr(self, 'proc_worker'):
            self.proc_worker.stop()
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
        
        kpi_layout = QHBoxLayout()
        self.lbl_kpi_apps = QLabel("Installed Apps: --")
        self.lbl_kpi_services = QLabel("Exposed Services: --")
        self.lbl_kpi_vulns = QLabel("High Risk Vulns: --")
        self.lbl_kpi_conns = QLabel("Active Conns: --")
        for lbl in [self.lbl_kpi_apps, self.lbl_kpi_services, self.lbl_kpi_vulns, self.lbl_kpi_conns]:
            lbl.setStyleSheet("background: #2d2d2d; padding: 15px; border-radius: 5px; font-weight: bold;")
            kpi_layout.addWidget(lbl)
        d_layout.addLayout(kpi_layout)
        
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
        sub_tabs.addTab(dash_tab, "Dashboard")
        
        # Threat Intelligence
        intel_tab = QWidget()
        i_layout = QVBoxLayout(intel_tab)
        i_layout.addWidget(self.create_header("Threat Intelligence Feed", "Latest security advisories."))
        i_ctrl = QHBoxLayout()
        btn_refresh_intel = QPushButton("🔄 Refresh Feed")
        btn_refresh_intel.clicked.connect(self.refresh_threat_feed)
        i_ctrl.addWidget(btn_refresh_intel)
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
        ctrl_layout = QHBoxLayout()
        self.chk_autorefresh = QCheckBox("Auto-refresh (5s)")
        self.chk_autorefresh.stateChanged.connect(self.toggle_process_monitor)
        ctrl_layout.addWidget(self.chk_autorefresh)
        p_layout.addLayout(ctrl_layout)
        self.proc_table = QTableView()
        self.configure_table(self.proc_table)
        self.proc_model = GenericTableModel(["PID", "Name", "Path", "Mem (MB)", "CPU %", "User"])
        self.proc_table.setModel(self.proc_model)
        self.proc_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
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
        
        self.main_tabs.addTab(tab, "Assets")

    def init_system_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        sub_tabs = QTabWidget()
        layout.addWidget(sub_tabs)
        
        # Health
        health_tab = QWidget()
        h_layout = QVBoxLayout(health_tab)
        
        h_ctrl = QHBoxLayout()
        btn_scan_health = QPushButton("🔄 Scan Health")
        btn_scan_health.clicked.connect(lambda: self.run_partial_scan(['health']))
        h_ctrl.addWidget(btn_scan_health)
        h_ctrl.addStretch()
        h_layout.addLayout(h_ctrl)
        
        h_layout.addWidget(self.create_header("Power & Battery", "Battery health status."))
        self.lbl_battery = QLabel("No Battery Data")
        self.lbl_battery.setStyleSheet("font-size: 14px; font-weight: bold; margin-left: 10px;")
        h_layout.addWidget(self.lbl_battery)
        
        h_layout.addWidget(self.create_header("Security Center", "Antivirus, Firewall, and Security settings."))
        self.sec_table = QTableView()
        self.configure_table(self.sec_table)
        self.sec_model = GenericTableModel(["Service", "Status", "State"])
        self.sec_table.setModel(self.sec_model)
        self.sec_table.setMaximumHeight(150)
        h_layout.addWidget(self.sec_table)
        
        h_layout.addWidget(self.create_header("Recent Crashes", "Application and System crashes."))
        self.crash_table = QTableView()
        self.configure_table(self.crash_table)
        self.crash_model = GenericTableModel(["Module", "Path", "Type", "Time"])
        self.crash_table.setModel(self.crash_model)
        h_layout.addWidget(self.crash_table)

        sub_tabs.addTab(health_tab, "Health")

        # Updates
        upd_tab = QWidget()
        u_layout = QVBoxLayout(upd_tab)
        u_layout.addWidget(self.create_header("Windows Updates", "History of installed patches and hotfixes."))
        
        u_ctrl = QHBoxLayout()
        btn_scan_upd = QPushButton("🔄 Scan Updates")
        btn_scan_upd.clicked.connect(lambda: self.run_partial_scan(['updates']))
        u_ctrl.addWidget(btn_scan_upd)
        u_ctrl.addStretch()
        u_layout.addLayout(u_ctrl)

        self.upd_table = QTableView()
        self.configure_table(self.upd_table)
        self.upd_model = GenericTableModel(["Hotfix ID", "Description", "Installed On", "Installed By"])
        self.upd_table.setModel(self.upd_model)
        u_layout.addWidget(self.upd_table)
        sub_tabs.addTab(upd_tab, "Updates")

        # Persistence
        pers_tab = QWidget()
        p_layout = QVBoxLayout(pers_tab)
        p_layout.addWidget(self.create_header("Persistence", "Startup items, Registry keys, and Scheduled Tasks."))
        
        pr_ctrl = QHBoxLayout()
        btn_scan_pers = QPushButton("🔄 Scan Startup")
        btn_scan_pers.clicked.connect(lambda: self.run_partial_scan(['persistence']))
        pr_ctrl.addWidget(btn_scan_pers)
        pr_ctrl.addStretch()
        p_layout.addLayout(pr_ctrl)

        self.startup_table = QTableView()
        self.configure_table(self.startup_table)
        self.startup_model = GenericTableModel(["Name", "Path", "Location", "Status", "User"])
        self.startup_table.setModel(self.startup_model)
        p_layout.addWidget(self.startup_table)
        sub_tabs.addTab(pers_tab, "Persistence")
        
        # Vulnerabilities
        vuln_tab = QWidget()
        v_layout = QVBoxLayout(vuln_tab)
        v_layout.addWidget(self.create_header("Local Vulnerabilities", "Detected CVEs matching installed software."))
        
        # Vuln matching depends on software, so it's part of 'software' category usually, but let's allow re-matching
        v_ctrl = QHBoxLayout()
        btn_scan_vuln = QPushButton("🔄 Re-Match CVEs")
        # Scanning software triggers matching, so we call that
        btn_scan_vuln.clicked.connect(lambda: self.run_partial_scan(['software'])) 
        v_ctrl.addWidget(btn_scan_vuln)
        v_ctrl.addStretch()
        v_layout.addLayout(v_ctrl)

        self.vuln_table = QTableView()
        self.configure_table(self.vuln_table)
        self.vuln_model = GenericTableModel(["Software", "CVE ID", "Desc", "Score", "Confidence"])
        self.vuln_table.setModel(self.vuln_model)
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
        logging.info("Configuration loaded.")

    def save_api_keys(self):
        data = {
            "nist_api_key": self.api_nist.text(),
            "gemini_api_key": self.api_gemini.text()
        }
        ConfigManager.save_config(data)
        logging.info("Configuration saved successfully.")
        self.status_bar.showMessage("Settings Saved")

    def refresh_threat_feed(self):
        logging.info("Refreshing Threat Intel Feed...")
        self.adv_worker = AdvisoryWorker()
        self.adv_worker.progress.connect(self.update_scan_status)
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

    # --- Modular Loaders ---

    def load_table_software(self):
        rows = self.db.execute_query("SELECT name, version, publisher, install_date FROM installed_software")
        self.inv_model.setRowCount(0)
        for row in rows:
            self.inv_model.appendRow([QStandardItem(str(f)) for f in row])
        self.lbl_kpi_apps.setText(f"Installed Apps: {len(rows)}")

    def load_table_exposure(self):
        rows = self.db.execute_query("SELECT port, protocol, process_name, username, binary_path FROM exposed_services")
        self.exposure_model.setRowCount(0)
        for row in rows:
            self.exposure_model.appendRow([QStandardItem(str(f)) for f in row])
        self.lbl_kpi_services.setText(f"Exposed Services: {len(rows)}")
        
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
        self.lbl_kpi_conns.setText(f"Active Conns: {len(rows)}+" if len(rows)==200 else f"Active Conns: {len(rows)}")
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
        # Battery
        bat = self.db.execute_query("SELECT remaining_percent, status FROM telemetry_battery LIMIT 1")
        if bat:
            self.lbl_battery.setText(f"Status: {bat[0][1]} | Level: {bat[0][0]}%")
        else:
            self.lbl_battery.setText("No Battery Data")
        
        # Security
        sec_rows = self.db.execute_query("SELECT service, status, state FROM telemetry_security_center")
        self.sec_model.setRowCount(0)
        for row in sec_rows:
            self.sec_model.appendRow([QStandardItem(str(f)) for f in row])

        # Crashes
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
         if not rows:
             self.lbl_kpi_vulns.setText("High Risk Vulns: 0")
         else:
             self.lbl_kpi_vulns.setText(f"High Risk Vulns: {len(rows)}")
             
         for row in rows:
             self.vuln_model.appendRow([QStandardItem(str(f)) for f in row])

    def refresh_dashboard_data(self):
        logging.info("Refreshing Dashboard Data (UI Side)...")
        try:
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
            logging.info("UI Refresh Complete.")
        except Exception as e:
            logging.error(f"Error refreshing dashboard: {e}", exc_info=True)

    # --- AI Features ---

    def show_context_menu(self, pos, table, context_type):
        index = table.indexAt(pos)
        if not index.isValid():
            return
        
        row = index.row()
        menu = QMenu(self)
        analyze_act = QAction("✨ AI Analyze / Explain", self)
        
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
            # Model: Date, Severity, Title, Impact, CVEs. Desc hidden in UserRole of col 0
            context_data = {
                "type": "cve",
                "title": self.intel_model.item(row, 2).text(),
                "description": self.intel_model.item(row, 0).data(Qt.ItemDataRole.UserRole) or "No detailed description.",
                "severity": self.intel_model.item(row, 1).text(),
                "cve_ids": self.intel_model.item(row, 4).text()
            }
        elif context_type == "cve":
             # Model: Software, CVE ID, Desc, Score, Confidence
             context_data = {
                 "type": "cve",
                 "title": f"{self.vuln_model.item(row, 1).text()} in {self.vuln_model.item(row, 0).text()}",
                 "description": self.vuln_model.item(row, 2).text(),
                 "severity": self.vuln_model.item(row, 3).text()
             }
        
        analyze_act.triggered.connect(lambda: self.trigger_ai_analysis(context_data))
        menu.addAction(analyze_act)
        menu.exec(table.viewport().mapToGlobal(pos))

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
