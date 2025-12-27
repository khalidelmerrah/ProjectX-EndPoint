"""
MODULE: workers.py
ProjectX Concurrency Layer - Background Thread Management

PURPOSE:
This module defines "Worker Threads" that handle long-running operations.
In a specific GUI application (like PyQt), you cannot run heavy tasks (scanning files, network requests)
on the "Main Thread" (the UI thread). If you do, the window freezes and becomes unresponsive.
Instead, we spawn separate threads (`QThread`) to do the work and communicate back via "Signals".

ARCHITECTURAL ROLE:
-------------------
[UI (Main Thread)] <----(Signals)---- [Workers (Bg Threads)] ----> [Managers/DB]

The UI *starts* a worker. The worker does the heavy lifting using Managers.
When done (or during progress), the worker *emits* a signal. The UI *receives* this signal
and updates the display (e.g., increments a progress bar).

SECURITY THEORY:
----------------
1.  **Isolation**: By separating scanning logic from the UI, we ensure that a crash in a 
    parsing engine (like YARA) might kill the thread but often spares the main application,
    allowing for graceful error reporting.
2.  **Responsiveness as a Security Feature**: A frozen security tool provides no info.
    Threading ensures the "Stop Scan" button actually works when needed.

DEPENDENCIES:
-------------
- PyQt6 (QThread, pyqtSignal, QObject): The core threading primitives.
- time, datetime: For timestamps and delays.
- watchdog: For File Integrity Monitoring (FIM).
- managers: The business logic classes that these workers execute.
- db_manager: To write results to the database safely.

AUTHOR: ProjectX Team
DATE: 2025-12-27
"""

from PyQt6.QtCore import QThread, pyqtSignal, QObject
import logging
import time
import datetime
import os
import sys

# Third-party libraries
# watchdog is used for monitoring file system events (created/modified/deleted)
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Internal Modules
from managers import InventoryManager, NetworkScanner, ProcessMonitor, VulnEngine, AIAssistant, CertificateManager, YaraManager, ThreatIntelManager
from db_manager import DatabaseManager

# Robust import for the backend package
try:
    from backend import advisory_feed
except ImportError:
    # If running from a different context, adjust path to find backend modules
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from backend import advisory_feed

# ---------------------------------------------------------
# SIGNAL DEFINITIONS (Interface)
# ---------------------------------------------------------

class WorkerSignals(QObject):
    """
    Defines the standard signals that workers can emit.
    
    Why a separate class? 
    It helps standardize the interface. All workers should ideally use these 
    rather than defining ad-hoc signals, though QThread subclasses often define their own for convenience.
    """
    finished = pyqtSignal()      # Emitted when task is done
    error = pyqtSignal(str)      # Emitted on failure with error message
    result = pyqtSignal(object)  # Emitted with data payload (dict, list, etc.)
    progress = pyqtSignal(int)   # Emitted with percentage (0-100)

# ---------------------------------------------------------
# WORKER CLASSES
# ---------------------------------------------------------

class ScanWorker(QThread):
    """
    The Heavy Lifter: Performs system-wide integrity and inventory scans.
    
    This thread coordinates multiple managers (Inventory, Network, etc.) in a serial fashion 
    to gather a complete snapshot of the system state.
    """
    # Signals
    finished = pyqtSignal()      # Task complete
    progress = pyqtSignal(str)   # Text update for the LoaderScreen (e.g., "Scanning Network...")
    
    def __init__(self, scan_categories=None, skip_cve_sync=False):
        """
        Args:
            scan_categories (list): Optional list of checks to run (e.g., ['network', 'software']).
            skip_cve_sync (bool): If True, skips the slow download of CVE definitions.
        """
        super().__init__()
        # We instantiate managers *inside* the thread or just before.
        # Note: DatabaseManager handles its own connection per thread.
        self.db = DatabaseManager()
        self.inventory_mgr = InventoryManager()
        self.network_mgr = NetworkScanner()
        self.vuln_engine = VulnEngine()
        self.cert_mgr = CertificateManager()
        
        # Default to 'all' categories if nothing specified
        self.scan_categories = scan_categories if scan_categories else ['all']
        self.skip_cve_sync = skip_cve_sync

    def is_cat(self, cat):
        """Helper to check if a category is enabled."""
        return 'all' in self.scan_categories or cat in self.scan_categories

    def _track_and_execute(self, table_name, category, operations, new_count):
        """
        Helper method to execute database transactions and log the 'Delta'.
        
        It calculates how many items were added/removed compared to the previous scan
        and logs a summary. This is useful for "Diffing" system state.
        
        Args:
            table_name (str): DB table being updated.
            category (str): Human readable name.
            operations (list): List of SQL queries.
            new_count (int): How many items we found in this scan.
        """
        # 1. Get old count (Current state in DB)
        try:
            old_count = self.db.execute_query(f"SELECT count(*) FROM {table_name}")[0][0]
        except: 
            old_count = 0
        
        # 2. Execute the Transaction (Atomic Flush & Replace)
        if self.db.execute_transaction(operations):
            # 3. Calculate Change (Delta)
            delta = new_count - old_count
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Log summary for history/analytics
            # Note: valid SQL queries usually belong in db_manager, but simple inserts here are acceptable.
            # ideally, we would call self.db.log_summary(...)
            self.db.execute_update(
                "INSERT INTO scan_summaries (timestamp, category, item_count, delta_count) VALUES (?, ?, ?, ?)",
                (timestamp, category, new_count, delta)
            )
            return True
        return False

    def run(self):
        """
        The main execution method required by QThread.
        Code here runs in the separate thread.
        """
        # Initialize loop-scoped variables to avoid 'UnboundLocalError' if exception occurs before assignment
        software = []
        
        # -----------------------------------------------------
        # PHASE 1: CVE Database Sync
        # -----------------------------------------------------
        if self.is_cat('software') and not self.skip_cve_sync:
            try:
                self.progress.emit("Syncing CVE Database...")
                self.vuln_engine.sync_cves() # Downloads large JSON files from NIST/Mitre
                time.sleep(0.1) # Tiny yield to let UI process events if needed
            except Exception as e:
                logging.error(f"CVE Sync Failed: {e}")
                self.progress.emit("CVE Sync Failed (Skipping)...")

        # -----------------------------------------------------
        # PHASE 2: Software Inventory
        # -----------------------------------------------------
        if self.is_cat('software'):
            try:
                self.progress.emit("Scanning Installed Software...")
                software = self.inventory_mgr.get_installed_software()
                logging.info(f"Scan Progress: Found {len(software)} applications.")
                
                # Prepare Bulk Insert
                # Strategy: DELETE ALL -> INSERT ALL (Full Refresh)
                # This is simpler than computing individual diffs for rows.
                ops = [("DELETE FROM installed_software", ())] # Wipe table
                for sw in software:
                    ops.append((
                        "INSERT INTO installed_software (name, version, publisher, install_date, icon_path, latest_version, update_available) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (sw['name'], sw['version'], sw['publisher'], sw['install_date'], sw['icon_path'], sw.get('latest_version', ''), sw.get('update_available', 0))
                    ))
                self._track_and_execute("installed_software", "Software", ops, len(software))
            except Exception as e:
                logging.error(f"Software Scan Failed: {e}")
                self.progress.emit("Software Scan Error (Skipping)...")

        # -----------------------------------------------------
        # PHASE 3: Network Connections (Active)
        # -----------------------------------------------------
        if self.is_cat('network'):
            try:
                self.progress.emit("Scanning Active Connections...")
                connections = self.network_mgr.scan_connections()
                ops = [("DELETE FROM telemetry_network", ())]
                for c in connections:
                     ops.append((
                        "INSERT INTO telemetry_network (pid, local_addr, remote_addr, state, protocol) VALUES (?, ?, ?, ?, ?)",
                        (c['pid'], c['local_addr'], c['remote_addr'], c['state'], c['protocol'])
                    ))
                self._track_and_execute("telemetry_network", "Network", ops, len(connections))
            except Exception as e:
                logging.error(f"Network Scan Failed: {e}")

        # -----------------------------------------------------
        # PHASE 4: Network Exposure (Listening Ports)
        # -----------------------------------------------------
        if self.is_cat('exposure'):
            try:
                self.progress.emit("Scanning Listening Services...")
                services = self.network_mgr.get_listening_ports()
                ops = [("DELETE FROM exposed_services", ())]
                for svc in services:
                    ops.append((
                        "INSERT INTO exposed_services (port, protocol, process_name, binary_path, pid, username, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (svc['port'], svc['protocol'], svc['process_name'], svc['binary_path'], svc['pid'], svc['username'], svc['risk_score'])
                    ))
                self._track_and_execute("exposed_services", "Exposure", ops, len(services))
            except Exception as e:
                logging.error(f"Services Scan Failed: {e}")

        # -----------------------------------------------------
        # PHASE 5: System Services (Daemons)
        # -----------------------------------------------------
        if self.is_cat('services'):
            try:
                self.progress.emit("Scanning System Services...")
                sys_services = self.inventory_mgr.get_services()
                ops = [("DELETE FROM system_services", ())]
                for ss in sys_services:
                    ops.append((
                        "INSERT INTO system_services (name, display_name, status, start_mode) VALUES (?, ?, ?, ?)",
                        (ss['name'], ss['display_name'], ss['status'], ss['start_mode'])
                    ))
                self._track_and_execute("system_services", "System Services", ops, len(sys_services))
            except Exception as e:
                  logging.error(f"System Services Scan Failed: {e}")

        # -----------------------------------------------------
        # PHASE 6: Certificates (Trust Store)
        # -----------------------------------------------------
        if self.is_cat('certificates'):
            try:
                self.progress.emit("Scanning Certificates...")
                certs = self.cert_mgr.get_certificates()
                ops = [("DELETE FROM certificates", ())]
                for c in certs:
                    ops.append((
                        "INSERT INTO certificates (subject, issuer, expiry_date, is_root) VALUES (?, ?, ?, ?)",
                        (c['subject'], c['issuer'], c['expiry'], c['is_root'])
                    ))
                self._track_and_execute("certificates", "Certificates", ops, len(certs))
            except Exception as e:
                 logging.error(f"Certificate Scan Failed: {e}")

        # -----------------------------------------------------
        # PHASE 7: Identity (User Accounts)
        # -----------------------------------------------------
        if self.is_cat('identity'):
            try:
                self.progress.emit("Scanning Identity & Users...")
                users = self.inventory_mgr.get_users()
                ops = [("DELETE FROM user_accounts", ())]
                for u in users:
                    ops.append((
                        "INSERT INTO user_accounts (username, uid, description, last_login) VALUES (?, ?, ?, ?)",
                        (u['username'], str(u['uid']), u['description'], u['last_login'])
                    ))
                self._track_and_execute("user_accounts", "Identity", ops, len(users))
            except Exception as e:
                 logging.error(f"User Scan Failed: {e}")

        # -----------------------------------------------------
        # PHASE 8: Persistence (Startup Items)
        # -----------------------------------------------------
        if self.is_cat('persistence'):
            try:
                self.progress.emit("Scanning Persistence Items...")
                startup = self.inventory_mgr.get_startup_items()
                ops = [("DELETE FROM startup_items", ())]
                for s in startup:
                    ops.append((
                        "INSERT INTO startup_items (name, path, location, args, type, source, status, username) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (s['name'], s['path'], s['location'], s.get('args',''), s.get('type',''), s.get('source',''), s.get('status',''), s.get('username',''))
                    ))
                self._track_and_execute("startup_items", "Persistence", ops, len(startup))
            except Exception as e:
                 logging.error(f"Startup Scan Failed: {e}")

        # -----------------------------------------------------
        # PHASE 9: Vulnerability Correlation
        # -----------------------------------------------------
        # Matches found software against the now-synced CVE database.
        if self.is_cat('software'):
            try:
                if software: # only run if software scan passed and found items
                    self.progress.emit("Matching Vulnerabilities...")
                    matches = self.vuln_engine.match_vulnerabilities(software)
                    
                    # Store matches in DB
                    ops = [("DELETE FROM vulnerability_matches", ())]
                    
                    # Create Map: Software Name -> Software ID (Foreign Key)
                    sw_map = {}
                    rows = self.db.execute_query("SELECT id, name FROM installed_software")
                    for r in rows:
                        sw_map[r[1]] = r[0] 
                    
                    match_count = 0
                    for m in matches:
                        sw_name = m['name']
                        sw_id = sw_map.get(sw_name)
                        if sw_id:
                            ops.append((
                                "INSERT INTO vulnerability_matches (software_id, cve_id, confidence, status) VALUES (?, ?, ?, ?)",
                                (sw_id, m['cve_id'], m['confidence'], 'Detected')
                            ))
                            match_count += 1
                    self.db.execute_transaction(ops)
                    self.progress.emit(f"Scan Complete. Found {match_count} vulnerabilities.")
                else:
                    self.progress.emit("Skipping Vulnerability Match (No Software Data)")
            except Exception as e:
                 logging.error(f"Vulnerability Match Failed: {e}")
            
        # Signal that the entire scan workflow is done
        self.finished.emit()

class ProcessWorker(QThread):
    """
    Real-time process monitor thread.
    
    Continuously polls the list of running processes (psutil) and emits updates.
    This allows the "Processes" tab to update live, like Task Manager.
    """
    updated = pyqtSignal(list) # Emits list of process dictionaries
    
    def __init__(self):
        super().__init__()
        self.monitor = ProcessMonitor()
        self.running = True

    def run(self):
        """Infinite loop polling every 5 seconds."""
        while self.running:
            try:
                data = self.monitor.get_running_processes()
                self.updated.emit(data)
            except Exception as e:
                logging.error(f"ProcessWorker Crash: {e}", exc_info=True)
            
            # Blocking Sleep is fine here because we are in a background thread
            time.sleep(5) 

    def stop(self):
        """Standard method to stop the loop cleanly."""
        self.running = False
        self.wait() # Wait for thread to finish current iteration

class AIWorker(QThread):
    """
    Asynchronous worker for querying the Gemini AI API.
    
    Network calls to LLMs can take 2-10 seconds. This thread prevents
    the UI from "hanging" while waiting for the explanation.
    """
    result = pyqtSignal(str) # Emits the Markdown explanation
    
    def __init__(self, context_data):
        super().__init__()
        self.context_data = context_data
        self.assistant = AIAssistant()

    def run(self):
        # The blocking API call happens here
        response = self.assistant.explain_risk(self.context_data)
        self.result.emit(response)

class AdvisoryWorker(QThread):
    """
    Worker to fetch security advisories from external feeds (RSS/XML).
    
    Runs periodically or on-demand to keep the 'Advisories' tab fresh.
    """
    finished = pyqtSignal()
    progress = pyqtSignal(str)
    
    def __init__(self, start_index=0, limit=50):
        super().__init__()
        self.db = DatabaseManager()
        self.start_index = start_index
        self.limit = limit

    def run(self):
        try:
            # Calls the crawler logic we defined in backend/advisory_feed.py
            feed = advisory_feed.fetch_advisories(limit=self.limit, start_index=self.start_index)
            for item in feed:
                # Insert or Update into DB
                self.db.upsert_advisory(item)
                self.progress.emit(f"Processed advisory: {item.get('title', 'Unknown')}")
            
            self.finished.emit()
        except Exception as e:
            logging.error(f"Advisory update failed: {e}")
            self.finished.emit()

# ---------------------------------------------------------
# FILE INTEGRITY MONITORING (FIM)
# ---------------------------------------------------------

class FIMEventHandler(FileSystemEventHandler):
    """
    Watchdog Event Handler.
    This class receives low-level OS file system events and converts them to PyQt signals.
    """
    def __init__(self, signal):
        self.signal = signal

    def on_modified(self, event):
        if not event.is_directory:
            self._emit_alert(event.src_path, "MODIFIED", "HIGH")

    def on_created(self, event):
        if not event.is_directory:
            self._emit_alert(event.src_path, "CREATED", "MEDIUM")

    def on_deleted(self, event):
        if not event.is_directory:
            self._emit_alert(event.src_path, "DELETED", "HIGH")
            
    def _emit_alert(self, path, action, severity):
        data = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "file_path": path,
            "action_type": action,
            "severity": severity
        }
        self.signal.emit(data)

class FIMWorker(QThread):
    """
    File Integrity Monitoring (FIM) Worker.
    
    Uses the `watchdog` library to listen for filesystem changes (edits/deletes)
    in critical directories (like Drivers or Downloads) and emits real-time alerts.
    """
    # Emits a dict whenever a file is touched
    alert = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.observer = Observer() # The Watchdog Observer
        self.running = True

    def run(self):
        # Paths to monitor (hardcoded for demo, normally config-driven)
        paths = [
            r"C:\Windows\System32\drivers\etc", # Hosts file location
            os.path.join(os.path.expanduser("~"), "Downloads") # User downloads (Malware entry point)
        ]
        
        handler = FIMEventHandler(self.alert)
        
        for path in paths:
            if os.path.exists(path):
                try:
                    # schedule(handler, path, recursive=False)
                    self.observer.schedule(handler, path, recursive=False)
                    logging.info(f"FIM monitoring started for: {path}")
                except Exception as e:
                     logging.error(f"FIM failed to monitor {path}: {e}")
            else:
                logging.warning(f"FIM path not found: {path}")

        try:
            self.observer.start()
            # Loop to keep the thread alive until stopped
            while self.running:
                time.sleep(1)
            self.observer.stop()
            self.observer.join()
        except Exception as e:
            logging.error(f"FIM Worker crashed: {e}")

    def stop(self):
        self.running = False

class YaraScanWorker(QThread):
    """
    Worker for executing YARA rules against a file or directory.
    
    YARA scanning is computationally expensive (regex matching on binary files).
    It recursively walks directories and scans each file.
    """
    progress = pyqtSignal(str)
    result = pyqtSignal(list) # Matches found
    finished = pyqtSignal()

    def __init__(self, scan_path):
        super().__init__()
        self.scan_path = scan_path
        self.running = True
        self.yara_mgr = YaraManager()

    def run(self):
        results = []
        try:
            if os.path.isfile(self.scan_path):
                 self.scan_single_file(self.scan_path, results)
            else:
                 # Recursive Directory Walk
                 for root, dirs, files in os.walk(self.scan_path):
                     if not self.running: break
                     for file in files:
                         if not self.running: break
                         path = os.path.join(root, file)
                         self.scan_single_file(path, results)
        except Exception as e:
            logging.error(f"Yara Scan Error: {e}")
        
        self.result.emit(results)
        self.finished.emit()

    def scan_single_file(self, path, results):
        self.progress.emit(f"Scanning: {path}")
        matches = self.yara_mgr.scan_file(path)
        if matches:
            for m in matches:
                # Convert YARA match object to simpler dict
                results.append({
                    "file": path,
                    "rule": m.rule,
                    "tags": m.tags,
                    "meta": m.meta
                })
    
    def stop(self):
        self.running = False

class ReputationWorker(QThread):
    """
    Worker to check file reputation on VirusTotal.
    """
    finished = pyqtSignal(dict) # {result: "Clean", stats: {}, error: ""}

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path
        self.ti_mgr = ThreatIntelManager()

    def run(self):
        result = {}
        try:
            logging.info(f"Checking reputation for {self.file_path}...")
            # Query VT (Network Call)
            vt_res = self.ti_mgr.check_virustotal(self.file_path)
            
            result = {"file": self.file_path, "vt": vt_res}
            if "hash" in vt_res:
                result["hash"] = vt_res["hash"]
        except Exception as e:
            result = {"error": str(e)}
        
        self.finished.emit(result)
