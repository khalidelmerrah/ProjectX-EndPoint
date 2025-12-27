"""
MODULE: workers.py
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
This module implements the **Concurrency Layer** of the application.
In GUI programming (and specifically Qt), the Main Thread is responsible for 
rendering the UI (60 FPS). If we run heavy tasks (like scanning the disk) on 
the Main Thread, the application will "freeze" and become unresponsive.

To solve this, we use **Worker Threads** (`QThread`).

KEY CONCEPTS:
-------------
1.  **Asynchronous Execution**:
    We spawn separate system threads for long-running operations (Scanning, 
    Network Requests, AI Processing).

2.  **Signals & Slots (Observer Pattern)**:
    Threads cannot directly touch the UI (e.g., `label.setText("Done")`).
    Attempting to do so causes Race Conditions and Crashes.
    Instead, we use `pyqtSignal`. The Worker *emits* a signal (Data), and the 
    UI *receives* it (Slot) to update itself safely.

3.  **Event Loops**:
    The `FIMWorker` (File Integrity Monitor) runs an infinite loop monitoring 
    filesystem events. It is a classic "Daemon" pattern.

4.  **Graceful Termination**:
    We implement `stop()` methods to allow threads to exit cleanly when the 
    application closes, preventing "Zombie Processes".

"""

from PyQt6.QtCore import QThread, pyqtSignal, QObject
import logging
import time
import datetime
import os
import sys
from typing import List, Dict, Any

# Third-party libraries
# watchdog is used for monitoring file system events (created/modified/deleted)
# ensuring we detect malware writing payload to disk in real-time.
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Internal Modules
# We import the "Managers" (Business Logic) here. The Workers are essentially 
# "Drivers" for these Managers.
from managers import SoftwareManager, NetworkScanner, ProcessMonitor, VulnEngine, AIAssistant, CertificateManager, YaraManager, ThreatIntelManager
from db_manager import DatabaseManager

# Robust import for the backend package
try:
    from backend import advisory_feed
except ImportError:
    # If running from a different context, adjust path to find backend modules
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from backend import advisory_feed

# ------------------------------------------------------------------------------
# CLASS: ScanWorker
# ------------------------------------------------------------------------------
class ScanWorker(QThread):
    """
    The **Orchestrator Thread** for System Scans.
    
    This thread performs a linear sequence of checks (Inventory -> Network -> CVEs).
    It is designed to run ONCE (Start -> Finish) rather than loop infinitely.
    """
    
    # SIGNALS: The Interface to the UI
    finished = pyqtSignal()      # Emitted when the entire workflow is done
    progress = pyqtSignal(str)   # Text update for the LoaderScreen (e.g., "Scanning Network...")
    
    def __init__(self, scan_categories: List[str] = None, skip_cve_sync: bool = False):
        """
        Constructor.
        
        Args:
            scan_categories (list): Optional list of checks to run (e.g., ['network', 'software']).
            skip_cve_sync (bool): If True, skips the slow download of CVE definitions.
                                  Used during startup for speed.
        """
        super().__init__()
        # Resource Acquisition:
        # We instantiate managers here. Note that DatabaseManager needs to be created
        # within the thread context (or handle thread-safety) ideally, but we create it
        # here in __init__ (Main Thread) and rely on its internal handling.
        # Best Practice: Move these to `run()` to ensure thread locality.
        self.db = DatabaseManager() 
        
        # Instantiate the Managers to perform actual work
        self.inventory_mgr = SoftwareManager()
        self.network_mgr = NetworkScanner()
        self.vuln_engine = VulnEngine()
        self.cert_mgr = CertificateManager()
        
        # Store configuration flags
        self.scan_categories = scan_categories if scan_categories else ['all']
        self.skip_cve_sync = skip_cve_sync

    def is_cat(self, cat: str) -> bool:
        """Helper to check if a specific category is enabled for this run."""
        return 'all' in self.scan_categories or cat in self.scan_categories

    def _track_and_execute(self, table_name: str, category: str, operations: List[tuple], new_count: int):
        """
        Executes database transactions and logs the 'Delta' (Change).
        
        This is a rudimentary form of **State Diffing**.
        We compare the item count before and after to see if the system state changed.
        """
        # 1. Get old count (Snapshot of previous state)
        try:
            old_count = self.db.execute_query(f"SELECT count(*) FROM {table_name}")[0][0]
        except: 
            old_count = 0
        
        # 2. Execute the Transaction (Atomic Wipe & Replace)
        # We use a "Delete All + Insert All" strategy for simplicity.
        # For huge datasets, we would use UPSERT (Insert on Conflict Update).
        if self.db.execute_transaction(operations):
            # 3. Calculate Delta and Log
            delta = new_count - old_count
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Record the summary event to the Posture Log
            self.db.execute_update(
                "INSERT INTO system_posture (check_name, status, timestamp) VALUES (?, ?, ?)",
                (f"Scan_{category}", f"Completed (Items: {new_count}, Delta: {delta})", timestamp)
            )
            return True
        return False

    def run(self):
        """
        The Entry Point for the thread.
        This code runs in parallel to the Main UI Loop.
        """
        # Local variables to share data between phases
        software_found = []
        
        # -----------------------------------------------------
        # PHASE 1: CVE Database Sync (The "Update" Step)
        # -----------------------------------------------------
        # Synchronizes local definitions with NIST NVD.
        if self.is_cat('software') and not self.skip_cve_sync:
            # Graceful Degradation: Check if we even have a key before trying
            if not self.vuln_engine.api_key:
                self.progress.emit("Offline Mode: Skipping NIST CVE Sync (No Key)...")
            else:
                try:
                    self.progress.emit("Syncing CVE Database (NIST)...")
                    # This is a network-bound blocking call
                    self.vuln_engine.sync_cves() 
                    
                    # Yield control briefly (Good citizenship in threading)
                    time.sleep(0.1) 
                except Exception as e:
                    logging.error(f"CVE Sync Failed: {e}")
                    self.progress.emit("CVE Sync Failed (Skipping)...")

        # -----------------------------------------------------
        # PHASE 2: Software Inventory (The "Asset Discovery")
        # -----------------------------------------------------
        # Identifies what is installed on the machine.
        if self.is_cat('software'):
            try:
                self.progress.emit("Scanning Installed Software...")
                software_found = self.inventory_mgr.get_installed_software()
                logging.info(f"Scan Progress: Found {len(software_found)} applications.")
                
                # Construct Bulk Queries for Database Insert
                # Step A: Clear existing data (Snapshot model)
                ops = [("DELETE FROM installed_software", ())] 
                
                # Step B: Insert new data
                for sw in software_found:
                    ops.append((
                        "INSERT INTO installed_software (name, version, publisher, install_date, icon_path, latest_version, update_available) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (sw['name'], sw['version'], sw['publisher'], sw['install_date'], sw['icon_path'], sw.get('latest_version', ''), sw.get('update_available', 0))
                    ))
                # Step C: Commit Transaction
                self._track_and_execute("installed_software", "Software", ops, len(software_found))
            except Exception as e:
                logging.error(f"Software Scan Failed: {e}")
                self.progress.emit("Software Scan Error (Skipping)...")

        # -----------------------------------------------------
        # PHASE 3: Network Connections (The "Activity")
        # -----------------------------------------------------
        # Identifies active communication sockets.
        if self.is_cat('network'):
            try:
                self.progress.emit("Scanning Active Connections...")
                connections = self.network_mgr.scan_connections()
                
                # Prepare replacement transaction
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
        # PHASE 4: Network Exposure (The "Attack Surface")
        # -----------------------------------------------------
        # Identifies listening ports open to the outside.
        if self.is_cat('exposure'):
            try:
                self.progress.emit("Scanning Listening Services...")
                services = self.network_mgr.get_listening_ports()
                
                # Prepare replacement transaction
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
        # PHASE 5: Identity & Persistence (The "Foothold")
        # -----------------------------------------------------
        # Scans for malware persistence mechanisms.
        if self.is_cat('persistence'):
            try:
                self.progress.emit("Scanning Persistence Items...")
                # We reuse SoftwareManager which has the persistence logic
                startup = self.inventory_mgr.get_startup_items()
                
                # Prepare replacement transaction
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
        # PHASE 6: Vulnerability Correlation (The "Analysis")
        # -----------------------------------------------------
        # We cross-reference the software found in Phase 2 with the CVEs from Phase 1.
        if self.is_cat('software'):
            try:
                if software_found: 
                    self.progress.emit("Matching Vulnerabilities...")
                    # CPU-bound Logic: String Matching Loop
                    matches = self.vuln_engine.match_vulnerabilities(software_found)
                    
                    # Store matches in DB
                    ops = [("DELETE FROM vulnerability_matches", ())]
                    
                    # Helper: Map Software Name -> ID
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
            
        # ALL DONE
        # We emit the 'finished' signal. The UI usually reacts by switching view 
        # from LoaderScreen to Dashboard.
        self.finished.emit()

# ------------------------------------------------------------------------------
# CLASS: ProcessWorker
# ------------------------------------------------------------------------------
class ProcessWorker(QThread):
    """
    Real-time process monitor thread (Like Task Manager).
    Polls every 5 seconds.
    """
    updated = pyqtSignal(list) 
    
    def __init__(self):
        super().__init__()
        self.monitor = ProcessMonitor()
        self.running = True

    def run(self):
        """Infinite loop to poll process stats."""
        while self.running:
            try:
                data = self.monitor.get_running_processes()
                self.updated.emit(data)
            except Exception as e:
                logging.error(f"ProcessWorker Crash: {e}", exc_info=True)
            
            # We sleep in short bursts to allow for responsive 'stop()'
            # Using 50 x 0.1s sleeps means we check 'running' flag every 0.1s
            # instead of blocking for 5 seconds blindly.
            for _ in range(50): 
                if not self.running: return
                time.sleep(0.1)

    def stop(self):
        """Sets flag to exit the loop gracefully."""
        self.running = False
        self.wait() # Wait for thread to actually finish

# ------------------------------------------------------------------------------
# CLASS: AIWorker
# ------------------------------------------------------------------------------
class AIWorker(QThread):
    """
    Asynchronous worker for calling LLMs (Generative AI).
    Network Latency for AI is often 2-10 seconds, which freezes UI if synchronous.
    """
    result = pyqtSignal(str) 
    
    def __init__(self, context_data):
        super().__init__()
        self.context_data = context_data
        self.assistant = AIAssistant()

    def run(self):
        # Graceful Guard: If no key, don't even try the network
        if not self.assistant.is_active:
             self.result.emit("Feature unavailable: Gemini API key required in Settings.")
             return

        # Blocking HTTP/gRPC call handled here in background
        response = self.assistant.explain_risk(self.context_data)
        # Return result to UI via Signal
        self.result.emit(response)

# ------------------------------------------------------------------------------
# CLASS: AdvisoryWorker
# ------------------------------------------------------------------------------
class AdvisoryWorker(QThread):
    """
    Worker to fetch security advisories (RSS).
    This prevents the UI from freezing while we fetch and parse XML/HTML.
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
            # Call the crawler module
            feed = advisory_feed.fetch_advisories(limit=self.limit, start_index=self.start_index)
            
            for item in feed:
                # Store in DB
                self.db.upsert_advisory(item)
                self.progress.emit(f"Processed advisory: {item.get('title', 'Unknown')}")
            
            self.finished.emit()
        except Exception as e:
            logging.error(f"Advisory update failed: {e}")
            self.finished.emit()

# ------------------------------------------------------------------------------
# CLASS: FIMWorker
# ------------------------------------------------------------------------------
class FIMEventHandler(FileSystemEventHandler):
    """
    The interface between low-level OS events and our High-Level Logic.
    Inherits from watchdog's generic handler.
    """
    def __init__(self, signal):
        self.signal = signal

    def on_modified(self, event):
        """Triggered when file content changes."""
        if not event.is_directory:
            self._emit_alert(event.src_path, "MODIFIED", "HIGH")

    def on_created(self, event):
        """Triggered when new file appears."""
        if not event.is_directory:
            self._emit_alert(event.src_path, "CREATED", "MEDIUM")

    def on_deleted(self, event):
        """Triggered when file removes."""
        if not event.is_directory:
            self._emit_alert(event.src_path, "DELETED", "HIGH")
            
    def _emit_alert(self, path, action, severity):
        """Constructs and fires the alert dictionary."""
        data = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "file_path": path,
            "action_type": action,
            "severity": severity
        }
        self.signal.emit(data)

class FIMWorker(QThread):
    """
    Real-Time File Integrity Monitor.
    Runs a specialized Event Loop (Observer) provided by 'watchdog'.
    """
    alert = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.observer = Observer()
        self.running = True

    def run(self):
        # Paths to monitor (Honeypots + Critical Areas)
        # Windows: System32 hosts file is a prime target
        paths = [
            r"C:\Windows\System32\drivers\etc", 
            os.path.join(os.path.expanduser("~"), "Downloads") # User downloads
        ]
        
        handler = FIMEventHandler(self.alert)
        
        for path in paths:
            if os.path.exists(path):
                try:
                    # 'recursive=False' because we only care about top-level files here
                    self.observer.schedule(handler, path, recursive=False)
                    logging.info(f"FIM monitoring started for: {path}")
                except Exception as e:
                     logging.error(f"FIM failed to monitor {path}: {e}")
            else:
                logging.warning(f"FIM path not found: {path}")

        try:
            # Start the watchdog thread (nested thread)
            self.observer.start()
            
            # Keep QThread alive with a loop
            while self.running:
                time.sleep(1)
            
            # Cleanup on exit
            self.observer.stop()
            self.observer.join()
        except Exception as e:
            logging.error(f"FIM Worker crashed: {e}")

    def stop(self):
        self.running = False

# ------------------------------------------------------------------------------
# CLASS: YaraScanWorker
# ------------------------------------------------------------------------------
class YaraScanWorker(QThread):
    """
    On-Demand YARA logic.
    Walks directory trees recursively and applies regex rules.
    """
    progress = pyqtSignal(str)
    result = pyqtSignal(list)
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
                 # Recursive Directory Walk (DFS)
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
        """Helper to scan one file and append matches."""
        self.progress.emit(f"Scanning: {path}")
        matches = self.yara_mgr.scan_file(path)
        if matches:
            for m in matches:
                results.append({
                    "file": path,
                    "rule": m.rule,
                    "tags": m.tags,
                    "meta": m.meta
                })
    
    def stop(self):
        self.running = False
