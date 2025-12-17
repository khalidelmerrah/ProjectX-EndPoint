from PyQt6.QtCore import QThread, pyqtSignal, QObject
import logging
import time
import datetime
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from managers import InventoryManager, NetworkScanner, ProcessMonitor, VulnEngine, AIAssistant, CertificateManager, YaraManager, ThreatIntelManager
from db_manager import DatabaseManager
try:
    from backend import advisory_feed
except ImportError:
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from backend import advisory_feed

class WorkerSignals(QObject):
    finished = pyqtSignal()
    error = pyqtSignal(str)
    result = pyqtSignal(object)
    progress = pyqtSignal(int)

class ScanWorker(QThread):
    finished = pyqtSignal()
    progress = pyqtSignal(str)
    
    def __init__(self, scan_categories=None, skip_cve_sync=False):
        super().__init__()
        self.db = DatabaseManager()
        self.inventory_mgr = InventoryManager()
        self.network_mgr = NetworkScanner()
        self.vuln_engine = VulnEngine()
        self.cert_mgr = CertificateManager()
        # Default to 'all' if None provided
        self.scan_categories = scan_categories if scan_categories else ['all']
        self.skip_cve_sync = skip_cve_sync

    def is_cat(self, cat):
        return 'all' in self.scan_categories or cat in self.scan_categories

    def _track_and_execute(self, table_name, category, operations, new_count):
        """Helper to track changes and execute transaction."""
        # 1. Get old count
        try:
            old_count = self.db.execute_query(f"SELECT count(*) FROM {table_name}")[0][0]
        except: old_count = 0
        
        # 2. Execute
        if self.db.execute_transaction(operations):
            # 3. Calculate Delta and Log
            delta = new_count - old_count
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Log summary
            self.db.execute_update(
                "INSERT INTO scan_summaries (timestamp, category, item_count, delta_count) VALUES (?, ?, ?, ?)",
                (timestamp, category, new_count, delta)
            )
            return True
        return False

    def run(self):
        # Initialize loop-scoped variables to avoid UnboundLocalError
        software = []
        
        # 1. CVE Sync (Independent) - Usually run with software or all
        if self.is_cat('software') and not self.skip_cve_sync:
            try:
                self.progress.emit("Syncing CVE Database...")
                self.vuln_engine.sync_cves()
                time.sleep(0.1)
            except Exception as e:
                logging.error(f"CVE Sync Failed: {e}")
                self.progress.emit("CVE Sync Failed (Skipping)...")

        # 2. Software
        if self.is_cat('software'):
            try:
                self.progress.emit("Scanning Installed Software...")
                software = self.inventory_mgr.get_installed_software()
                logging.info(f"Scan Progress: Found {len(software)} applications.")
                
                ops = [("DELETE FROM installed_software", ())]
                for sw in software:
                    ops.append((
                        "INSERT INTO installed_software (name, version, publisher, install_date, icon_path, latest_version, update_available) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (sw['name'], sw['version'], sw['publisher'], sw['install_date'], sw['icon_path'], sw.get('latest_version', ''), sw.get('update_available', 0))
                    ))
                self._track_and_execute("installed_software", "Software", ops, len(software))
            except Exception as e:
                logging.error(f"Software Scan Failed: {e}")
                self.progress.emit("Software Scan Error (Skipping)...")

        # 3. Network (Connections)
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

        # 4. Exposure (Listening Services)
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

        # 5. System Services
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

        # 6. Certificates
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

        # 7. Identity (Users)
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

        # 8. Persistence (Startup Items)
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

        # --- New Phase 2 Telemetry ---
        
        # 9. Health & Crashes
        if self.is_cat('health'):
            try:
                self.progress.emit("Scanning System Crashes...")
                crashes = self.inventory_mgr.get_crashes()
                ops = [("DELETE FROM telemetry_crashes", ())]
                for x in crashes:
                    ops.append((
                        "INSERT INTO telemetry_crashes (crash_time, module, path, type) VALUES (?, ?, ?, ?)",
                        (x['crash_time'], x['module'], x['path'], x['type'])
                    ))
                self.db.execute_transaction(ops)
            except Exception as e:
                 logging.error(f"Crash Scan Failed: {e}")

            # Security Status
            try:
                self.progress.emit("Scanning Security Center...")
                sec_status = self.inventory_mgr.get_security_status()
                ops = [("DELETE FROM telemetry_security_center", ())]
                for x in sec_status:
                    ops.append((
                        "INSERT INTO telemetry_security_center (service, status, state) VALUES (?, ?, ?)",
                        (x['service'], x['status'], x['state'])
                    ))
                self.db.execute_transaction(ops)
            except Exception as e:
                 logging.error(f"Security Status Scan Failed: {e}")

        # 10. Updates
        if self.is_cat('updates'):
            try:
                self.progress.emit("Scanning Windows Updates...")
                updates = self.inventory_mgr.get_windows_updates()
                ops = [("DELETE FROM telemetry_windows_updates", ())]
                for x in updates:
                    ops.append((
                        "INSERT INTO telemetry_windows_updates (hotfix_id, description, installed_on, installed_by) VALUES (?, ?, ?, ?)",
                        (x['hotfix_id'], x['description'], x['installed_on'], x['installed_by'])
                    ))
                self.db.execute_transaction(ops)
            except Exception as e:
                 logging.error(f"Update Scan Failed: {e}")
        
        # 11. Battery
        if self.is_cat('health'):
            try:
                self.progress.emit("Scanning Battery Health...")
                batt = self.inventory_mgr.get_battery_status()
                ops = [("DELETE FROM telemetry_battery", ())]
                for x in batt:
                     ops.append((
                        "INSERT INTO telemetry_battery (cycle_count, health, status, remaining_percent) VALUES (?, ?, ?, ?)",
                        (x['cycle_count'], x['health'], x['status'], x['remaining_percent'])
                    ))
                self.db.execute_transaction(ops)
            except Exception as e:
                 logging.error(f"Battery Scan Failed: {e}")

            # Health Scorecard KPIs
            try:
                self.progress.emit("Calculating Health Scorecard...")
                
                # 1. Metadata
                meta = self.inventory_mgr.get_system_metadata()
                self.db.update_metadata("bios_date", meta.get("bios_date", ""))
                self.db.update_metadata("os_install_date", meta.get("os_install_date", ""))
                
                now = datetime.datetime.now()
                
                # 2. Hardware Age
                hw_days = -1
                if meta.get("bios_date"):
                    try:
                        bd = datetime.datetime.strptime(meta["bios_date"][:8], "%Y%m%d")
                        hw_days = (now - bd).days
                    except: pass
                self.db.update_metadata("hw_age_days", str(hw_days))
                
                # 3. OS Freshness
                os_days = -1
                if meta.get("os_install_date"):
                    try:
                        val = str(meta["os_install_date"])
                        if val.isdigit() and len(val) > 8: # Unix Timestamp
                             od = datetime.datetime.fromtimestamp(int(val))
                        else:
                             od = datetime.datetime.strptime(val[:8], "%Y%m%d")
                        os_days = (now - od).days
                    except: pass
                self.db.update_metadata("os_freshness_days", str(os_days))
                
                # 4. Vulnerability Density
                vuln_count = self.db.execute_query("SELECT count(*) FROM vulnerability_matches")[0][0]
                sw_count = self.db.execute_query("SELECT count(*) FROM installed_software")[0][0]
                vuln_density = (vuln_count / sw_count * 100) if sw_count > 0 else 0
                self.db.update_metadata("vuln_density", f"{vuln_density:.1f}")
                
                # 5. Persistence Density
                start_count = self.db.execute_query("SELECT count(*) FROM startup_items")[0][0]
                proc_count = self.db.execute_query("SELECT count(*) FROM telemetry_processes")[0][0] # Assuming populated
                # Fallback if processes not in DB (live only?) -> process worker writes to nothing? 
                # ProcessWorker emits list. Telemetry table not always populated unless full scan ran system_info phase?
                # Re-check db. 
                # Actually ScanWorker doesn't populate telemetry_processes typically, ProcessWorker does? 
                # ScanWorker has no process scan?
                # Ah, InventoryManager doesn't seem to scan processes in ScanWorker usually.
                # Use current process count from psutil if needed or check if table has data.
                # Assuming table might be empty, let's just use psutil if possible or skip. 
                # ScanWorker DOES NOT populate telemetry_processes in code shown. ProcessWorker does? 
                # ProcessWorker emits to UI. Logic for persistence density requested: "count(startup_items) / count(running_processes)"
                
                # Let's count running processes using psutil directly here for accuracy if DB is empty
                import psutil
                try:
                    p_count = len(psutil.pids())
                except: p_count = 1
                
                pers_density = (start_count / p_count * 100) if p_count > 0 else 0
                self.db.update_metadata("persistence_density", f"{pers_density:.1f}")
                
                # 6. User Stale Rate
                # users table: user_accounts (username, uid, description, last_login)
                # last_login format? often string.
                users = self.db.execute_query("SELECT last_login FROM user_accounts")
                stale_users = 0
                for u in users:
                    # Parse logic depends on OSQuery output... often textual or empty
                    pass 
                # Simplification: just count total users for now or try parse
                self.db.update_metadata("stale_user_count", "0") # Placeholder implementation
                
                # 7. Driver Compliance
                # telemetry_drivers (signed int 1/0)
                d_rows = self.db.execute_query("SELECT count(*), sum(signed) FROM telemetry_drivers")
                total_drv = d_rows[0][0]
                signed_drv = d_rows[0][1] if d_rows[0][1] else 0
                unsigned = total_drv - signed_drv
                self.db.update_metadata("unsigned_drivers", str(unsigned))
                
            except Exception as e:
                logging.error(f"Health Scorecard Calc Failed: {e}")

        # 12. Browser Extensions
        if self.is_cat('extensions'):
            try:
                self.progress.emit("Scanning Browser Extensions...")
                exts = self.inventory_mgr.get_browser_extensions()
                ops = [("DELETE FROM telemetry_browser_extensions", ())]
                for x in exts:
                    ops.append((
                        "INSERT INTO telemetry_browser_extensions (name, version, browser, identifier, status) VALUES (?, ?, ?, ?, ?)",
                        (x['name'], x['version'], x['browser'], x['identifier'], x['status'])
                    ))
                self.db.execute_transaction(ops)
            except Exception as e:
                 logging.error(f"Browser Ext Scan Failed: {e}")

        # 13. Drivers
        if self.is_cat('drivers'):
            try:
                self.progress.emit("Scanning Drivers...")
                drvs = self.inventory_mgr.get_drivers()
                ops = [("DELETE FROM telemetry_drivers", ())]
                for x in drvs:
                    ops.append((
                        "INSERT INTO telemetry_drivers (name, description, provider, status, signed) VALUES (?, ?, ?, ?, ?)",
                        (x['name'], x['description'], x['provider'], x['status'], x['signed'])
                    ))
                self.db.execute_transaction(ops)
            except Exception as e:
                 logging.error(f"Driver Scan Failed: {e}")

        # 14. Hosts File
        if self.is_cat('network') or self.is_cat('hosts'):
            try:
                self.progress.emit("Scanning Hosts File...")
                hosts = self.inventory_mgr.get_hosts_file()
                ops = [("DELETE FROM telemetry_hosts", ())]
                for x in hosts:
                    ops.append((
                        "INSERT INTO telemetry_hosts (hostnames, ip_address) VALUES (?, ?)",
                        (x['hostnames'], x['ip_address'])
                    ))
                self.db.execute_transaction(ops)
            except Exception as e:
                 logging.error(f"Hosts Scan Failed: {e}")

        # 15. Vulnerability Matches (Depends on Software)
        if self.is_cat('software'):
            try:
                if software: # only run if software scan passed
                    self.progress.emit("Matching Vulnerabilities...")
                    matches = self.vuln_engine.match_vulnerabilities(software)
                    ops = [("DELETE FROM vulnerability_matches", ())]
                    
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
            
        self.finished.emit()

class ProcessWorker(QThread):
    updated = pyqtSignal(list)
    
    def __init__(self):
        super().__init__()
        self.monitor = ProcessMonitor()
        self.running = True

    def run(self):
        while self.running:
            try:
                data = self.monitor.get_running_processes()
                self.updated.emit(data)
            except Exception as e:
                logging.error(f"ProcessWorker Crash: {e}", exc_info=True)
            
            time.sleep(5) 

    def stop(self):
        self.running = False
        self.wait()

class AIWorker(QThread):
    result = pyqtSignal(str)
    
    def __init__(self, context_data):
        super().__init__()
        self.context_data = context_data
        self.assistant = AIAssistant()

    def run(self):
        response = self.assistant.explain_risk(self.context_data)
        self.result.emit(response)

class AdvisoryWorker(QThread):
    finished = pyqtSignal()
    progress = pyqtSignal(str)
    
    def __init__(self, start_index=0, limit=50):
        super().__init__()
        self.db = DatabaseManager()
        self.start_index = start_index
        self.limit = limit

    def run(self):
        try:
            feed = advisory_feed.fetch_advisories(limit=self.limit, start_index=self.start_index)
            for item in feed:
                # Upsert into DB
                self.db.upsert_advisory(item)
                self.progress.emit(f"Processed advisory: {item.get('title', 'Unknown')}")
            
            self.finished.emit()
        except Exception as e:
            logging.error(f"Advisory update failed: {e}")
            self.finished.emit()

class FIMEventHandler(FileSystemEventHandler):
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
    alert = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.observer = Observer()
        self.running = True

    def run(self):
        # paths to monitor
        paths = [
            r"C:\Windows\System32\drivers\etc",
            os.path.join(os.path.expanduser("~"), "Downloads")
        ]
        
        handler = FIMEventHandler(self.alert)
        
        for path in paths:
            if os.path.exists(path):
                try:
                    self.observer.schedule(handler, path, recursive=False)
                    logging.info(f"FIM monitoring started for: {path}")
                except Exception as e:
                     logging.error(f"FIM failed to monitor {path}: {e}")
            else:
                logging.warning(f"FIM path not found: {path}")

        try:
            self.observer.start()
            # Keep thread alive
            while self.running:
                time.sleep(1)
            self.observer.stop()
            self.observer.join()
        except Exception as e:
            logging.error(f"FIM Worker crashed: {e}")

    def stop(self):
        self.running = False

class YaraScanWorker(QThread):
    progress = pyqtSignal(str)
    result = pyqtSignal(list) # List of matches: {'file': path, 'rule': name, 'meta': ...}
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
                results.append({
                    "file": path,
                    "rule": m.rule,
                    "tags": m.tags,
                    "meta": m.meta
                })
    
    def stop(self):
        self.running = False

class ReputationWorker(QThread):
    finished = pyqtSignal(dict) # {result: "Clean", stats: {}, error: ""}

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path
        self.ti_mgr = ThreatIntelManager()

    def run(self):
        result = {}
        try:
            logging.info(f"Checking reputation for {self.file_path}...")
            vt_res = self.ti_mgr.check_virustotal(self.file_path)
            result = {"file": self.file_path, "vt": vt_res}
            if "hash" in vt_res:
                result["hash"] = vt_res["hash"]
        except Exception as e:
            result = {"error": str(e)}
        
        self.finished.emit(result)
