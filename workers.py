from PyQt6.QtCore import QThread, pyqtSignal, QObject
import logging
import time
from managers import InventoryManager, NetworkScanner, ProcessMonitor, VulnEngine, AIAssistant, CertificateManager
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
    
    def __init__(self, scan_categories=None):
        super().__init__()
        self.db = DatabaseManager()
        self.inventory_mgr = InventoryManager()
        self.network_mgr = NetworkScanner()
        self.vuln_engine = VulnEngine()
        self.cert_mgr = CertificateManager()
        # Default to 'all' if None provided
        self.scan_categories = scan_categories if scan_categories else ['all']

    def is_cat(self, cat):
        return 'all' in self.scan_categories or cat in self.scan_categories

    def run(self):
        # Initialize loop-scoped variables to avoid UnboundLocalError
        software = []
        
        # 1. CVE Sync (Independent) - Usually run with software or all
        if self.is_cat('software'):
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
                self.db.execute_transaction(ops)
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
                self.db.execute_transaction(ops)
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
                self.db.execute_transaction(ops)
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
                self.db.execute_transaction(ops)
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
                self.db.execute_transaction(ops)
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
                self.db.execute_transaction(ops)
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
                self.db.execute_transaction(ops)
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
                        sw_name = m['software']
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
    
    def __init__(self):
        super().__init__()
        self.db = DatabaseManager()

    def run(self):
        try:
            self.progress.emit("Fetching Threat Intelligence Feed...")
            advisories = advisory_feed.fetch_advisories()
            
            self.progress.emit(f"Saving {len(advisories)} advisories...")
            count = 0
            for adv in advisories:
                if self.db.upsert_advisory(adv):
                    count += 1
            
            self.progress.emit(f"Saved {count} advisories.")
        except Exception as e:
            self.progress.emit(f"Feed Error: {e}")
        finally:
            self.finished.emit()
