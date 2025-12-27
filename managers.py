"""
MODULE: managers.py
ProjectX Business Logic Layer

PURPOSE:
This module contains the core "brain" of the application. It abstracts away 
low-level OS interactions into high-level Python classes.
It handles:
1.  **Configuration**: Securely loading API keys using the OS Keychain.
2.  **Inventory**: querying OSQuery, WMI, or Registry to find installed apps.
3.  **Network**: Scanning active ports and connections.
4.  **Vulnerability**: Matching software versions against the NVD CVE database.
5.  **Intelligence**: Checking file hashes against VirusTotal.
6.  **AI**: Interfacing with Gemini for natural language explanations.

ARCHITECTURAL ROLE:
-------------------
[Workers] --> [Managers] --> [Operating System / APIs]

Workers (running in threads) instantiate these Managers to perform tasks.
This separation allows us to test "Business Logic" independently of "Threading Logic" or "UI Logic".

SECURITY THEORY:
----------------
1.  **Least Privilege**: We try to use the least invasive method first (e.g., parsing a safe registry key)
    before trying to spawn a sub-shell or run a binary as admin.
2.  **Credential Safety**: We use `keyring` to store API keys. Storing secrets in plain text files 
    (like .env or config.json) is a major security anti-pattern because malware often scrapes them.
    The OS Keychain (Windows Credential Locker) is encrypted by the user's login password.

DEPENDENCIES:
-------------
- osquery: A tool that exposes the OS as a relational database.
- wmi: Windows Management Instrumentation (legacy but powerful).
- winreg: Windows Registry access.
- psutil: Cross-platform process and system monitoring.
- keyring: Secure password storage.
- requests: For API calls (NIST, VirusTotal, Gemini).

AUTHOR: ProjectX Team
DATE: 2025-12-27
"""

import platform     # OS Detection
import subprocess   # To run external binaries (osqueryi)
import socket       # Network primitives
import logging      # Error logging
import psutil       # System Monitoring
from typing import List, Dict, Any, Optional
import datetime     # Timestamps
import os           # File system
import requests     # HTTP Client
import sys          # System info
import json         # parsing osquery JSON output
import hashlib      # For calculating file SHA256 hashes

# ---------------------------------------------------------
# OPTIONAL IMPORTS (Hardware Specific)
# ---------------------------------------------------------

# WMI is Windows-only. We Wrap it in a try-block so the code doesn't crash on Linux/Mac.
try:
    import wmi
except ImportError:
    wmi = None

# Secure Credential Storage
import keyring

# YARA is an optional dependency for rule compilation
try:
    import yara
except ImportError:
    yara = None


# ---------------------------------------------------------
# CONFIGURATION MANAGER
# ---------------------------------------------------------

class ConfigManager:
    """
    Manages application configuration and secure credential storage.
    
    Pedagogical Note:
    Hardcoding API keys is bad. Storing them in 'config.json' is better, but still risky
    (malware reads files). Using the OS Keychain (`keyring` library) is the Best Practice.
    It delegates encryption to the Operating System.
    """
    SERVICE_ID = "ProjectX_Desktop"
    KEYS = ["nist_api_key", "gemini_api_key", "vt_api_key", "safe_mode"]

    @staticmethod
    def load_config() -> Dict[str, str]:
        """
        Loads API keys from the secure credential store.
        Returns:
            dict: { 'nist_api_key': '...', ... }
        """
        config = {}
        for key in ConfigManager.KEYS:
            try:
                # get_password(service, username) -> returns password string or None
                val = keyring.get_password(ConfigManager.SERVICE_ID, key)
                config[key] = val if val else ""
            except Exception as e:
                logging.error(f"Keyring load error for {key}: {e}")
                config[key] = ""
        return config

    @staticmethod
    def save_config(data: Dict[str, str]):
        """
        Saves API keys to the secure credential store.
        """
        for key in ConfigManager.KEYS:
            if key in data:
                try:
                    keyring.set_password(ConfigManager.SERVICE_ID, key, data[key])
                except Exception as e:
                    logging.error(f"Keyring save error for {key}: {e}")

# ---------------------------------------------------------
# OSQUERY WRAPPER
# ---------------------------------------------------------

class OSQueryClient:
    """
    Wrapper for interacting with the 'osqueryi' binary.
    
    What is OSQuery?
    It is a tool created by Facebook that allows you to treat the Operating System 
    as a relational database. You can run SQL queries like:
    `SELECT * FROM active_processes WHERE name = 'malware.exe'`
    This is much easier and safer than writing complex C++ or parsing raw system files.
    """
    def __init__(self):
        self.available = False
        self.binary_path = "osqueryi"
        
        # Strategy: Find the binary
        # 1. Check Bundled Path (if packaged with PyInstaller)
        # 2. Check Local 'bin' folder (for dev)
        # 3. Check System PATH (if installed globally)
        
        # getattr(sys, '_MEIPASS', ...) handles PyInstaller's temporary temp folder extraction
        base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
        
        bundled_paths = [
            os.path.join(base_path, 'bin', 'osqueryi.exe'),
            os.path.join(base_path, '..', 'bin', 'osqueryi.exe'),
            os.path.join(os.getcwd(), 'bin', 'osqueryi.exe')
        ]
        
        for p in bundled_paths:
            if os.path.exists(p):
                self.binary_path = p
                self.available = True
                logging.info(f"OSQuery found (Bundled) at {p}")
                return # Stop searching
        
        # Fallback: Check System PATH
        try:
            # subprocess.CREATE_NO_WINDOW hides the black command prompt window on Windows
            creation_flags = subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0
            
            # Just run version check to see if it exists
            subprocess.run(["osqueryi", "--version"], capture_output=True, creationflags=creation_flags)
            self.binary_path = "osqueryi"
            self.available = True
            logging.info("OSQuery found in PATH.")
            return
        except FileNotFoundError:
            pass

        # Fallback: Hardcoded common paths
        possible_paths = [
            r"C:\Program Files\osquery\osqueryi.exe",
            r"C:\Program Files\Facebook\osquery\osqueryi.exe"
        ]
        for p in possible_paths:
            if os.path.exists(p):
                self.binary_path = p
                self.available = True
                logging.info(f"OSQuery found via fallback at {p}")
                return
        
        if not self.available:
            logging.warning("osqueryi binary not found. Functionality will be degraded (using Fallbacks).")

    def query(self, sql: str) -> List[Dict]:
        """
        Executes a raw SQL query against the OS.
        Args:
            sql (str): standard SQL (e.g., 'SELECT * FROM users')
        Returns:
            list: List of dictionaries (rows)
        """
        if not self.available:
            return []
        try:
            # We call the binary with '--json' flag to get parsed output
            cmd = [self.binary_path, "--json", sql]
            
            creation_flags = subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                encoding='utf-8',
                creationflags=creation_flags,
                timeout=10 # Security: Don't let a query hang forever
            )
            
            if result.returncode == 0:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    return []
            else:
                logging.error(f"OSQuery Error ({result.returncode}): {result.stderr}")
                return []
        except Exception as e:
            logging.error(f"OSQuery Execution Exception: {e}")
            return []

# Instantiate a global shared client
osq_client = OSQueryClient()

# ---------------------------------------------------------
# SYSTEM INVENTORY MANAGER
# ---------------------------------------------------------

class InventoryManager:
    """
    The 'Collector'. Aggregates data from multiple sources.
    
    Pattern: Chain of Responsibility / Fallback
    It tries the best source (OSQuery) first. If that fails or is missing,
    it falls back to native Python libraries (psutil, winreg, WMI).
    """
    
    def get_installed_software(self) -> List[Dict[str, Any]]:
        """
        Returns a list of installed applications.
        Critical for Vulnerability Management (knowing what you have).
        """
        software_list = []
        
        # METHOD A: OSQuery (Fastest & Cleanest)
        if osq_client.available:
            logging.info("Using OSQuery (Direct) for Software Inventory...")
            data = osq_client.query("SELECT name, version, publisher, install_date FROM programs")
            for p in data:
                software_list.append({
                    'name': p.get('name', 'Unknown'),
                    'version': p.get('version') or "0.0",
                    'publisher': p.get('publisher') or "Unknown",
                    'install_date': p.get('install_date') or "",
                    'icon_path': "",
                    'latest_version': p.get('version') or "0.0",
                    'update_available': 0
                })
            
            if software_list:
                return software_list
            else:
                logging.warning("OSQuery returned 0 apps. Falling back to Registry...")

        # METHOD B: Windows Registry (The "Old School" way)
        # Windows stores uninstall info in specific Registry keys.
        try:
            import winreg
            logging.info("Scanning Windows Registry for Software...")
            
            def get_val(key, name):
                """Helper to safely read a registry string value."""
                try:
                    return winreg.QueryValueEx(key, name)[0]
                except FileNotFoundError:
                    return ""

            # The 3 locations where software usually registers itself
            registry_paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"), # 32-bit apps on 64-bit OS
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall") # Per-user apps
            ]
            
            seen_names = set() # Dedup set

            for root, path in registry_paths:
                try:
                    with winreg.OpenKey(root, path) as key:
                        # Iterate subkeys (folders)
                        for i in range(winreg.QueryInfoKey(key)[0]):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                with winreg.OpenKey(key, f"{path}\\{subkey_name}") as subkey:
                                    name = get_val(subkey, "DisplayName")
                                    # Filter out garbage entries
                                    if not name or name in seen_names: 
                                        continue
                                    
                                    version = get_val(subkey, "DisplayVersion") or "Unknown"
                                    publisher = get_val(subkey, "Publisher") or "Unknown"
                                    install_date = get_val(subkey, "InstallDate") or "" 
                                    
                                    seen_names.add(name)
                                    software_list.append({
                                        'name': name,
                                        'version': version,
                                        'publisher': publisher,
                                        'install_date': install_date,
                                        'icon_path': "",
                                        'latest_version': version, 
                                        'update_available': 0
                                    })
                            except Exception:
                                continue
                except Exception:
                    continue
            
            if software_list:
                logging.info(f"Registry Scan found {len(software_list)} apps.")
                return software_list

        except Exception as e:
            logging.error(f"Registry Scan Error: {e}")

        # METHOD C: WMI (Last Resort - Very Slow)
        if wmi:
            try:
                logging.info("Falling back to WMI for Software Inventory...")
                c = wmi.WMI()
                # Win32_Product is notorious for being slow and triggering MSI consistency checks
                for product in c.Win32_Product(['Name', 'Version', 'Vendor', 'InstallDate']):
                    software_list.append({
                        'name': product.Name,
                        'version': product.Version or "Unknown",
                        'publisher': product.Vendor or "Unknown",
                        'install_date': product.InstallDate or datetime.date.today().strftime("%Y%m%d"),
                        'icon_path': "",
                        'latest_version': product.Version,
                        'update_available': 0
                    })
            except Exception as e:
                logging.error(f"WMI Error: {e}")
        
        return software_list

    def get_startup_items(self) -> List[Dict[str, Any]]:
        """
        Scans for Persistence Mechanisms (Autoruns).
        Malware usually places itself here to survive reboots.
        """
        items = []
        if osq_client.available:
            data = osq_client.query("SELECT name, path, args, type, source, status, username FROM startup_items")
            for i in data:
                items.append({
                    'name': i.get('name', 'Unknown'),
                    'path': i.get('path', ''),
                    'location': i.get('source', ''),
                    'args': i.get('args', ''),
                    'type': i.get('type', ''),
                    'source': i.get('source', ''),
                    'status': i.get('status', 'enabled'),
                    'username': i.get('username', '')
                })
            if items: return items

        # Fallback WMI
        if wmi:
            try:
                c = wmi.WMI()
                for s in c.Win32_StartupCommand():
                    items.append({
                        'name': s.Name,
                        'path': s.Command,
                        'location': s.Location,
                        'args': '',
                        'type': 'Login',
                        'source': 'Registry',
                        'status': 'Enabled',
                        'username': s.User
                    })
            except Exception:
                pass
        return items

    def get_system_health(self):
        """Returns simple CPU/RAM usage stats using psutil."""
        health = {
            "cpu": {},
            "ram": {},
            "disk": []
        }
        try:
            # CPU
            health["cpu"]["percent"] = psutil.cpu_percent(interval=None) # Non-blocking
            health["cpu"]["count"] = psutil.cpu_count(logical=True)
            
            # RAM
            mem = psutil.virtual_memory()
            health["ram"]["total"] = mem.total
            health["ram"]["available"] = mem.available
            health["ram"]["percent"] = mem.percent
            
            # Disk
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    health["disk"].append({
                        "device": part.device,
                        "total": usage.total,
                        "free": usage.free,
                        "percent": usage.percent
                    })
                except: 
                    pass
        except Exception as e:
            logging.error(f"Health Check Error: {e}")
        return health

    def get_system_metadata(self):
        """Gets BIOS date and OS Install date to calculate 'Hardware Age' and 'OS Freshness'."""
        meta = {"os_install_date": "", "bios_date": ""}
        if osq_client.available:
            try:
                data = osq_client.query("SELECT install_date FROM os_version")
                if data:
                    meta["os_install_date"] = data[0].get("install_date", "")
            except: pass
        
        # Fallback to WMI if missing (Windows)
        if not meta["bios_date"] and wmi:
            try:
                c = wmi.WMI()
                for bios in c.Win32_BIOS():
                    meta["bios_date"] = str(bios.ReleaseDate)
                    break
            except Exception as e:
                logging.error(f"WMI BIOS Date Error: {e}")
                
        return meta

    def get_services(self) -> List[Dict[str, Any]]:
        """Lists all system services (Daemons)."""
        services = []
        if osq_client.available:
            data = osq_client.query("SELECT name, display_name, status, start_type FROM services")
            for s in data:
                services.append({
                    'name': s.get('name'),
                    'display_name': s.get('display_name'),
                    'status': s.get('status'),
                    'start_mode': s.get('start_type')
                })
            if services: return services

        # Fallback psutil
        try:
            for service in psutil.win_service_iter():
                try:
                    info = service.as_dict(attrs=['name', 'display_name', 'status', 'start_type'])
                    services.append({
                        'name': info['name'],
                        'display_name': info['display_name'],
                        'status': info['status'],
                        'start_mode': info['start_type']
                    })
                except psutil.NoSuchProcess:
                    continue
        except AttributeError:
             pass # Not on Windows

        return services

    def get_users(self) -> List[Dict[str, Any]]:
        """Lists user accounts on the machine."""
        users = []
        if osq_client.available:
            data = osq_client.query("SELECT username, uid, description FROM users")
            for u in data:
                users.append({
                    'username': u.get('username', 'Unknown'),
                    'uid': u.get('uid', ''),
                    'description': u.get('description', ''),
                    'last_login': 'Unknown' 
                })
            if users: return users

        # Fallback
        try:
             seen = set()
             # Active Sessions
             for u in psutil.users():
                 users.append({
                     'username': u.name,
                     'uid': '',
                     'description': 'Active Session',
                     'last_login': datetime.datetime.fromtimestamp(u.started).strftime("%Y-%m-%d %H:%M")
                 })
                 seen.add(u.name)
             # All Accounts (WMI)
             if wmi:
                c = wmi.WMI()
                for u in c.Win32_UserAccount():
                    if u.Name not in seen:
                        users.append({
                            'username': u.Name,
                            'uid': u.SID,
                            'description': u.Description or "",
                            'last_login': "" 
                        })
        except Exception:
            pass
        return users
        
    # --- Phase 2 Telemetry Methods (Enrichment) ---
    
    def get_crashes(self) -> List[Dict]:
        """Gets recent application crash logs (WER)."""
        if not osq_client.available: return []
        data = osq_client.query("SELECT crash_path, module, type FROM windows_crashes LIMIT 10")
        crashes = []
        for x in data:
            crashes.append({
                'crash_time': 'Unknown',
                'path': x.get('crash_path'),
                'module': x.get('module'),
                'type': x.get('type')
            })
        return crashes

    def get_security_status(self) -> List[Dict]:
        """Gets status of Antivirus / Firewall / AutoUpdate settings."""
        if not osq_client.available: return []
        data = osq_client.query("SELECT * FROM windows_security_products")
        res = []
        for x in data:
             res.append({
                 'service': x.get('name'),
                 'status': x.get('type'),
                 'state': x.get('state') 
             })
        return res

    def get_windows_updates(self) -> List[Dict]:
        """Gets history of installed windows patches (Hotfixes)."""
        if not osq_client.available: return []
        data = osq_client.query("SELECT title, description, date FROM windows_update_history LIMIT 20")
        res = []
        for x in data:
            res.append({
                'hotfix_id': x.get('title', 'Unknown'),
                'description': x.get('description', ''),
                'installed_on': str(x.get('date', '')),
                'installed_by': 'System'
            })
        return res

    def get_battery_status(self) -> List[Dict]:
        """Battery health for laptops."""
        if not osq_client.available: return []
        data = osq_client.query("SELECT * FROM battery")
        if not data: return []
        res = []
        for x in data:
            res.append({
                'cycle_count': x.get('cycle_count', 0),
                'health': x.get('health', 'Good'),
                'status': x.get('state', 'Unknown'),
                'remaining_percent': x.get('percent_remaining', 0)
            })
        return res

    def get_browser_extensions(self) -> List[Dict]:
        """
        Lists installed browser extensions.
        Extensions are a common vector for Adware/Spyware.
        """
        if not osq_client.available: return []
        res = []
        # Chrome
        data = osq_client.query("SELECT name, version, identifier, 'Chrome' as browser FROM chrome_extensions")
        for x in data:
             res.append(x)
        # Firefox
        data = osq_client.query("SELECT name, version, identifier, 'Firefox' as browser FROM firefox_addons")
        for x in data:
             res.append(x)
        return res

    def get_drivers(self) -> List[Dict]:
        """Lists kernel drivers. Focus on UNSIGNED drivers."""
        if not osq_client.available: return []
        data = osq_client.query("SELECT description, provider, signed, image FROM drivers LIMIT 100") 
        res = []
        for x in data:
            res.append({
                'name': os.path.basename(x.get('image', 'Unknown') or 'Unknown'),
                'description': x.get('description'),
                'provider': x.get('provider'),
                'status': 'Running',
                'signed': 1 if x.get('signed') == '1' else 0
            })
        return res

    def get_hosts_file(self) -> List[Dict]:
        """Reads /etc/hosts (or C:\\Windows\\System32\\drivers\\etc\\hosts)."""
        if not osq_client.available: return []
        data = osq_client.query("SELECT hostnames, address FROM etc_hosts")
        res = []
        for x in data:
            res.append({
                'hostnames': x.get('hostnames'),
                'ip_address': x.get('address')
            })
        return res

# ---------------------------------------------------------
# CERTIFICATE MANAGER
# ---------------------------------------------------------

class CertificateManager:
    """
    Manages inspection of system certificates.
    Useful for detecting malicious root certificates installed by bad actors (MitM attacks).
    """
    def get_certificates(self) -> List[Dict[str, str]]:
        certs = []
        if osq_client.available:
            data = osq_client.query("SELECT common_name, issuer, not_valid_after, self_signed FROM certificates")
            for c in data:
                 certs.append({
                    'subject': c.get('common_name', 'Unknown'),
                    'issuer': c.get('issuer', 'Unknown'),
                    'expiry': datetime.datetime.fromtimestamp(int(c.get('not_valid_after', 0))).strftime("%Y-%m-%d") if c.get('not_valid_after') else "Unknown",
                    'is_root': c.get('self_signed') == '1'
                 })
        return certs

# ---------------------------------------------------------
# NETWORK SCANNER
# ---------------------------------------------------------

class NetworkScanner:
    """
    Monitors active network connections and listening ports.
    """
    def scan_connections(self) -> List[Dict[str, Any]]:
        """Returns list of active sockets (TCP/UDP)."""
        if osq_client.available:
            sql = "SELECT p.pid, p.name, s.local_address, s.local_port, s.remote_address, s.remote_port, s.state, s.protocol FROM process_open_sockets s JOIN processes p ON s.pid = p.pid WHERE s.family = 2"
            results = osq_client.query(sql)
            if results:
                connections = []
                for r in results:
                    connections.append({
                        'local_addr': f"{r.get('local_address')}:{r.get('local_port')}",
                        'remote_addr': f"{r.get('remote_address')}:{r.get('remote_port')}",
                        'state': r.get('state'),
                        'pid': r.get('pid'),
                        'process_name': r.get('name'),
                        'protocol': 'TCP' if r.get('protocol') == 6 else 'UDP'
                    })
                return connections
        
        # Fallback to psutil
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    process = psutil.Process(conn.pid)
                    proc_name = process.name()
                except: proc_name = "Unknown"
                
                connections.append({
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                    'state': conn.status,
                    'pid': conn.pid,
                    'process_name': proc_name,
                    'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                })
        except: pass
        return connections

    def get_listening_ports(self) -> List[Dict[str, Any]]:
        """Returns list of ports currently listening for incoming connections."""
        if osq_client.available:
            sql = "SELECT p.pid, p.name, p.uid, l.port, l.protocol FROM listening_ports l JOIN processes p ON l.pid = p.pid"
            results = osq_client.query(sql)
            if results:
                listening = []
                for r in results:
                    listening.append({
                        'port': r.get('port'),
                        'protocol': 'TCP' if r.get('protocol') == 6 else 'UDP',
                        'process_name': r.get('name'),
                        'binary_path': '',
                        'pid': r.get('pid'),
                        'username': r.get('uid'),
                        'risk_score': 0 
                    })
                return listening

        listening = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_LISTEN:
                    try:
                        process = psutil.Process(conn.pid)
                        proc_name = process.name()
                        username = process.username()
                        exe = process.exe()
                    except:
                        proc_name = "System/Unknown"
                        username = "SYSTEM"
                        exe = ""
                    
                    listening.append({
                        'port': conn.laddr.port,
                        'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                        'process_name': proc_name,
                        'binary_path': exe,
                        'pid': conn.pid,
                        'username': username,
                        'risk_score': 0 
                    })
        except: pass
        return listening

# ---------------------------------------------------------
# PROCESS MONITOR
# ---------------------------------------------------------

class ProcessMonitor:
    """
    Monitors running system processes.
    Captures CPU/Memory usage for Task-Manager-like views.
    """
    def get_running_processes(self) -> List[Dict[str, Any]]:
        procs = []
        # 'process_iter' is preferred over 'pids' as it is atomic and efficient
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'memory_info', 'cpu_percent', 'username', 'create_time']):
            try:
                pinfo = proc.info
                mem_info = pinfo.get('memory_info')
                mem_mb = (mem_info.rss / (1024 * 1024)) if mem_info else 0.0
                
                procs.append({
                    'pid': pinfo['pid'],
                    'name': pinfo['name'] or "Unknown",
                    'path': pinfo['exe'] or "",
                    'memory': mem_mb, 
                    'cpu': pinfo['cpu_percent'] or 0.0,
                    'username': pinfo['username'] or "System",
                    'start_time': datetime.datetime.fromtimestamp(pinfo['create_time']).strftime("%Y-%m-%d %H:%M:%S") if pinfo.get('create_time') else ""
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue
            except Exception as e:
                logging.error(f"Process Monitor Error: {e}")
        return procs

# ---------------------------------------------------------
# VULNERABILITY ENGINE
# ---------------------------------------------------------

class VulnEngine:
    """
    Core engine for vulnerability detection.
    Correlates installed software with known CVEs from NIST NVD.
    """
    def __init__(self):
        self.config = ConfigManager.load_config()
        self.api_key = self.config.get("nist_api_key", "")
        self.cached_cves = []

    def sync_cves(self) -> int:
        """
        Connects to NIST NVD API 2.0 to download recent vulnerabilities.
        """
        if not self.api_key:
            logging.warning("NIST API Key missing. Skipping real CVE Sync.")
            return 0
        try:
            # We fetch last 120 days to keep the database small but relevant
            end_date = datetime.datetime.now()
            start_date = end_date - datetime.timedelta(days=120)
            
            pub_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            pub_end = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            
            headers = {"apiKey": self.api_key}
            base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            start_index = 0
            results_per_page = 2000
            
            self.cached_cves = []
            
            while True:
                # Pagination Loop
                url = f"{base_url}?pubStartDate={pub_start}&pubEndDate={pub_end}&startIndex={start_index}&resultsPerPage={results_per_page}"
                logging.info(f"Querying NIST NVD (Index {start_index}): {url}")
                
                resp = requests.get(url, headers=headers, timeout=30)
                
                if resp.status_code != 200:
                    logging.error(f"NIST API Error: {resp.status_code}")
                    break
                    
                data = resp.json()
                vulnerabilities = data.get('vulnerabilities', [])
                total_results = data.get('totalResults', 0)
                
                for item in vulnerabilities:
                    cve = item.get('cve', {})
                    cve_id = cve.get('id')
                    desc = cve.get('descriptions', [{}])[0].get('value', 'No description')
                    
                    # Score Extraction (Try V3.1 -> V3.0 -> V2)
                    metrics = cve.get('metrics', {})
                    score = 0.0
                    if 'cvssMetricV31' in metrics:
                         score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                    elif 'cvssMetricV30' in metrics:
                         score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                    elif 'cvssMetricV2' in metrics:
                         score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                    
                    if score > 0:
                        self.cached_cves.append({
                            'cve_id': cve_id,
                            'description': desc,
                            'cvss_score': score
                        })
                
                logging.info(f"Fetched {len(vulnerabilities)} entries. Total Cached: {len(self.cached_cves)}")
                
                start_index += len(vulnerabilities)
                if start_index >= total_results:
                    break
                    
                # Rate Limiting (NIST requires pauses)
                import time
                time.sleep(2) 
            
            return len(self.cached_cves)
        except Exception as e:
            logging.error(f"CVE Sync Exception: {e}")
            return 0

    def match_vulnerabilities(self, software_list: List[Dict]) -> List[Dict]:
        """
        Cross-references installed software with the CVE cache.
        Algorithm: String Matching (Naive but effective for demo).
        """
        matches = []
        if not self.cached_cves:
            self.sync_cves()
        
        for sw in software_list:
            sw_name = sw.get('name', '').lower()
            if len(sw_name) < 4: continue 
            
            for cve in self.cached_cves:
                # Naive Fuzzy Match: check if software name is inside the CVE description
                if sw_name in cve.get('description', '').lower():
                     matches.append({
                         "software_id": sw.get("id"),
                         "name": sw.get("name"),
                         "cve_id": cve.get("cve_id"),
                         "confidence": "Medium",
                         "status": "Detected"
                     })
        return matches

# ---------------------------------------------------------
# YARA MANAGER
# ---------------------------------------------------------

class YaraManager:
    """
    Manages YARA rule compilation and file scanning.
    YARA is the industry standard for malware pattern matching.
    """
    def __init__(self, rules_dir="rules"):
        self.rules = None
        self.rules_dir = rules_dir
        self.compile_rules()

    def compile_rules(self):
        """Compiles all .yar files in the directory into a single optimized Rules object."""
        if not yara:
            logging.warning("YARA not installed.")
            return

        if not os.path.exists(self.rules_dir):
            try:
                os.makedirs(self.rules_dir)
                # Create a harmless dummy rule so compilation doesn't fail
                dummy_rule = """
rule Dummy {
    condition: false
}
"""
                with open(os.path.join(self.rules_dir, "dummy.yar"), "w") as f:
                    f.write(dummy_rule)
            except Exception as e:
                logging.error(f"Failed to create rules dir: {e}")

        filepaths = {}
        for root, dirs, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith(".yar") or file.endswith(".yara"):
                     filepaths[file] = os.path.join(root, file)
        
        if filepaths:
            try:
                self.rules = yara.compile(filepaths=filepaths)
                logging.info(f"Compiled {len(filepaths)} YARA rules.")
            except Exception as e:
                logging.error(f"Failed to compile YARA rules: {e}")

    def scan_file(self, file_path):
        """Scans a single file against all compiled rules."""
        if not self.rules:
            return []
        try:
            matches = self.rules.match(file_path)
            # Match objects need to be converted to something serializable usually, 
            # but we return matches objects here and let the worker process them.
            return matches
        except Exception as e:
            return []

# ---------------------------------------------------------
# AI ASSISTANT MANAGER
# ---------------------------------------------------------

class AIAssistant:
    """
    Interface for Generative AI (Google Gemini).
    Translates technical alerts into plain English instructions.
    """
    def __init__(self, api_key: str = ""):
        self.config = ConfigManager.load_config()
        self.api_key = self.config.get("gemini_api_key", "")
        # Using the Gemini 1.5/2.0 Flash/Pro endpoint
        self.endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent?key={self.api_key}"

    def explain_vulnerability(self, title: str, description: str) -> str:
        try:
            prompt = f"""
            You are a cybersecurity expert. Explain the following vulnerability simply.
            Title: {title}
            Description: {description}
            Focus on Impact and Remediation. Concise.
            """
            payload = {"contents": [{"parts": [{"text": prompt}]}]}
            headers = {'Content-Type': 'application/json'}
            response = requests.post(self.endpoint, headers=headers, json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                try:
                    return data['candidates'][0]['content']['parts'][0]['text']
                except: return "Could not parse AI response."
            else:
                return f"AI Error: {response.status_code}"
        except Exception as e:
            return f"AI Service Unavailable: {e}"

    def explain_exposure(self, service_info: dict, risk_reasons: str) -> str:
        try:
            prompt = f"""
            Analyze this exposed service:
            Service: {service_info.get('process_name')}
            Port: {service_info.get('port')}
            User: {service_info.get('username', 'Unknown')}
            Risk: {risk_reasons}
            Explain the threat and how to secure it.
            """
            payload = {"contents": [{"parts": [{"text": prompt}]}]}
            headers = {'Content-Type': 'application/json'}
            response = requests.post(self.endpoint, headers=headers, json=payload, timeout=15)
            if response.status_code == 200:
                data = response.json()
                try:
                    return data['candidates'][0]['content']['parts'][0]['text']
                except: return "Error parsing explanation."
            else:
                return f"AI Error: {response.status_code}"
        except Exception as e:
            return f"AI Unavailable: {e}"

    def explain_risk(self, context_data: Dict) -> str:
        """Dispatcher method used by the worker."""
        risk_type = context_data.get('type', 'general')
        if risk_type == 'cve':
            return self.explain_vulnerability(context_data.get('title',''), context_data.get('description',''))
        elif risk_type == 'exposure':
            return self.explain_exposure(context_data, context_data.get('risk_reasons',''))
        else:
            return f"Risk Analysis for {risk_type}"

# ---------------------------------------------------------
# THREAT INTEL MANAGER
# ---------------------------------------------------------

class ThreatIntelManager:
    """
    Connects to external Threat Intelligence APIs (VirusTotal).
    """
    def __init__(self):
        self.config = ConfigManager.load_config()
        # Fallback to Gemini Key if VT key missing (sometimes users reuse keys, though incorrect)
        self.api_key = self.config.get("vt_api_key", "") 

    @staticmethod
    def get_file_hash(path):
        """Calculates SHA256 hash of a file efficiently (chunked read)."""
        sha256_hash = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                # Read 4KB chunks
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logging.error(f"Hash error: {e}")
            return None

    def check_virustotal(self, target):
        """
        Queries VirusTotal API v3.
        """
        if not self.api_key:
            return {"error": "No API Key"}

        file_hash = target
        if os.path.exists(target):
            file_hash = self.get_file_hash(target)
            if not file_hash:
                return {"error": "Could not calculate hash"}

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "x-apikey": self.api_key
        }
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                stats['hash'] = file_hash
                return stats
            elif response.status_code == 404:
                return {"result": "Clean (Not Found in VT)", "harmless": 0, "malicious": 0, "hash": file_hash}
            else:
                return {"error": f"VT API Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

# ---------------------------------------------------------
# RESPONSE MANAGER
# ---------------------------------------------------------

class ResponseManager:
    """
    Handles active remediation actions.
    """
    @staticmethod
    def kill_process(pid: int) -> bool:
        """Terminates a process by PID."""
        try:
            p = psutil.Process(pid)
            p.terminate()
            return True
        except psutil.NoSuchProcess:
            return False
        except psutil.AccessDenied:
            logging.error(f"Access Denied terminating PID {pid}")
            return False
        except Exception as e:
            logging.error(f"Error terminating PID {pid}: {e}")
            return False

    @staticmethod
    def block_ip_firewall(ip: str) -> bool:
        """
        Blocks an IP address using Windows Firewall (netsh).
        Requires Admin Privileges.
        """
        try:
            cmd = f'netsh advfirewall firewall add rule name="ProjectX Block {ip}" dir=in action=block remoteip={ip}'
            subprocess.check_call(cmd, shell=True)
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to block IP {ip}: {e}")
            return False
        except Exception as e:
            logging.error(f"Error blocking IP {ip}: {e}")
            return False
