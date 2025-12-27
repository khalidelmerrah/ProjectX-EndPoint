"""
MODULE: managers.py
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
This module contains the **Business Logic Layer** (the "Brain") of the application.
It follows the **Service-Oriented Architecture (SOA)** pattern, where distinct
functionalities (Inventory, Vulnerability Ops, Threat Intel) are encapsulated 
in separate "Manager" classes.

DESIGN PATTERNS IMPLEMENTED:
----------------------------
1.  **Singleton / Monostate**:
    While not strictly enforced via `__new__`, these classes are designed to be 
    instantiated once and shared (conceptually) or are stateless enough to be 
    transient.

2.  **Chain of Responsibility (Fallback Logic)**:
    In `SoftwareManager`, we see a critical resilience pattern. The system attempts 
    to fetch data from the most reliable source (OSQuery). If that fails (e.g., 
    binary missing), it degrades gracefully to Windows Registry scans, and finally 
    to WMI (Windows Management Instrumentation). 
    *Principle: Security tools must function even in broken environments.*

3.  **Sidecar Pattern (OSQuery Integration)**:
    ProjectX does not re-invent the wheel. It leverages `osqueryi.exe` as a 
    powerful subprocess ("Sidecar") to query the OS like a database. 
    This decouples the "Data Collection" (C++) from the "Analysis" (Python).

4.  **Secure Configuration Management**:
    The `ConfigManager` prioritizes OS-level Keychains (Windows Credential Locker) 
    over plaintext files for storing sensitive API keys. This is a baseline 
    requirement for any security software.

KEY COMPONENTS:
---------------
-   `ConfigManager`: Handles persistence of settings and secrets (Keyring).
-   `OSQueryClient`: Wrapper for IPC (stdIO) with the OSQuery table explorer.
-   `SoftwareManager`: Aggregates software inventory from multiple sources.
-   `VulnEngine`: Correlates inventory with NIST NVD CVE data (the "Matcher").
-   `YaraManager`: Compiles and executes YARA rules for signature matching.
-   `AIAssistant`: Connects to LLMs (Gemini) to explain alerts to users.
-   `ResponseManager`: Active defense capabilities (Kill Process, Firewall Block).

"""

import sys          # System-specific parameters and functions
import os           # Operating system interfaces (Paths, FS)
import subprocess   # Spawning new processes, connecting to input/output pipes
import json         # JSON encoder and decoder
import logging      # Event logging system
import platform     # Access to underlying platform's identifying data
import datetime     # Basic date and time types
import hashlib      # Secure hash and message digest algorithms
import socket       # Low-level networking interface
from typing import List, Dict, Any, Optional
from dateutil import parser # Robust date parsing library

# ------------------------------------------------------------------------------
# THIRD-PARTY DEPENDENCIES
# ------------------------------------------------------------------------------
# We adhere to "Defensive Importing". 
# If a non-critical library is missing, we catch the import error and disable 
# the feature rather than crashing the entire application.

# PSUTIL: Cross-platform process and system monitoring
try:
    import psutil
except ImportError:
    logging.critical("CRITICAL: 'psutil' library missing. System monitoring disabled.")
    psutil = None

# REQUESTS: HTTP Library for Humans (used for API calls)
try:
    import requests
except ImportError:
    logging.critical("CRITICAL: 'requests' library missing. Cloud features disabled.")
    requests = None

# KEYRING: Secure Password Storage (Windows Credential Manager / macOS Keychain)
try:
    import keyring
except ImportError:
    logging.warning("WARNING: 'keyring' not found. API keys will verify insecurely if not handled.")
    keyring = None

# YARA: The pattern matching swiss knife for malware researchers
try:
    import yara
except ImportError:
    logging.warning("WARNING: 'yara-python' not found. Signature scanning disabled.")
    yara = None

# WMI: Windows Management Instrumentation (Windows Only)
try:
    import wmi
except ImportError:
    # This is expected on Linux/macOS
    logging.info("INFO: 'wmi' module not found (Non-Windows or missing).")
    wmi = None

# ------------------------------------------------------------------------------
# CONSTANTS & CONFIGURATION
# ------------------------------------------------------------------------------
CONFIG_FILE = "config.json"       # Stored in the application root
SERVICE_NAME = "ProjectX_Secure" # Namespace for Keyring storage

# ------------------------------------------------------------------------------
# CLASS: ConfigManager
# ------------------------------------------------------------------------------
class ConfigManager:
    """
    Manages application configuration and sensitive secrets.
    
    Security Principle: Separation of Secrets.
    Non-sensitive configuration (UI themes, boolean flags) goes into a JSON file.
    Sensitive secrets (API Keys) go into the OS Secure Storage (Keyring).
    """

    @staticmethod
    def load_config() -> Dict[str, Any]:
        """
        Loads the JSON configuration file from disk.
        Returns empty dict if file is missing or corrupt.
        """
        if not os.path.exists(CONFIG_FILE):
             return {}
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logging.error(f"Config corruption detected: {e}")
            return {}

    @staticmethod
    def save_config(data: Dict[str, Any]):
        """
        Persists the JSON configuration to disk.
        
        Args:
            data (dict): The configuration dictionary.
        """
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(data, f, indent=4) # Indent for human readability
        except IOError as e:
            logging.error(f"Failed to write config: {e}")

    @staticmethod
    def set_key(service: str, username: str, password: str):
        """
        Securely stores a secret using the OS Keyring.
        
        Why Keyring?
        Storing API keys in `config.json` is a security vulnerability.
        Malware exfiltrating files would steal the keys. 
        Keyring encrypts them using the User's Windows Login credentials.
        """
        if keyring:
            try:
                keyring.set_password(service, username, password)
            except Exception as e:
                logging.error(f"Keyring Write Error: {e}")
        else:
            # Fallback for environments without keyring (e.g., some CI runners)
            # CAUTION: This is insecure, but necessary for compatibility.
            config = ConfigManager.load_config()
            config[f"{service}_{username}"] = password
            ConfigManager.save_config(config)

    @staticmethod
    def get_key(service: str, username: str) -> str:
        """Retrieves a secret from the OS Keyring."""
        if keyring:
            try:
                val = keyring.get_password(service, username)
                return val if val else ""
            except Exception:
                return ""
        else:
            config = ConfigManager.load_config()
            return config.get(f"{service}_{username}", "")

    # Convenience Wrappers for Specific API Keys
    def get(self, key: str, default: Any = None):
        """Facade for retrieving values, abstracting the storage backend."""
        # 1. Check Keyring for known secrets
        if key == "nist_api_key":
            val = self.get_key(SERVICE_NAME, "nist_api_key")
            if val: return val
        if key == "vt_api_key":
             val = self.get_key(SERVICE_NAME, "vt_api_key")
             if val: return val
        if key == "gemini_api_key":
             val = self.get_key(SERVICE_NAME, "gemini_api_key")
             if val: return val
             
        # 2. Check JSON Config
        cfg = self.load_config()
        return cfg.get(key, default)

# ------------------------------------------------------------------------------
# CLASS: OSQueryClient
# ------------------------------------------------------------------------------
class OSQueryClient:
    """
    Interface to the OSQuery binary.
    
    Architecture:
    OSQuery acts as a "Sidecar" process. We spawn it in interactive mode (`-i`)
    and communicate via Standard Input/Output (stdin/stdout).
    This allows us to treat the Operating System as a Relational Database (SQL).
    """
    
    def __init__(self):
        self.available = False
        self.binary_path = "osqueryi" # Default: assume in System PATH
        
        # ----------------------------------------------------------------------
        # PATH INTEGRITY & PYINSTALLER COMPATIBILITY
        # ----------------------------------------------------------------------
        # When compiling to a standalone EXE (Frozen), external assets like binaries
        # are unpacked into a temporary temp folder (`sys._MEIPASS`).
        # We must detect this to find `osqueryi.exe`.
        
        if getattr(sys, 'frozen', False):
            # APP IS FROZEN (Running as EXE)
            base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
            # We bundled osqueryi.exe in the 'bin' submenu of the bundle.
            bundled_path = os.path.join(base_path, 'bin', 'osqueryi.exe')
            
            if os.path.exists(bundled_path):
                self.binary_path = bundled_path
                self.available = True
                logging.info(f"OSQuery (Bundled) found at: {bundled_path}")
                return
            else:
                logging.error(f"OSQuery bundle expected at {bundled_path} but missing!")

        # ----------------------------------------------------------------------
        # DEVELOPMENT MODE (Running from Source)
        # ----------------------------------------------------------------------
        # Check local 'bin' folder first
        local_bin = os.path.join(os.getcwd(), 'bin', 'osqueryi.exe')
        if os.path.exists(local_bin):
            self.binary_path = local_bin
            self.available = True
            logging.info(f"OSQuery (Local) found at: {local_bin}")
            return
            
        # Check System PATH as fallback
        try:
            # We use '--version' as a lightweight "Ping" to check existence
            subprocess.run([self.binary_path, "--version"], 
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            self.available = True
            logging.info("OSQuery found in System PATH")
        except (FileNotFoundError, subprocess.CalledProcessError):
            logging.warning("OSQuery not found. Some features will be disabled.")
            self.available = False

    def query(self, sql: str) -> List[Dict[str, Any]]:
        """
        Executes a SQL query against the OS.
        
        Args:
            sql (str): SQL statement (e.g. "SELECT * FROM users")
            
        Returns:
            List[Dict]: A list of dictionaries representing the rows.
        """
        if not self.available:
            return []
            
        try:
            # EXECUTION STRATEGY:
            # We pass the SQL query and request JSON output format.
            # timeout=10 prevents hanging if OSQuery freezes.
            cmd = [self.binary_path, "--json", sql]
            
            # Windows: Hide the console window for the subprocess
            startupinfo = None
            if platform.system() == "Windows":
                 startupinfo = subprocess.STARTUPINFO()
                 startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=10,
                startupinfo=startupinfo
            )
            
            if result.returncode == 0:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    return []
            else:
                logging.error(f"OSQuery failed: {result.stderr}")
                return []
        except Exception as e:
            logging.error(f"OSQuery execution error: {e}")
            return []

# Initialize the global client instance
osq_client = OSQueryClient()

# ------------------------------------------------------------------------------
# CLASS: SoftwareManager
# ------------------------------------------------------------------------------
class SoftwareManager:
    """
    Aggregates installed software inventory.
    
    Pattern: Chain of Responsibility / Fallback
    It tries the best source (OSQuery) first. If that fails or is missing,
    it falls back to native Python libraries (psutil, winreg, WMI).
    """
    
    def get_installed_software(self) -> List[Dict[str, Any]]:
        """
        Returns a list of installed applications.
        Critical for Vulnerability Management (Search installed apps vs NVD).
        """
        software_list = []
        
        # ----------------------------------------------------------------------
        # METHOD A: OSQuery "programs" table (Fastest & Most Reliable)
        # ----------------------------------------------------------------------
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

        # ----------------------------------------------------------------------
        # METHOD B: Windows Registry (The "Classic" Manual Method)
        # ----------------------------------------------------------------------
        # Windows stores uninstall strings in HKLM and HKCU hives.
        try:
            import winreg
            logging.info("Scanning Windows Registry for Software...")
            
            def get_val(key, name):
                """Helper to safely read a registry string value."""
                try:
                    return winreg.QueryValueEx(key, name)[0]
                except FileNotFoundError:
                    return ""

            # The 3 canonical locations (64-bit, 32-bit WoW64, User-specific)
            registry_paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"), 
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall") 
            ]
            
            seen_names = set() # De-duplication set (some apps exist in multiple keys)

            for root, path in registry_paths:
                try:
                    with winreg.OpenKey(root, path) as key:
                        # Iterate subkeys (one subkey per application)
                        for i in range(winreg.QueryInfoKey(key)[0]):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                with winreg.OpenKey(key, f"{path}\\{subkey_name}") as subkey:
                                    name = get_val(subkey, "DisplayName")
                                    # Filter: Ignore entries without display names
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

        # ----------------------------------------------------------------------
        # METHOD C: WMI (Last Resort - Very Slow)
        # ----------------------------------------------------------------------
        # querying Win32_Product is discouraged by Microsoft (can trigger MSI self-repair).
        if wmi:
            try:
                logging.info("Falling back to WMI for Software Inventory...")
                c = wmi.WMI()
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
        Attackers use these keys to ensure malware runs on every reboot.
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
        """Returns simple CPU/RAM usage stats using psutil (Polling)."""
        health = {
            "cpu": {},
            "ram": {},
            "disk": []
        }
        try:
            # CPU
            # interval=None makes it non-blocking (returns immediate last val)
            health["cpu"]["percent"] = psutil.cpu_percent(interval=None) 
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
        """Gets BIOS date and OS Install date to calculate 'System Freshness'."""
        meta = {"os_install_date": "", "bios_date": ""}
        if osq_client.available:
            try:
                data = osq_client.query("SELECT install_date FROM os_version")
                if data:
                    meta["os_install_date"] = data[0].get("install_date", "")
            except: pass
        
        # Fallback to WMI
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
                    # 'as_dict' is expensive, use selective attributes
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
        """Gets recent application crash logs (Windows Error Reporting - WER)."""
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
        """Gets history of installed Windows patches (Hotfixes)."""
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
        """Battery health for laptops (power management)."""
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
        Extensions are a common vector for Adware/Spyware injection.
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
        """
        Lists kernel drivers. 
        Focus is on UNSIGNED drivers, which are often rootkits or poorly written legacy code.
        """
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
        """
        Reads /etc/hosts (or C:\\Windows\\System32\\drivers\\etc\\hosts).
        Malware modifies this to redirect banking sites to phishing servers.
        """
        if not osq_client.available: return []
        data = osq_client.query("SELECT hostnames, address FROM etc_hosts")
        res = []
        for x in data:
            res.append({
                'hostnames': x.get('hostnames'),
                'ip_address': x.get('address')
            })
        return res

# ------------------------------------------------------------------------------
# CLASS: CertificateManager
# ------------------------------------------------------------------------------
class CertificateManager:
    """
    Manages inspection of system certificates.
    Useful for detecting malicious root certificates installed by attackers to 
    perform Man-in-the-Middle (MitM) attacks on SSL/TLS traffic.
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

# ------------------------------------------------------------------------------
# CLASS: NetworkScanner
# ------------------------------------------------------------------------------
class NetworkScanner:
    """
    Monitors active network connections and listening ports.
    Equivalent to running `netstat -ano` but programmatic.
    """
    def scan_connections(self) -> List[Dict[str, Any]]:
        """Returns list of active sockets (TCP/UDP) with Process attribution."""
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
        """
        Returns list of ports currently listening for incoming connections.
        Open ports are potential entry points for attackers.
        """
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

# ------------------------------------------------------------------------------
# CLASS: ProcessMonitor
# ------------------------------------------------------------------------------
class ProcessMonitor:
    """
    Monitors running system processes.
    Captures CPU/Memory usage for Task-Manager-like views.
    """
    def get_running_processes(self) -> List[Dict[str, Any]]:
        procs = []
        # 'process_iter' is preferred over 'pids' as it is atomic and efficient.
        # It creates a generator that yields processes one by one.
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'memory_info', 'cpu_percent', 'username', 'create_time']):
            try:
                pinfo = proc.info
                # Convert bytes to Megabytes (MB)
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
                # Processes die quickly; if one vanishes during iteration, we skip it.
                continue
            except Exception as e:
                logging.error(f"Process Monitor Error: {e}")
        return procs

# ------------------------------------------------------------------------------
# CLASS: VulnEngine
# ------------------------------------------------------------------------------
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
        
        Note: This is an expensive operation (Network + Parsing).
        It retrieves the last 120 days of published CVEs.
        """
        if not self.api_key:
            logging.warning("NIST API Key missing. Skipping real CVE Sync.")
            return 0
        try:
            # We fetch last 120 days to keep the database small but relevant
            end_date = datetime.datetime.now()
            start_date = end_date - datetime.timedelta(days=120)
            
            # NIST required ISO 8601 format
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
                    
                    # Score Extraction (Support V3.1 -> V3.0 -> V2)
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
                    
                # Rate Limiting (NIST requires pauses between pages)
                import time
                time.sleep(2) 
            
            return len(self.cached_cves)
        except Exception as e:
            logging.error(f"CVE Sync Exception: {e}")
            return 0

    def match_vulnerabilities(self, software_list: List[Dict]) -> List[Dict]:
        """
        Cross-references installed software with the CVE cache.
        Algorithm: Naive String Matching (O(N*M)).
        
        Optimization Note:
        In a production system, CPE (Common Platform Enumeration) matching would be used.
        Here, we fuzzy match the software name inside the CVE description for simplicity.
        """
        matches = []
        if not self.cached_cves:
            self.sync_cves()
        
        for sw in software_list:
            sw_name = sw.get('name', '').lower()
            if len(sw_name) < 4: continue # Skip short names to reduce False Positives
            
            for cve in self.cached_cves:
                # Matching Logic: Is 'adobereader' in 'cve-2023-xyz description'?
                if sw_name in cve.get('description', '').lower():
                     matches.append({
                         "software_id": sw.get("id"),
                         "name": sw.get("name"),
                         "cve_id": cve.get("cve_id"),
                         "confidence": "Medium",
                         "status": "Detected"
                     })
        return matches

# ------------------------------------------------------------------------------
# CLASS: YaraManager
# ------------------------------------------------------------------------------
class YaraManager:
    """
    Manages YARA rule compilation and file scanning.
    YARA is the industry standard for pattern-based malware classification.
    """
    def __init__(self, rules_dir="rules"):
        self.rules = None
        self.rules_dir = rules_dir
        self.compile_rules()

    def compile_rules(self):
        """Compiles all .yar files in the directory into a single optimized Rules object."""
        if not yara:
            logging.warning("YARA not installed (Import Error).")
            return

        if not os.path.exists(self.rules_dir):
            try:
                os.makedirs(self.rules_dir)
                # Create a harmless dummy rule so compilation doesn't fail on empty dir
                dummy_rule = "rule Dummy { condition: false }"
                with open(os.path.join(self.rules_dir, "dummy.yar"), "w") as f:
                    f.write(dummy_rule)
            except Exception as e:
                logging.error(f"Failed to create rules dir: {e}")

        filepaths = {}
        # Walk directory to find all .yar files
        for root, dirs, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith(".yar") or file.endswith(".yara"):
                     filepaths[file] = os.path.join(root, file)
        
        if filepaths:
            try:
                # Compilation checks syntax of all files at once
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
            return matches
        except Exception as e:
            # We fail silently here for individual files to avoid log spam
            return []

# ------------------------------------------------------------------------------
# CLASS: AIAssistant
# ------------------------------------------------------------------------------
class AIAssistant:
    """
    Interface for Generative AI (Google Gemini).
    Translates technical alerts (JSON/Logs) into plain English instructions for the user.
    """
    def __init__(self, api_key: str = ""):
        self.config = ConfigManager.load_config()
        self.api_key = self.config.get("gemini_api_key", "")
        # Using the experimental Gemini 2.0 Flash endpoint for speed/cost balance
        self.endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent?key={self.api_key}"

    def explain_vulnerability(self, title: str, description: str) -> str:
        """
        Asks AI to summarize a CVE and suggest fixes.
        """
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
        """
        Asks AI to explain why an open port is dangerous.
        """
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
        """Dispatcher method used by the worker to route requests based on type."""
        risk_type = context_data.get('type', 'general')
        if risk_type == 'cve':
            return self.explain_vulnerability(context_data.get('title',''), context_data.get('description',''))
        elif risk_type == 'exposure':
            return self.explain_exposure(context_data, context_data.get('risk_reasons',''))
        else:
            return f"Risk Analysis for {risk_type}"

# ------------------------------------------------------------------------------
# CLASS: ThreatIntelManager
# ------------------------------------------------------------------------------
class ThreatIntelManager:
    """
    Connects to external Threat Intelligence APIs (VirusTotal).
    """
    def __init__(self):
        self.config = ConfigManager.load_config()
        self.api_key = self.config.get("vt_api_key", "") 
        # Fallback to Gemini Key is not technically correct but sometimes done by users.
        # We prefer a dedicated key.

    @staticmethod
    def get_file_hash(path):
        """Calculates SHA256 hash of a file efficiently (chunked read)."""
        sha256_hash = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                # Read 4KB chunks to avoid loading large files into RAM
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logging.error(f"Hash error: {e}")
            return None

    def check_virustotal(self, target):
        """
        Queries VirusTotal API v3 using the file hash.
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
                # 404 on VT means "Unknown file", which usually means clean (or 0-day)
                return {"result": "Clean (Not Found in VT)", "harmless": 0, "malicious": 0, "hash": file_hash}
            else:
                return {"error": f"VT API Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

# ------------------------------------------------------------------------------
# CLASS: ResponseManager
# ------------------------------------------------------------------------------
class ResponseManager:
    """
    Handles active remediation actions.
    Warning: These actions can disrupt the user experience.
    """
    @staticmethod
    def kill_process(pid: int) -> bool:
        """Terminates a process by PID."""
        try:
            p = psutil.Process(pid)
            p.terminate() # SIGTERM
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
        Requires Admin Privileges (UAC).
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
