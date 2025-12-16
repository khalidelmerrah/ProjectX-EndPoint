import platform
import subprocess
import socket
import logging
import psutil
from typing import List, Dict, Any
import datetime
import os
import requests
import sys
import json

# Try importing wmi for Windows, handle if missing
try:
    import wmi
except ImportError:
    wmi = None

# Secure Credential Storage
import keyring

class ConfigManager:
    SERVICE_ID = "ProjectX_Desktop"
    KEYS = ["nist_api_key", "gemini_api_key"]

    @staticmethod
    def load_config() -> Dict[str, str]:
        """Loads API keys from the secure credential store (Keyring)."""
        config = {}
        for key in ConfigManager.KEYS:
            try:
                # get_password returns None if not found
                val = keyring.get_password(ConfigManager.SERVICE_ID, key)
                config[key] = val if val else ""
            except Exception as e:
                logging.error(f"Keyring load error for {key}: {e}")
                config[key] = ""
        return config

    @staticmethod
    def save_config(data: Dict[str, str]):
        """Saves API keys to the secure credential store (Keyring)."""
        for key in ConfigManager.KEYS:
            if key in data:
                try:
                    keyring.set_password(ConfigManager.SERVICE_ID, key, data[key])
                except Exception as e:
                    logging.error(f"Keyring save error for {key}: {e}")

class OSQueryClient:
    def __init__(self):
        self.available = False
        self.binary_path = "osqueryi"
        
        # Check availability
        # 1. Check Bundled/Local Path (Portable Deployment)
        # Handle PyInstaller _MEIPASS if applicable
        base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
        
        bundled_paths = [
            os.path.join(base_path, 'bin', 'osqueryi.exe'),
            os.path.join(base_path, '..', 'bin', 'osqueryi.exe'), # In case we are in src/
            os.path.join(os.getcwd(), 'bin', 'osqueryi.exe')
        ]
        
        for p in bundled_paths:
            if os.path.exists(p):
                self.binary_path = p
                self.available = True
                logging.info(f"OSQuery found (Bundled) at {p}")
                return # Stop if found locally

        # 2. Check System PATH
        try:
            creation_flags = subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0
            subprocess.run(["osqueryi", "--version"], capture_output=True, creationflags=creation_flags)
            self.binary_path = "osqueryi"
            self.available = True
            logging.info("OSQuery found in PATH.")
            return
        except FileNotFoundError:
            pass

        # 3. Check Standard Windows paths (Fallback)
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
            logging.warning("osqueryi binary not found. Scans will be limited.")

    def query(self, sql: str) -> List[Dict]:
        if not self.available:
            return []
        try:
            # Run osqueryi directly
            cmd = [self.binary_path, "--json", sql]
            
            creation_flags = subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                encoding='utf-8',
                creationflags=creation_flags
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

    def __del__(self):
        pass

# Global shared client
osq_client = OSQueryClient()

class InventoryManager:
    def get_installed_software(self) -> List[Dict[str, Any]]:
        software_list = []
        
        # 1. Try OSQuery (Direct)
        if osq_client.available:
            logging.info("Using OSQuery (Direct) for Software Inventory...")
            data = osq_client.query("SELECT name, version, publisher, install_date FROM programs")
            # osquery sometimes returns nulls or different keys
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
                logging.info(f"OSQuery found {len(software_list)} apps.")
                return software_list
            else:
                logging.warning("OSQuery returned 0 apps. Falling back to Registry...")

        # 2. Try Windows Registry (Reliable Fallback)
        try:
            import winreg
            logging.info("Scanning Windows Registry for Software...")
            
            def get_val(key, name):
                try:
                    return winreg.QueryValueEx(key, name)[0]
                except FileNotFoundError:
                    return ""

            registry_paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
            ]
            
            seen_names = set()

            for root, path in registry_paths:
                try:
                    with winreg.OpenKey(root, path) as key:
                        for i in range(winreg.QueryInfoKey(key)[0]):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                with winreg.OpenKey(key, f"{path}\\{subkey_name}") as subkey:
                                    name = get_val(subkey, "DisplayName")
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

        # 3. Try WMI
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
        
        # NO MOCK DATA - Return empty if nothing found
        return software_list

    def get_startup_items(self) -> List[Dict[str, Any]]:
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

    def get_services(self) -> List[Dict[str, Any]]:
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
             pass

        return services

    def get_users(self) -> List[Dict[str, Any]]:
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

        try:
             seen = set()
             for u in psutil.users():
                 users.append({
                     'username': u.name,
                     'uid': '',
                     'description': 'Active Session',
                     'last_login': datetime.datetime.fromtimestamp(u.started).strftime("%Y-%m-%d %H:%M")
                 })
                 seen.add(u.name)
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
        
    # --- New Phase 2 Telemetry Methods ---
    
    def get_crashes(self) -> List[Dict]:
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
        if not osq_client.available: return []
        # Schema Verified: title, description, date, support_url
        data = osq_client.query("SELECT title, description, date FROM windows_update_history LIMIT 20")
        res = []
        for x in data:
            raw_date = str(x.get('date', ''))
            try:
                if raw_date.isdigit():
                    installed_on = datetime.datetime.fromtimestamp(int(raw_date)).strftime("%Y-%m-%d")
                else:
                    installed_on = raw_date
            except: installed_on = raw_date
            
            res.append({
                'hotfix_id': x.get('title', 'Unknown'), # Maps Title (e.g., KBxxxx) to hotfix_id
                'description': x.get('description', ''),
                'installed_on': installed_on,
                'installed_by': 'System'
            })
        return res

    def get_battery_status(self) -> List[Dict]:
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
        if not osq_client.available: return []
        res = []
        # Chrome
        data = osq_client.query("SELECT name, version, identifier, 'Chrome' as browser FROM chrome_extensions")
        for x in data:
             res.append({
                 'name': x.get('name'),
                 'version': x.get('version'),
                 'browser': 'Chrome',
                 'identifier': x.get('identifier'),
                 'status': 'Enabled'
             })
        # Firefox
        data = osq_client.query("SELECT name, version, identifier, 'Firefox' as browser FROM firefox_addons")
        for x in data:
             res.append({
                 'name': x.get('name'),
                 'version': x.get('version'),
                 'browser': 'Firefox',
                 'identifier': x.get('identifier'),
                 'status': 'Enabled'
             })
        return res

    def get_drivers(self) -> List[Dict]:
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
        if not osq_client.available: return []
        data = osq_client.query("SELECT hostnames, address FROM etc_hosts")
        res = []
        for x in data:
            res.append({
                'hostnames': x.get('hostnames'),
                'ip_address': x.get('address')
            })
        return res

class CertificateManager:
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
        
        # NO MOCK DATA
        return certs

class NetworkScanner:
    def scan_connections(self) -> List[Dict[str, Any]]:
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

class ProcessMonitor:
    def get_running_processes(self) -> List[Dict[str, Any]]:
        procs = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'memory_info', 'cpu_percent', 'username', 'create_time']):
            try:
                pinfo = proc.info
                # Safely get memory info
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

class VulnEngine:
    def __init__(self):
        self.config = ConfigManager.load_config()
        self.api_key = self.config.get("nist_api_key", "")
        self.cached_cves = []

    def sync_cves(self) -> int:
        if not self.api_key:
            logging.warning("NIST API Key missing. Skipping real CVE Sync.")
            return 0
        try:
            end_date = datetime.datetime.now()
            start_date = end_date - datetime.timedelta(days=30)
            
            pub_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            pub_end = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            
            headers = {"apiKey": self.api_key}
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={pub_start}&pubEndDate={pub_end}&cvssV3Severity=CRITICAL"
            
            logging.info(f"Querying NIST NVD: {url}")
            resp = requests.get(url, headers=headers, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json()
                vulnerabilities = data.get('vulnerabilities', [])
                self.cached_cves = []
                for item in vulnerabilities:
                    cve = item.get('cve', {})
                    cve_id = cve.get('id')
                    desc = cve.get('descriptions', [{}])[0].get('value', 'No description')
                    metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {})
                    score = metrics.get('baseScore', 0.0)
                    
                    self.cached_cves.append({
                        'cve_id': cve_id,
                        'description': desc,
                        'cvss_score': score
                    })
                logging.info(f"Fetched {len(self.cached_cves)} recent critical CVEs.")
                return len(self.cached_cves)
            else:
                logging.error(f"NIST API Error: {resp.status_code} - {resp.text}")
                return 0
        except Exception as e:
            logging.error(f"CVE Sync Exception: {e}")
            return 0

    def match_vulnerabilities(self, software_list: List[Dict]) -> List[Dict]:
        matches = []
        if not self.cached_cves:
            # NO MOCK DATA
            logging.warning("No CVEs in cache. Skipping matching.")
            return matches
        
        # Real Matching
        for sw in software_list:
            sw_name = sw['name'].lower()
            if len(sw_name) < 4: continue 
            
            for cve in self.cached_cves:
                if sw_name in cve['description'].lower():
                    matches.append({
                        'software': sw['name'],
                        'software_id': 0,
                        'cve_id': cve['cve_id'],
                        'description': cve['description'],
                        'cvss_score': cve['cvss_score'],
                        'confidence': 50
                    })
        return matches

class AIAssistant:
    def __init__(self, api_key: str = ""):
        self.config = ConfigManager.load_config()
        self.api_key = self.config.get("gemini_api_key", "")
        self.endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key={self.api_key}"

    def explain_vulnerability(self, title: str, description: str) -> str:
        try:
            prompt = f"""
            You are a cybersecurity expert. Explain the following vulnerability simply to a user.
            Focus on: 1) What is happening? 2) What is the impact? 3) What should I do?
            
            Title: {title}
            Description: {description}
            
            Keep the response concise (under 200 words).
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
            You are a security analyst. Analyze this exposed service:
            
            Service: {service_info.get('process_name')} (PID: {service_info.get('pid')})
            Port: {service_info.get('port')} / {service_info.get('protocol')}
            Path: {service_info.get('binary_path')}
            User: {service_info.get('username', 'Unknown')}
            Risk Factors: {risk_reasons}
            
            Provide a response in Markdown with:
            1. **What is it?** (Likely identity)
            2. **Threat** (Why it matters)
            3. **Action** (Concrete remediation)
            4. **Verification**
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
        risk_type = context_data.get('type', 'general')
        if risk_type == 'cve':
            return self.explain_vulnerability(context_data.get('title',''), context_data.get('description',''))
        elif risk_type == 'exposure':
            return self.explain_exposure(context_data, context_data.get('risk_reasons',''))
        else:
            return f"Risk Analysis for {risk_type}"
