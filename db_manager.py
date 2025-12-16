import sqlite3
import logging
from typing import List, Tuple, Any, Optional, Dict
import os

DB_NAME = "projectx.db"

class DatabaseManager:
    def __init__(self, db_path: str = DB_NAME):
        self.db_path = db_path
        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Returns a connection. Note: SQLite objects created in a thread can only be used in that thread unless check_same_thread=False."""
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        """Initializes the database schema."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # 1. installed_software (Updated Phase 2)
        cursor.execute('''CREATE TABLE IF NOT EXISTS installed_software (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            version TEXT,
            publisher TEXT,
            install_date TEXT,
            icon_path TEXT,
            latest_version TEXT,
            update_available INTEGER DEFAULT 0
        )''')

        # 2. software_updates
        cursor.execute('''CREATE TABLE IF NOT EXISTS software_updates (
            software_id INTEGER,
            update_available BOOLEAN,
            latest_version TEXT,
            FOREIGN KEY(software_id) REFERENCES installed_software(id)
        )''')

        # 3. exposed_services
        cursor.execute('''CREATE TABLE IF NOT EXISTS exposed_services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port INTEGER,
            protocol TEXT,
            process_name TEXT,
            binary_path TEXT,
            pid INTEGER,
            username TEXT,
            risk_score INTEGER
        )''')

        # 4. cves
        cursor.execute('''CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            severity TEXT,
            cvss_score REAL,
            published_at TEXT,
            fetched_at TEXT
        )''')

        # 5. vulnerability_matches
        cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerability_matches (
            software_id INTEGER,
            cve_id TEXT,
            confidence INTEGER,
            status TEXT,
            FOREIGN KEY(software_id) REFERENCES installed_software(id),
            FOREIGN KEY(cve_id) REFERENCES cves(cve_id)
        )''')

        # 6. telemetry_processes
        cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_processes (
            pid INTEGER,
            name TEXT,
            path TEXT,
            username TEXT,
            start_time TEXT
        )''')

        # 7. telemetry_network
        cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_network (
            pid INTEGER,
            local_addr TEXT,
            remote_addr TEXT,
            state TEXT,
            protocol TEXT
        )''')

        # 8. system_services
        cursor.execute('''CREATE TABLE IF NOT EXISTS system_services (
            name TEXT,
            display_name TEXT,
            status TEXT,
            start_mode TEXT
        )''')

        # 9. startup_items (Updated Phase 2)
        cursor.execute('''CREATE TABLE IF NOT EXISTS startup_items (
            name TEXT,
            path TEXT,
            location TEXT,
            args TEXT,
            type TEXT,
            source TEXT,
            status TEXT,
            username TEXT
        )''')

        # 10. certificates
        cursor.execute('''CREATE TABLE IF NOT EXISTS certificates (
            subject TEXT,
            issuer TEXT,
            expiry_date TEXT,
            is_root BOOLEAN
        )''')

        # 11. user_accounts
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_accounts (
            username TEXT,
            uid TEXT,
            description TEXT,
            last_login TEXT
        )''')

        # 12. system_posture
        cursor.execute('''CREATE TABLE IF NOT EXISTS system_posture (
            check_name TEXT,
            status TEXT,
            timestamp TEXT
        )''')
        
        # 13. advisories
        cursor.execute('''CREATE TABLE IF NOT EXISTS advisories (
            advisory_id TEXT PRIMARY KEY,
            title TEXT,
            link TEXT,
            pub_date TEXT,
            description TEXT,
            severity REAL,
            impact TEXT,
            cvss_vector TEXT,
            vendor TEXT,
            cve_ids TEXT,
            products TEXT,
            summary TEXT,
            html_title TEXT,
            html_description TEXT,
            html_fetched_at TEXT,
            updated_at TEXT
        )''')

        # 14. telemetry_crashes (Phase 2)
        cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_crashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            crash_time TEXT,
            module TEXT,
            path TEXT,
            type TEXT
        )''')
        
        # 15. telemetry_security_center (Phase 2)
        cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_security_center (
            service TEXT,
            status TEXT,
            state TEXT
        )''')
        
        # 16. telemetry_windows_updates (Phase 2)
        cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_windows_updates (
            hotfix_id TEXT,
            description TEXT,
            installed_on TEXT,
            installed_by TEXT
        )''')
        
        # 17. telemetry_battery (Phase 2)
        cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_battery (
            cycle_count INTEGER,
            health TEXT,
            status TEXT,
            remaining_percent INTEGER
        )''')
        
        # 18. telemetry_browser_extensions (Phase 2)
        cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_browser_extensions (
            name TEXT,
            version TEXT,
            browser TEXT,
            identifier TEXT,
            status TEXT
        )''')
        
        # 19. telemetry_drivers (Phase 2)
        cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_drivers (
            name TEXT,
            description TEXT,
            provider TEXT,
            status TEXT,
            signed INTEGER
        )''')
        
        # 20. telemetry_hosts (Phase 2)
        cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_hosts (
            hostnames TEXT,
            ip_address TEXT
        )''')

        conn.commit()
        conn.close()

    def execute_query(self, query: str, params: Tuple = ()) -> List[Tuple]:
        """Executes a read query and returns results."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()
        except Exception as e:
            logging.error(f"Database read error: {e}")
            return []
        finally:
            conn.close()

    def execute_update(self, query: str, params: Tuple = ()) -> bool:
        """Executes a write query (INSERT, UPDATE, DELETE)."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return True
        except Exception as e:
            logging.error(f"Database write error: {e}")
            return False
        finally:
            conn.close()

    def execute_transaction(self, operations: List[Tuple[str, Tuple]]) -> bool:
        """Executes a list of queries as a single atomic transaction."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            for query, params in operations:
                cursor.execute(query, params)
            conn.commit()
            return True
        except Exception as e:
            logging.error(f"Transaction error: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()
            
    def upsert_advisory(self, data: Dict[str, Any]) -> bool:
        """Insert or Update an advisory record."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            # Check existence
            cursor.execute("SELECT advisory_id FROM advisories WHERE advisory_id = ?", (data['advisory_id'],))
            exists = cursor.fetchone()
            
            if exists:
                cursor.execute('''UPDATE advisories SET 
                    title=?, link=?, pub_date=?, description=?, severity=?, impact=?, 
                    cvss_vector=?, vendor=?, cve_ids=?, products=?, summary=?, 
                    html_title=?, html_description=?, html_fetched_at=?, updated_at=?
                    WHERE advisory_id=?''',
                    (data['title'], data['link'], str(data['pub_date']), data['description'], data['severity'], data['impact'],
                     data['cvss_vector'], data['vendor'], data['cve_ids'], data['products'], data['summary'],
                     data['html_title'], data['html_description'], str(data['html_fetched_at']), str(data['updated_at']),
                     data['advisory_id']))
            else:
                cursor.execute('''INSERT INTO advisories (
                    advisory_id, title, link, pub_date, description, severity, impact, 
                    cvss_vector, vendor, cve_ids, products, summary, 
                    html_title, html_description, html_fetched_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (data['advisory_id'], data['title'], data['link'], str(data['pub_date']), data['description'], data['severity'], data['impact'],
                 data['cvss_vector'], data['vendor'], data['cve_ids'], data['products'], data['summary'],
                 data['html_title'], data['html_description'], str(data['html_fetched_at']), str(data['updated_at'])))
            
            conn.commit()
            return True
        except Exception as e:
            logging.error(f"Advisory upsert error: {e}")
            return False
        finally:
            conn.close()

def get_advisory_by_link(link: str) -> Optional[Dict[str, Any]]:
    """Fetches an advisory by link link to check cache."""
    db = DatabaseManager()
    rows = db.execute_query("SELECT * FROM advisories WHERE link = ?", (link,))
    if rows:
        # Map tuple to dict based on known schema order
        r = rows[0]
        return {
            "advisory_id": r[0],
            "title": r[1],
            "link": r[2],
            "pub_date": r[3],
            "description": r[4],
            "severity": r[5],
            "impact": r[6],
            "cvss_vector": r[7],
            "vendor": r[8],
            "cve_ids": r[9],
            "products": r[10],
            "summary": r[11],
            "html_title": r[12],
            "html_description": r[13],
            "html_fetched_at": r[14],
            "updated_at": r[15]
        }
    return None

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    db = DatabaseManager()
