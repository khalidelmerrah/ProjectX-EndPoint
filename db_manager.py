"""
MODULE: db_manager.py
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
This module acts as the **Persistence Layer** (Model) of the application.
It follows the **Repository Pattern**, abstracting the underlying SQLite database
details away from the business logic. All data modifications go through here.

ARCHITECTURAL PRINCIPLES:
-------------------------
1.  **Single Source of Truth**: 
    The `projectx.db` file allows state to persist across application restarts.
    This is critical for security tools (logging past incidents, tracking patches).

2.  **ACID Compliance**:
    We utilize SQLite's transactional nature. 
    -   **Atomicity**: Transactions (e.g., `execute_transaction`) either succeed fully or fail completely.
    -   **Consistency**: Foreign Keys (FK) ensure orphaned records (e.g., updates for deleted software) doesn't exist.
    -   **Isolation**: Each connection operates in its own scope (mostly).
    -   **Durability**: Write-Ahead Logging (WAL) ensures data survives crashes.

3.  **SQL Injection (SQLi) Prevention**:
    The code strictly enforces **Parameterized Queries** (using `?`).
    String concatenation for SQL (e.g., `SELECT * FROM users WHERE name = '` + user + `'`)
    is the #1 vulnerability in web/software history. We demonstrate the fix.

4.  **Schema Evolution**:
    The `_init_db` method uses `CREATE TABLE IF NOT EXISTS`, allowing the app to 
    "Migrate" purely by running the code. No external SQL scripts are needed for 
    basic setup.

"""

import sqlite3      # The Python standard library interface for SQLite
import logging      # Error auditing
from typing import List, Tuple, Any, Optional, Dict
import os           # File system operations

# ------------------------------------------------------------------------------
# CONSTANTS
# ------------------------------------------------------------------------------
# The database file is created in the Current Working Directory (CWD).
# In a real deployment, this should be %APPDATA% or /var/lib/projectx.
DB_NAME = "projectx.db"

# ------------------------------------------------------------------------------
# CLASS: DatabaseManager
# ------------------------------------------------------------------------------
class DatabaseManager:
    """
    Manages all SQLite database interactions for ProjectX.
    
    This class handles checking/creating the database schema, executing queries,
    and managing transactions. It acts as the "Gatekeeper" for data.
    """
    
    def __init__(self, db_path: str = DB_NAME):
        """
        Constructor.
        
        Args:
            db_path (str): Path to the SQLite database file. Defaults to "projectx.db".
            
        Design:
            We use "Lazy Initialization" partially, but we strictly ensure the 
            Schema exists immediately on startup (`_init_db`).
        """
        self.db_path = db_path
        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        """
        Factory method to create a new thread-local database connection.
        
        Threading Model:
            SQLite connections in Python are not thread-safe by default.
            We use `check_same_thread=False` to allow passing connections between
            Workers and UI (common in PyQt), but we must be careful to lock properly.
            Ideally, each thread should create its OWN connection.
        """
        try:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            # Enable Foreign Key enforcement (SQLite disables it by default!)
            conn.execute("PRAGMA foreign_keys = ON;")
            return conn
        except sqlite3.Error as e:
            logging.critical(f"Failed to connect to DB: {e}")
            raise

    def _init_db(self):
        """
        Initializes the database schema using Data Definition Language (DDL).
        
        Idempotency:
            Using `IF NOT EXISTS` ensures this function is safe to run on every boot.
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            # -----------------------------------------------------------------
            # SCHEMA GROUP 1: ASSET INVENTORY
            # -----------------------------------------------------------------
            
            # Table: installed_software
            # The core inventory table.
            cursor.execute('''CREATE TABLE IF NOT EXISTS installed_software (
                id INTEGER PRIMARY KEY AUTOINCREMENT,   -- Valid Primary Key
                name TEXT NOT NULL,                     -- App Name (e.g., "Notepad++")
                version TEXT,                           -- Version (e.g., "8.4.2")
                publisher TEXT,                         -- Vendor Signer
                install_date TEXT,                      -- ISO 8601 Date
                icon_path TEXT,                         -- Local cache path
                latest_version TEXT,                    -- Enriched data
                update_available INTEGER DEFAULT 0      -- Boolean Flag
            )''')
            
            # Table: software_updates
            # 1:1 relation mapping software to available patches.
            cursor.execute('''CREATE TABLE IF NOT EXISTS software_updates (
                software_id INTEGER,
                update_available BOOLEAN,
                latest_version TEXT,
                FOREIGN KEY(software_id) REFERENCES installed_software(id) ON DELETE CASCADE
            )''')

            # Table: startup_items
            # Security Critical: Tracks persistent binaries.
            cursor.execute('''CREATE TABLE IF NOT EXISTS startup_items (
                name TEXT,
                path TEXT,      -- Full Binary Path (Check for masquerading)
                location TEXT,  -- Registry Key or Folder
                args TEXT,      -- Malicious args (e.g., powershell -Enc ...)
                type TEXT,      
                source TEXT,
                status TEXT,
                username TEXT
            )''')

            # -----------------------------------------------------------------
            # SCHEMA GROUP 2: ATTACK SURFACE & TELEMETRY
            # -----------------------------------------------------------------
            
            # Table: exposed_services
            # Tracks open ports (Listening Sockets).
            cursor.execute('''CREATE TABLE IF NOT EXISTS exposed_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                port INTEGER,   
                protocol TEXT,          -- TCP/UDP
                process_name TEXT,      -- Associated Binary
                binary_path TEXT,
                pid INTEGER,            
                username TEXT,          -- Privilege Level (SYSTEM vs User)
                risk_score INTEGER      
            )''')
            
            # Table: telemetry_network
            # Snapshot of active connections (Netstat).
            cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_network (
                pid INTEGER,
                local_addr TEXT,
                remote_addr TEXT,       -- Potential C2 Server
                state TEXT,             -- ESTABLISHED, SYN_SENT
                protocol TEXT
            )''')

            # -----------------------------------------------------------------
            # SCHEMA GROUP 3: THREAT INTELLIGENCE (CVEs)
            # -----------------------------------------------------------------

            # Table: cves
            # Cache of NVD data.
            cursor.execute('''CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,    -- CVE-YYYY-NNNN
                description TEXT,
                severity TEXT,              -- LOW, MEDIUM, HIGH, CRITICAL
                cvss_score REAL,            -- Base Score (0-10)
                published_at TEXT,
                fetched_at TEXT
            )''')

            # Table: vulnerability_matches
            # Join Table: Software <--> CVEs
            cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerability_matches (
                software_id INTEGER,
                cve_id TEXT,
                confidence INTEGER,         -- Heuristic Confidence
                status TEXT,                -- 'Active', 'Mitigated'
                FOREIGN KEY(software_id) REFERENCES installed_software(id) ON DELETE CASCADE,
                FOREIGN KEY(cve_id) REFERENCES cves(cve_id)
            )''')
            
            # Table: advisories (Processing Queue)
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

            # -----------------------------------------------------------------
            # SCHEMA GROUP 4: FORENSICS & POSTURE
            # -----------------------------------------------------------------

            # Process List snapshot
            cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_processes (
                pid INTEGER,
                name TEXT,
                path TEXT,
                username TEXT,
                start_time TEXT
            )''')
            
            cursor.execute('''CREATE TABLE IF NOT EXISTS system_services (
                name TEXT,
                display_name TEXT,
                status TEXT,
                start_mode TEXT
            )''')
            
            # Root Certificates (MitM detection)
            cursor.execute('''CREATE TABLE IF NOT EXISTS certificates (
                subject TEXT,
                issuer TEXT,
                expiry_date TEXT,
                is_root BOOLEAN -- True if Self-Signed (Root CA)
            )''')

            cursor.execute('''CREATE TABLE IF NOT EXISTS user_accounts (
                username TEXT,
                uid TEXT,
                description TEXT,
                last_login TEXT
            )''')
            
            cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_windows_updates (
                hotfix_id TEXT,
                description TEXT,
                installed_on TEXT,
                installed_by TEXT
            )''')
            
            cursor.execute('''CREATE TABLE IF NOT EXISTS system_posture (
                check_name TEXT,
                status TEXT,
                timestamp TEXT
            )''')
            
            # Browser Extensions (Often malicious)
            cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_browser_extensions (
                name TEXT,
                version TEXT,
                browser TEXT,
                identifier TEXT,
                status TEXT
            )''')
            
            # Kernel Drivers (Rootkit checks)
            cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_drivers (
                name TEXT,
                description TEXT,
                provider TEXT,
                status TEXT,
                signed INTEGER  
            )''')
            
            cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_hosts (
                hostnames TEXT,
                ip_address TEXT
            )''')

            # FIM (File Integrity Monitoring)
            cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_fim_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                file_path TEXT,
                action_type TEXT,   -- Modified, Deleted
                severity TEXT
            )''')
            
            cursor.execute('''CREATE TABLE IF NOT EXISTS system_metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )''')

            conn.commit()
            
        except sqlite3.Error as e:
            logging.critical(f"Database Schema Init Failed: {e}")
        finally:
            conn.close()

    # ---------------------------------------------------------
    # CORE CRUD METHODS (Create, Read, Update, Delete)
    # ---------------------------------------------------------

    def execute_query(self, query: str, params: Tuple = ()) -> List[Tuple]:
        """
        Executes a Read-Only Query (SELECT).
        
        Security Note:
            `params` is passed separately to the driver. The driver escapes it.
            NEVER do: cursor.execute(f"SELECT * FROM table WHERE id={id}")
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()
        except Exception as e:
            logging.error(f"DB Read Error [{query}]: {e}")
            return []
        finally:
            conn.close()

    def execute_update(self, query: str, params: Tuple = ()) -> bool:
        """
        Executes a Write Query (INSERT, UPDATE, DELETE).
        Returns True on success.
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return True
        except Exception as e:
            logging.error(f"DB Write Error [{query}]: {e}")
            return False
        finally:
            conn.close()

    def execute_transaction(self, operations: List[Tuple[str, Tuple]]) -> bool:
        """
        Executes multiple queries atomically.
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            for query, params in operations:
                cursor.execute(query, params)
            conn.commit()
            return True
        except Exception as e:
            logging.error(f"Transaction Failed. Rolling back. {e}")
            conn.rollback() # Critical: Maintain consistency
            return False
        finally:
            conn.close()

    # ---------------------------------------------------------
    # DOMAIN SPECIFIC HELPERS
    # ---------------------------------------------------------

    def upsert_advisory(self, data: Dict[str, Any]) -> bool:
        """
        Specialized logic for the RSS Feed items.
        Needed because we scrape them repeatedly and don't want duplicates.
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT advisory_id FROM advisories WHERE advisory_id = ?", (data['advisory_id'],))
            exists = cursor.fetchone()
            
            pub_date = str(data.get('pub_date', ''))
            fetched_at = str(data.get('html_fetched_at', ''))
            updated_at = str(data.get('updated_at', ''))
            
            if exists:
                cursor.execute('''UPDATE advisories SET 
                    title=?, link=?, pub_date=?, description=?, severity=?, impact=?, 
                    cvss_vector=?, vendor=?, cve_ids=?, products=?, summary=?, 
                    html_title=?, html_description=?, html_fetched_at=?, updated_at=?
                    WHERE advisory_id=?''',
                    (data['title'], data['link'], pub_date, data['description'], data['severity'], data['impact'],
                     data['cvss_vector'], data['vendor'], data['cve_ids'], data['products'], data['summary'],
                     data['html_title'], data['html_description'], fetched_at, updated_at,
                     data['advisory_id']))
            else:
                cursor.execute('''INSERT INTO advisories (
                    advisory_id, title, link, pub_date, description, severity, impact, 
                    cvss_vector, vendor, cve_ids, products, summary, 
                    html_title, html_description, html_fetched_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (data['advisory_id'], data['title'], data['link'], pub_date, data['description'], data['severity'], data['impact'],
                 data['cvss_vector'], data['vendor'], data['cve_ids'], data['products'], data['summary'],
                 data['html_title'], data['html_description'], fetched_at, updated_at))
            
            conn.commit()
            return True
        except Exception as e:
            logging.error(f"Upsert Advisory Error: {e}")
            return False
        finally:
            conn.close()

    def update_metadata(self, key: str, value: str):
        return self.execute_update("INSERT OR REPLACE INTO system_metadata (key, value) VALUES (?, ?)", (key, str(value)))

    def get_metadata(self, key: str) -> str:
        rows = self.execute_query("SELECT value FROM system_metadata WHERE key = ?", (key,))
        return rows[0][0] if rows else ""

# ---------------------------------------------------------
# UTILITY FUNCTIONS
# ---------------------------------------------------------

def get_advisory_by_link(link: str) -> Optional[Dict[str, Any]]:
    """Helper for the crawler to check existence by URL."""
    db = DatabaseManager()
    rows = db.execute_query("SELECT * FROM advisories WHERE link = ?", (link,))
    if rows:
        r = rows[0]
        # Manual Mapping (Index -> Key)
        return {
            "advisory_id": r[0], "title": r[1], "link": r[2], "pub_date": r[3],
            "description": r[4], "severity": r[5], "impact": r[6],
            "cvss_vector": r[7], "vendor": r[8], "cve_ids": r[9],
            "products": r[10], "summary": r[11], "html_title": r[12],
            "html_description": r[13], "html_fetched_at": r[14], "updated_at": r[15]
        }
    return None

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("Initialize DB Schema...")
    db = DatabaseManager()
    print("Done.")
