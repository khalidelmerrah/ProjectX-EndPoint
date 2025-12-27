"""
MODULE: db_manager.py
ProjectX Data Persistence Layer - SQLite Database Management

PURPOSE:
This module acts as the "Single Source of Truth" for all data in the application.
It handles:
1.  Defining the Relational Database Schema (20+ tables).
2.  Creating the SQLite database file (`projectx.db`) if it doesn't exist.
3.  Providing thread-safe connection factories.
4.  Executing SQL queries (Read/Write) and atomic transactions.
5.  Caching logic for security advisories to reduce network load.

ARCHITECTURAL ROLE:
-------------------
[UI/Workers] -> [DatabaseManager] -> [SQLite File]

By centralizing database access here, we prevent "Spaghetti SQL" scattered across the app.
It allows us to change the underlying database engine (e.g., to PostgreSQL) later
with minimal refactoring of the rest of the application.

SECURITY THEORY:
----------------
1.  **Parameterized Queries**: We use `?` placeholders (e.g., `WHERE id=?`) for all inputs.
    This prevents SQL Injection (SQLi) attacks where malicious strings could alter queries.
2.  **Least Privilege (File System)**: The database file is created with standard user permissions,
    avoiding the need for Admin/Root access just to run the app.

DEPENDENCIES:
-------------
- sqlite3: The built-in Python library for SQLite interaction.
- logging: For auditing database errors.
- typing: Type hints (List, Tuple, Dict) for better code readability and IDE support.
- os: To check for file existence (though mostly handled by sqlite3 itself).

AUTHOR: ProjectX Team
DATE: 2025-12-27
"""

import sqlite3
import logging
from typing import List, Tuple, Any, Optional, Dict
import os

# Constant for the database filename.
# In a real app, this might come from an environment variable or config file.
DB_NAME = "projectx.db"

class DatabaseManager:
    """
    Manages all SQLite database interactions for ProjectX.
    
    This class handles checking/creating the database schema, executing queries,
    and managing transactions. It uses SQLite for a lightweight, local storage solution.
    """
    
    def __init__(self, db_path: str = DB_NAME):
        """
        Initialize the database manager.
        
        Args:
            db_path (str): Path to the SQLite database file. Defaults to "projectx.db".
            
        Logic:
            On instantiation, we immediately attempt to initialize the schema (`_init_db`).
            This ensures that tables always exist before any query is run.
        """
        self.db_path = db_path
        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        """
        Factory method to create a new database connection.
        
        Returns:
            sqlite3.Connection: A new connection object to the file.
            
        Technical constraints of SQLite in Python:
            SQLite objects created in a thread can usually only be used in that same thread.
            We set `check_same_thread=False` to allow passing the connection around if needed,
            but best practice is to create a new connection, use it, and close it within the same scope.
        """
        # check_same_thread=False disables the thread enforcement check.
        # This is risky if not handled carefully (race conditions), but necessary for
        # some PyQt architectures where objects move between threads.
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        """
        Initializes the database schema by creating tables if they don't exist.
        
        Idempotency:
            This method uses `CREATE TABLE IF NOT EXISTS`, so it is safe to run
            multiple times (idempotent). It won't delete or overwrite existing data.
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            # -----------------------------------------------------------------
            # 1. Asset Management Tables
            # -----------------------------------------------------------------
            
            # Table: installed_software
            # Stores the "Inventory" of applications found on the OS.
            cursor.execute('''CREATE TABLE IF NOT EXISTS installed_software (
                id INTEGER PRIMARY KEY AUTOINCREMENT,   -- Unique numeric ID
                name TEXT NOT NULL,                     -- Software Name (e.g., "Google Chrome")
                version TEXT,                           -- Version string (e.g., "102.0.5005.61")
                publisher TEXT,                         -- Vendor (e.g., "Google LLC")
                install_date TEXT,                      -- ISO 8601 Date string
                icon_path TEXT,                         -- Path to cached icon file
                latest_version TEXT,                    -- Enriched data from API
                update_available INTEGER DEFAULT 0      -- Boolean flag (0 or 1)
            )''')

            # Table: software_updates
            # One-to-One relation tracking available updates.
            cursor.execute('''CREATE TABLE IF NOT EXISTS software_updates (
                software_id INTEGER,
                update_available BOOLEAN,
                latest_version TEXT,
                FOREIGN KEY(software_id) REFERENCES installed_software(id) -- Relational Link
            )''')

            # Table: startup_items
            # Persistence mechanisms checking (Malware often hides here).
            cursor.execute('''CREATE TABLE IF NOT EXISTS startup_items (
                name TEXT,
                path TEXT,      -- Binary path
                location TEXT,  -- Registry Path or Startup Folder path
                args TEXT,      -- Command line arguments
                type TEXT,      -- "Registry", "Folder", "Service"
                source TEXT,
                status TEXT,
                username TEXT
            )''')

            # -----------------------------------------------------------------
            # 2. Network & Exposure Tables
            # -----------------------------------------------------------------
            
            # Table: exposed_services
            # Stores open ports and listening services.
            cursor.execute('''CREATE TABLE IF NOT EXISTS exposed_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                port INTEGER,   
                protocol TEXT,          -- TCP or UDP
                process_name TEXT,      -- e.g., "nginx.exe"
                binary_path TEXT,
                pid INTEGER,            -- Process ID
                username TEXT,          -- Owner of the process
                risk_score INTEGER      -- Calculated 0-100
            )''')
            
            # Table: telemetry_network
            # Snapshot of active network connections at a point in time.
            cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_network (
                pid INTEGER,
                local_addr TEXT,
                remote_addr TEXT,
                state TEXT,             -- ESTABLISHED, LISTENING, TIME_WAIT
                protocol TEXT
            )''')
            
            # -----------------------------------------------------------------
            # 3. Security Intelligence Tables
            # -----------------------------------------------------------------

            # Table: cves (Common Vulnerabilities and Exposures)
            # A cache of vulnerability definitions downloaded from NIST/Mitre.
            cursor.execute('''CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,    -- e.g., "CVE-2021-44228"
                description TEXT,
                severity TEXT,              -- CRITICAL, HIGH, MEDIUM, LOW
                cvss_score REAL,            -- 0.0 to 10.0
                published_at TEXT,
                fetched_at TEXT
            )''')

            # Table: vulnerability_matches
            # The "Join Table" connecting Software <-> CVEs
            cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerability_matches (
                software_id INTEGER,
                cve_id TEXT,
                confidence INTEGER,         -- 0-100% confidence of match
                status TEXT,
                FOREIGN KEY(software_id) REFERENCES installed_software(id),
                FOREIGN KEY(cve_id) REFERENCES cves(cve_id)
            )''')
            
            # Table: advisories (Security News Feed)
            # Extracted from RSS feeds (e.g., WatchGuard, US-CERT).
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
                cve_ids TEXT,               -- Comma-separated list for simplicity (Non-normalized)
                products TEXT,
                summary TEXT,
                html_title TEXT,
                html_description TEXT,
                html_fetched_at TEXT,
                updated_at TEXT
            )''')
            
            # -----------------------------------------------------------------
            # 4. System Telemetry (Health & Stats)
            # -----------------------------------------------------------------

            # Processes Snapshot
            cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_processes (
                pid INTEGER,
                name TEXT,
                path TEXT,
                username TEXT,
                start_time TEXT
            )''')
            
            # System Services (Background Daemons)
            cursor.execute('''CREATE TABLE IF NOT EXISTS system_services (
                name TEXT,
                display_name TEXT,
                status TEXT,    -- Running, Stopped
                start_mode TEXT -- Auto, Manual, Disabled
            )''')

            # Certificates (Root CA Trust Store checks)
            cursor.execute('''CREATE TABLE IF NOT EXISTS certificates (
                subject TEXT,
                issuer TEXT,
                expiry_date TEXT,
                is_root BOOLEAN
            )''')

            # User Accounts (Identity Hygiene)
            cursor.execute('''CREATE TABLE IF NOT EXISTS user_accounts (
                username TEXT,
                uid TEXT,
                description TEXT,
                last_login TEXT
            )''')
            
            # Windows Updates History
            cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_windows_updates (
                hotfix_id TEXT,
                description TEXT,
                installed_on TEXT,
                installed_by TEXT
            )''')
            
            # System Posture (Security Checks results)
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
            
            # Drivers (Kernel modules)
            cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_drivers (
                name TEXT,
                description TEXT,
                provider TEXT,
                status TEXT,
                signed INTEGER  -- 1 if digitally signed, 0 if not
            )''')
            
            # Hosts File (DNS hijacks)
            cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_hosts (
                hostnames TEXT,
                ip_address TEXT
            )''')

            # File Integrity Monitoring (FIM) Alerts
            cursor.execute('''CREATE TABLE IF NOT EXISTS telemetry_fim_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                file_path TEXT,
                action_type TEXT,   -- Modified, Deleted, Created
                severity TEXT
            )''')
            
            # Metadata Key-Value Store (Generic)
            cursor.execute('''CREATE TABLE IF NOT EXISTS system_metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )''')

            # Commit the schema changes to disk
            conn.commit()
            
        except sqlite3.Error as e:
            logging.error(f"Database Initialization Error: {e}")
            # Re-raise or handle gracefully depending on severity
        finally:
            # Always close the connection in the scope it was created
            conn.close()

    # ---------------------------------------------------------
    # GENERIC QUERY METHODS
    # ---------------------------------------------------------

    def execute_query(self, query: str, params: Tuple = ()) -> List[Tuple]:
        """
        Executes a Read-Only Query (SELECT) and returns findings.
        
        Args:
            query (str): The SQL SELECT statement.
            params (Tuple): Values to fill into '?' placeholders.
            
        Returns:
            List[Tuple]: A list of rows, where each row is a tuple of columns.
            Example: [('Chrome', '1.0'), ('Firefox', '2.0')]
        """
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
        """
        Executes a Write Query (INSERT, UPDATE, DELETE).
        
        Args:
            query (str): The SQL action statement.
            params (Tuple): Values to bind.
            
        Returns:
            bool: True if the operation succeeded, False if it failed.
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit() # Write changes to disk
            return True
        except Exception as e:
            logging.error(f"Database write error: {e}")
            return False
        finally:
            conn.close()

    def execute_transaction(self, operations: List[Tuple[str, Tuple]]) -> bool:
        """
        Executes a batch of queries as a single Atomic Transaction.
        
        Atomicity Principle:
            "All or Nothing". If one query in the batch fails, NONE of them are applied.
            This prevents partial data states (corruption).
            
        Args:
            operations: A list of (query, params) to be executed in order.
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            # Loop through operations but do NOT commit yet
            for query, params in operations:
                cursor.execute(query, params)
            
            # Commit only after all operations succeeded
            conn.commit()
            return True
        except Exception as e:
            logging.error(f"Transaction error: {e}")
            # Rollback: Undo any changes made during this failed session
            conn.rollback()
            return False
        finally:
            conn.close()

    # ---------------------------------------------------------
    # SPECIALIZED METHODS
    # ---------------------------------------------------------

    def upsert_advisory(self, data: Dict[str, Any]) -> bool:
        """
        Insert or Update (Upsert) an advisory record.
        
        Logic:
            1. check if ID exists.
            2. If yes, UPDATE fields.
            3. If no, INSERT new record.
            
        This is separated because it has many fields and complex logic.
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            # Check existence
            cursor.execute("SELECT advisory_id FROM advisories WHERE advisory_id = ?", (data['advisory_id'],))
            exists = cursor.fetchone()
            
            # Normalize dates to strings for SQLite
            pub_date = str(data.get('pub_date', ''))
            fetched_at = str(data.get('html_fetched_at', ''))
            updated_at = str(data.get('updated_at', ''))
            
            if exists:
                # Update existing record
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
                # Insert new record
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
            logging.error(f"Advisory upsert error: {e}")
            return False
        finally:
            conn.close()

    def update_metadata(self, key: str, value: str):
        """Simple helper to set a key-value pair in system_metadata."""
        return self.execute_update("INSERT OR REPLACE INTO system_metadata (key, value) VALUES (?, ?)", (key, str(value)))

    def get_metadata(self, key: str) -> str:
        """Simple helper to get a value from system_metadata."""
        rows = self.execute_query("SELECT value FROM system_metadata WHERE key = ?", (key,))
        return rows[0][0] if rows else ""


# ---------------------------------------------------------
# MODULE UTILITIES
# ---------------------------------------------------------

def get_advisory_by_link(link: str) -> Optional[Dict[str, Any]]:
    """
    A standalone helper function to get an advisory by its URL.
    This is often used by the crawler to check if a URL has already been processed.
    
    Args:
        link (str): The unique URL of the advisory.
        
    Returns:
        Dict | None: The record as a dictionary, or None if not found.
    """
    db = DatabaseManager()
    rows = db.execute_query("SELECT * FROM advisories WHERE link = ?", (link,))
    if rows:
        # SQLite returns tuples (idx 0, idx 1...), we must map back to dict keys manually
        # This brittle coupling (index order) is a downside of raw SQL vs ORMs (like SQLAlchemy).
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

# ---------------------------------------------------------
# DIRECT EXECUTION
# ---------------------------------------------------------
if __name__ == "__main__":
    # If run as a script, just initialize the DB.
    # Useful for "setup" scripts.
    logging.basicConfig(level=logging.INFO)
    print("Initializing Database...")
    db = DatabaseManager()
    print(f"Database {DB_NAME} initialized/checked.")
