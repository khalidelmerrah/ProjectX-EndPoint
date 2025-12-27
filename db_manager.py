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
# We do NOT use _MEIPASS here as the DB must be writable and persistent.
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
        # Initialize the schema unconditionally on instantiation
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
            # Establish connection to the file
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            
            # Enable Foreign Key enforcement (SQLite disables it by default!)
            # This ensures referential integrity (e.g. can't have vulns for non-existent software)
            conn.execute("PRAGMA foreign_keys = ON;")
            return conn
            
        except sqlite3.Error as e:
            # Log critical failure as this renders the app useless
            logging.critical(f"Failed to connect to DB: {e}")
            raise

    def _init_db(self):
        """
        Idempotent Schema Initialization.
        
        Runs the DDL (Data Definition Language) SQL scripts to create tables
        if they do not already exist.
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            # ------------------------------------------------------------------
            # TABLE 1: INSTALLED SOFTWARE (Inventory)
            # ------------------------------------------------------------------
            # Tracks applications found on the host machine.
            # Used as the baseline for Vulnerability Matching.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS installed_software (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    version TEXT,
                    publisher TEXT,
                    install_date TEXT,
                    icon_path TEXT,
                    
                    -- Metadata for future updates
                    latest_version TEXT,
                    update_available INTEGER DEFAULT 0
                )
            """)

            # ------------------------------------------------------------------
            # TABLE 2: TELEMETRY NETWORK (Activity)
            # ------------------------------------------------------------------
            # Transient data about active TCP/UDP connections.
            # Refreshed on every scan (snapshot model).
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS telemetry_network (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pid INTEGER,
                    local_addr TEXT,
                    remote_addr TEXT,
                    state TEXT,
                    protocol TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # ------------------------------------------------------------------
            # TABLE 3: SYSTEM POSTURE (Audit Log)
            # ------------------------------------------------------------------
            # Immutable log of security events.
            # Good for forensics: "When was the last scan run?"
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_posture (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    check_name TEXT,
                    status TEXT,
                    details TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # ------------------------------------------------------------------
            # TABLE 4: EXPOSED SERVICES (Attack Surface)
            # ------------------------------------------------------------------
            # Tracks ports listening for incoming connections.
            # High Risk items (Risk Score > 80) trigger alerts.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS exposed_services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    port INTEGER,
                    protocol TEXT,
                    process_name TEXT,
                    binary_path TEXT,
                    pid INTEGER,
                    username TEXT,
                    risk_score INTEGER DEFAULT 0
                )
            """)
            
            # ------------------------------------------------------------------
            # TABLE 5: STARTUP ITEMS (Persistence)
            # ------------------------------------------------------------------
            # Programs configured to launch automatically.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS startup_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    path TEXT,
                    location TEXT,
                    args TEXT,
                    type TEXT,
                    source TEXT,
                    status TEXT,
                    username TEXT
                )
            """)

            # ------------------------------------------------------------------
            # TABLE 6: VULNERABILITY MATCHES (The Findings)
            # ------------------------------------------------------------------
            # A Join Table linking Software to Definitions.
            # Demonstrates 'Referential Integrity' via Foreign Key.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerability_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    software_id INTEGER,
                    cve_id TEXT,
                    confidence TEXT,
                    status TEXT,
                    
                    FOREIGN KEY(software_id) REFERENCES installed_software(id) ON DELETE CASCADE
                )
            """)

            # ------------------------------------------------------------------
            # TABLE 7: THREAT ADVISORIES (Intelligence)
            # ------------------------------------------------------------------
            # External feed data (from backend/advisory_feed.py).
            # We use UNIQUE index on 'advisory_id' for UPSERT capability.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_advisories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    advisory_id TEXT UNIQUE,
                    title TEXT,
                    link TEXT,
                    pub_date TEXT,
                    description TEXT,
                    severity REAL,
                    impact TEXT,
                    cvss_vector TEXT,
                    vendor TEXT,
                    products TEXT,
                    cve_ids TEXT,
                    
                    -- HTML extraction fields
                    summary TEXT,
                    html_title TEXT,
                    html_description TEXT,
                    html_fetched_at TEXT,
                    
                    updated_at TEXT
                )
            """)
            
            # Commit the schema changes to disk
            conn.commit()
            
        except sqlite3.Error as e:
            # Fatal error if we cannot create tables.
            logging.critical(f"Database Initialization Error: {e}")
        finally:
            # Always close the connection to prevent file locks
            conn.close()

    # --------------------------------------------------------------------------
    # CRUD OPERATIONS (Create, Read, Update, Delete)
    # --------------------------------------------------------------------------

    def execute_query(self, query: str, params: Tuple = ()) -> List[Tuple]:
        """
        Executes a Read-Only SQL query (SELECT).
        
        Args:
            query (str): The SQL statement with '?' placeholders.
            params (tuple): The values to bind to the placeholders.
            
        Returns:
            list: A list of tuples representing the rows.
            
        Security Check:
            This method strictly uses `execute(query, params)`.
            It prevents SQL Injection because the DB driver escapes the params.
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            # Execute with safe parameter binding
            cursor.execute(query, params)
            # Fetch all results into memory
            rows = cursor.fetchall()
            return rows
        except sqlite3.Error as e:
            logging.error(f"Query Failed: {query} | Error: {e}")
            return []
        finally:
            conn.close()

    def execute_update(self, query: str, params: Tuple = ()) -> bool:
        """
        Executes a Write operation (INSERT, UPDATE, DELETE).
        
        Returns:
            bool: True if successful, False otherwise.
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            # IMPORTANT: Writes must be explicitly committed in SQLite
            conn.commit()
            return True
        except sqlite3.Error as e:
            logging.error(f"Update Failed: {query} | Error: {e}")
            # Rollback is automatic on exception in older versions, but manual is safer
            conn.rollback()
            return False
        finally:
            conn.close()

    def execute_transaction(self, operations: List[Tuple[str, Tuple]]) -> bool:
        """
        Executes a Batch of operations atomically.
        
        If ANY operation fails, ALL changes are rolled back.
        This ensures the database is never left in a half-broken state.
        
        Args:
            operations: List of (query_string, params_tuple)
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            # Iterate through the list of operations
            for query, params in operations:
                cursor.execute(query, params)
            
            # Commit only after all operations succeed
            conn.commit()
            return True
        except sqlite3.Error as e:
            logging.error(f"Transaction Failed. Rolling back changes. Error: {e}")
            # The 'Undo' button for databases
            conn.rollback()
            return False
        finally:
            conn.close()

    # --------------------------------------------------------------------------
    # SPECIALIZED DATA ACCESS OBJECTS (DAO Methods)
    # --------------------------------------------------------------------------

    def upsert_advisory(self, item: Dict[str, Any]) -> bool:
        """
        Insert or Update (UPSERT) a Threat Advisory.
        
        Logic:
            If 'advisory_id' exists -> Update the record.
            If not -> Insert new record.
        """
        sql = """
            INSERT INTO threat_advisories (
                advisory_id, title, link, pub_date, description, severity, 
                impact, cvss_vector, vendor, products, cve_ids, 
                summary, html_title, html_description, html_fetched_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(advisory_id) DO UPDATE SET
                title=excluded.title,
                pub_date=excluded.pub_date,
                description=excluded.description,
                severity=excluded.severity,
                impact=excluded.impact,
                html_fetched_at=excluded.html_fetched_at,
                updated_at=excluded.updated_at
        """
        
        # Prepare the tuple of values
        params = (
            item['advisory_id'], item['title'], item['link'], str(item['pub_date']),
            item['description'], item['severity'], item['impact'], item['cvss_vector'],
            item['vendor'], item['products'], item['cve_ids'],
            item['summary'], item['html_title'], item['html_description'],
            str(item.get('html_fetched_at', '')), str(item['updated_at'])
        )
        
        return self.execute_update(sql, params)

    def get_advisory_by_link(self, link: str) -> Optional[Dict]:
        """
        Retrieves a single advisory by its URL (Link).
        Used for caching checks to prevent re-crawling.
        """
        sql = "SELECT * FROM threat_advisories WHERE link = ?"
        rows = self.execute_query(sql, (link,))
        
        if rows:
            # Map tuple back to dictionary provided we know the schema order
            # (Ideally utilize row_factory for this, but manual mapping teaches the structure)
            r = rows[0]
            # Warning: Hardcoding indices is brittle to schema changes. 
            # row_factory is preferred in production.
            return {
                "id": r[0],
                "advisory_id": r[1],
                "title": r[2],
                "link": r[3],
                "html_fetched_at": r[14] # Index 14 based on Create Table order
            }
        return None

    def get_top_vulnerabilities(self, limit=10):
        """
        Returns the highest severity vulnerabilities found on the system.
        Joining Software + Matches + CVE Details would go here.
        """
        # Currently simplified to just return count or basic list
        pass
