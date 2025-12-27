import sqlite3
import logging

try:
    conn = sqlite3.connect('projectx.db')
    cursor = conn.cursor()
    
    query = "SELECT count(*) FROM vulnerability_matches m JOIN cves c ON m.cve_id = c.cve_id WHERE c.cvss_score >= 9.0 AND m.status='Detected'"
    cursor.execute(query)
    print(f"Result: {cursor.fetchall()}")
    
    conn.close()
except Exception as e:
    print(f"Error: {e}")
