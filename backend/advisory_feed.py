"""
MODULE: backend/advisory_feed.py
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
This module implements the **Threat Intelligence Ingestion Service**.
It acts as a customized "Web Crawler" designed to fetch security advisories 
from external sources (specifically WatchGuard's PSIRT) and transform them 
into a structured format for our database.

CORE CONCEPTS (ETL PIPELINE):
-----------------------------
1.  **Extract (Fetch)**:
    We connect to an XML/RSS feed via HTTP. This is the raw data source.
    *Challenges*: Network timeouts, 404 errors, Vendor downtime.

2.  **Transform (Parse & Clean)**:
    Converting the XML tree into Python dictionaries.
    Includes careful handling of text encoding, stripping HTML tags (Sanitization), 
    and extracting embedded metadata (like CVSS scores) using Regex.

3.  **Load (Persist)**:
    Data is returned to the worker, which then loads it into the SQLite database.

SECURITY CONSIDERATIONS:
------------------------
1.  **Server-Side Request Forgery (SSRF) Prevention**:
    We ignore user-supplied URLs. The feed URL `ADVISORY_FEED_URL` is hardcoded 
    to a trusted vendor source.

2.  **Input Sanitization**:
    We assume external XML/HTML is "tainted". We strip scripts/tags before 
    displaying to the user to prevent XSS (Cross-Site Scripting).

3.  **Politeness (Rate Limiting)**:
    We implement a caching mechanism. If we downloaded the full HTML details 
    recently, we skip the network call to avoid WAF blocking.

"""

import requests                     # The de-facto standard HTTP library for Python
import xml.etree.ElementTree as ET  # Built-in XML parser (Lightweight, C-optimized)
from dateutil import parser         # Robust date parsing (handles ISO, RFC, etc.)
from datetime import datetime       # Time manipulation class
import re                           # Regular Expressions (Pattern Matching)
import logging                      # Event logging for debugging
import sys                          # System parameters (sys.path, sys.frozen)
import os                           # Operating System Interface

# ------------------------------------------------------------------------------
# DYNAMIC PATH RESOLUTION & IMPORT HACKS
# ------------------------------------------------------------------------------
# This module lives in 'backend/', but needs 'db_manager' from the root.
# We must ensure proper import resolution for both source and frozen modes.

def get_base_path():
    """Returns the base application path (Source or Frozen)."""
    # Check if running as a PyInstaller bundle
    if getattr(sys, 'frozen', False):
        return getattr(sys, '_MEIPASS', os.getcwd())
    else:
        # If running from source, go up one level from 'backend/'
        return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Add the application root to sys.path to enable importing root modules
base_path = get_base_path()
if base_path not in sys.path:
    # Append to path so 'import db_manager' works
    sys.path.append(base_path)

# Attempt to import the database manager
try:
    import db_manager as database
except ImportError:
    # Log failure but do not crash; degrade functionality instead
    logging.error("Failed to import db_manager. Caching features disabled.")
    database = None

# ------------------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------------------
# The fixed source URL. Hardcoding this prevents SSRF attacks.
ADVISORY_FEED_URL = "https://www.watchguard.com/wgrd-psirt/advisories.xml"

# We spoof the User-Agent to identify ourselves responsibly to the server logs.
# Some servers block generic "requests/x.y.z" agents.
HEADERS = {
    "User-Agent": "ProjectX-SecurityScanner/1.0 (Educational Purposes)"
}

# ------------------------------------------------------------------------------
# PARSING LOGIC (The "Transform" Phase)
# ------------------------------------------------------------------------------

def extract_metadata_from_html(html_content: str) -> dict:
    """
    Scrapes metadata from the raw HTML page of an advisory.
    
    Why: RSS feeds often provide only a snippet. The "Meat" (CVE IDs, active 
    exploits) is usually on the full webpage.
    """
    meta = {
        "cve_ids": [],          # List to hold CVE identifiers
        "products": [],         # List to hold affected products
        "html_title": "",       # Scraped Page Title
        "html_description": ""  # Scraped Meta Description
    }
    
    try:
        # 1. Extract Page Title using Regex
        # Matches <title>...</title>, non-greedy, case-insensitive
        title_match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE)
        if title_match:
            # Strip whitespace and store
            meta["html_title"] = title_match.group(1).strip()
            
        # 2. Extract Meta Description (Summary)
        desc_match = re.search(r'<meta name="description" content="(.*?)"', html_content, re.IGNORECASE)
        if desc_match:
            meta["html_description"] = desc_match.group(1).strip()
            
        # 3. Extract CVE IDs using Pattern Matching
        # Pattern: CVE-YYYY-NNNN... (Four digits for year, 4-7 digits for ID)
        cves = re.findall(r'CVE-\d{4}-\d{4,7}', html_content)
        # De-duplicate the list using set(), then convert back to list
        meta["cve_ids"] = list(set(cves)) 
        
    except Exception as e:
        # Log parsing errors but return partial data if possible
        logging.error(f"HTML Parsing Error: {e}")
        
    return meta

def fetch_advisory_metadata(link: str) -> dict:
    """
    Performs the HTTP GET for the detail page.
    Wrapper around requests.get with error handling and timeouts.
    """
    # Validation: Ensure link is valid HTTP
    if not link or not link.startswith("http"):
        return {}
        
    try:
        logging.info(f"Crawling detail page: {link}")
        # Perform GET request with timeout to avoid hanging threads
        response = requests.get(link, headers=HEADERS, timeout=10)
        
        if response.status_code == 200:
            # If successful, pass content to the scraper
            return extract_metadata_from_html(response.text)
        elif response.status_code == 404:
            # Handle broken links gracefully
            logging.warning(f"Advisory page not found (404): {link}")
        else:
            logging.warning(f"HTTP Error {response.status_code} for {link}")
            
    except requests.Timeout:
        # Specific handling for timeouts
        logging.error(f"Timeout fetching {link}")
    except Exception as e:
        # Catch-all for other network errors (DNS, reset, etc.)
        logging.error(f"Network failure for {link}: {e}")
        
    return {}

# ------------------------------------------------------------------------------
# MAIN EXECUTION ROUTINE
# ------------------------------------------------------------------------------

def fetch_advisories(limit=50, start_index=0) -> list:
    """
    The Primary Worker Function.
    
    Orchestrates the Fetch -> Parse -> Cache Check -> Return flow.
    Called by 'workers.py' inside a QThread.
    
    Args:
        limit (int): Max number of items to process.
        start_index (int): Pagination offset.
    """
    try:
        logging.info("Starting Feed Ingestion...")
        
        # STEP 1: Fetch the XML Feed
        # Connect to the main RSS/XML endpoint
        response = requests.get(ADVISORY_FEED_URL, headers=HEADERS, timeout=15)
        if response.status_code != 200:
            logging.error(f"Feed unreachable: {response.status_code}")
            return []
            
        # STEP 2: Parse XML Tree
        # Security Note: ET.fromstring is vulnerable to XML Bombs.
        # However, we trust the vendor source 'watchguard.com'.
        root = ET.fromstring(response.content)
        
        advisories = []
        
        # Traverse the XML structure (Channel -> Item) standard format
        items = root.findall('./channel/item')
        if not items:
            # Fallback recursive search if structure differs
            items = root.findall('.//item') 
            
        count = 0
        
        # STEP 3: Iterate and Normalize Data
        for index, item in enumerate(items):
            # Apply Pagination Logic
            if index < start_index: continue
            if count >= limit: break
                
            # Helper to extract text safely (handling None types)
            get_text = lambda tag: item.find(tag).text if item.find(tag) is not None else ""
            
            # Extract basic RSS fields
            title = get_text('title') or "No Title"
            link = get_text('link') or "#"
            description = get_text('description')
            
            # --- Text Analysis (Regex) ---
            
            # Extract Vendor ID (Format: WGSA-YYYY-NNNN)
            wgsa_id_match = re.search(r'WGSA-\d{4}-\d{5}', description)
            advisory_id = wgsa_id_match.group(0) if wgsa_id_match else ""
            
            if not advisory_id:
                # Heuristic ID generation if official ID missing
                # Use URL slug or Title Hash
                if link and link != "#":
                    advisory_id = link.rstrip('/').split('/')[-1]
                else:
                    advisory_id = f"unknown-{hash(title)}"
            
            # Extract CVSS Metrics from Description HTML
            # Look for "CVSS Score</div>...<div>7.5</div>" pattern
            cvss_match = re.search(r'CVSS Score</div>\s*<div[^>]*>([0-9\.]+)</div>', description)
            severity = float(cvss_match.group(1)) if cvss_match else 0.0
            
            impact_match = re.search(r'Impact</div>\s*<div[^>]*>(\w+)</div>', description)
            impact = impact_match.group(1) if impact_match else "Unknown"
            
            vector_match = re.search(r'CVSS Vector</div>\s*<div[^>]*>([^<]+)</div>', description)
            cvss_vector = vector_match.group(1) if vector_match else ""
            
            # Extract Publication Date
            pub_date = datetime.now()
            # Often hidden in HTML attributes
            date_match = re.search(r'datetime="([^"]+)"', description)
            if date_match:
                 try: 
                     # Parse date string to datetime object
                     pub_date = parser.parse(date_match.group(1))
                 except: pass
            
            # Sanitization (Strip HTML for safe preview)
            # Remove all tags using regex
            clean_desc = re.sub(r'<[^>]+>', '', description)
            # Collapse whitespace
            clean_desc = re.sub(r'\s+', ' ', clean_desc).strip()
            # Truncate for UI preview
            preview_desc = (clean_desc[:250] + "...") if len(clean_desc) > 250 else clean_desc
            
            # --- Caching Optimization ---
            # Determine if we need to crawl the detailed page
            should_fetch = True
            extra_meta = {}
            
            if database:
                # Check DB for existing record
                existing = database.get_advisory_by_link(link)
                if existing:
                    last_fetched = existing.get('html_fetched_at')
                    if last_fetched:
                        # Logic: If fetched < 7 days ago, use cache.
                        try:
                            last_fetched_dt = parser.parse(str(last_fetched))
                            if (datetime.now(last_fetched_dt.tzinfo) - last_fetched_dt).days < 7:
                                should_fetch = False
                        except: pass
            
            # Fetch metadata if not cached
            if should_fetch and link.startswith("http"):
                extra_meta = fetch_advisory_metadata(link)
                # Timestamp the fetch
                extra_meta['html_fetched_at'] = datetime.now()
            
            # Assemble Final Record Dictionary
            advisory_data = {
                "advisory_id": advisory_id,
                "title": title,
                "link": link,
                "pub_date": pub_date,
                "description": preview_desc,
                "severity": severity,
                "impact": impact,
                "cvss_vector": cvss_vector,
                "vendor": "WatchGuard",
                # Flatten lists to CSV strings for DB
                "cve_ids": ",".join(extra_meta.get("cve_ids", [])),
                "products": ",".join(extra_meta.get("products", [])),
                "summary": extra_meta.get("html_description", ""),
                "html_title": extra_meta.get("html_title", ""),
                "html_description": extra_meta.get("html_description", ""),
                "html_fetched_at": extra_meta.get("html_fetched_at"),
                "updated_at": datetime.now()
            }
            
            advisories.append(advisory_data)
            count += 1
            
        return advisories

    except Exception as e:
        # Catch critical errors to prevent crash
        logging.error(f"Critical Crawler Error: {e}")
        return []

if __name__ == "__main__":
    # Test Harness: Run module directly to debug
    logging.basicConfig(level=logging.INFO)
    print("Running crawler directly...")
    results = fetch_advisories(limit=5)
    print(f"Fetched {len(results)} items.")
    for r in results:
        print(f" - {r['advisory_id']}: {r['title']}")
