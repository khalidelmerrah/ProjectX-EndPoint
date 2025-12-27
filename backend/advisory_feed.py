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
    displaying to the user to prevent XSS (Cross-Site Scripting) in our own UI.

3.  **Politeness (Rate Limiting)**:
    We implement a caching mechanism (`should_fetch`). If we downloaded the full 
    HTML details for an advisory recently (< 7 days), we skip the network call. 
    This prevents us from being blocked by the vendor's WAF (Web Application Firewall).

"""

import requests                     # The de-facto standard HTTP library for Python
import xml.etree.ElementTree as ET  # Built-in XML parser (Lightweight, C-optimized)
from dateutil import parser         # Robust date parsing (handles ISO, RFC, etc.)
from datetime import datetime       # Time manipulation
import re                           # Regular Expressions (Pattern Matching)
import logging                      # Event logging
import sys                          # System parameters
import os                           # OS Interface

# ------------------------------------------------------------------------------
# DYNAMIC PATH RESOLUTION
# ------------------------------------------------------------------------------
# This module lives in 'backend/', but needs 'db_manager' from the root.
# Python doesn't look in parent directories by default. We modify sys.path.
# SECURITY NOTE: In a packaged app, relative imports are safer, but this is a 
# standard hack for standalone script execution.
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

try:
    import db_manager as database
except ImportError:
    logging.error("Failed to import db_manager. Caching features disabled.")
    database = None

# ------------------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------------------
# The fixed source URL. Hardcoding this prevents SSRF attacks.
ADVISORY_FEED_URL = "https://www.watchguard.com/wgrd-psirt/advisories.xml"

# We spoof the User-Agent to identify ourselves responsibly to the server logs.
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
    
    technique: Regex Scraping (Lightweight) vs BeautifulSoup (Heavy).
    For simple extraction, Regex is faster and adds no external dependency.
    """
    meta = {
        "cve_ids": [],
        "products": [],
        "html_title": "",
        "html_description": ""
    }
    
    try:
        # 1. Extract Page Title
        # <title>WatchGuard Firebox Auth Bypass...</title>
        title_match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE)
        if title_match:
            meta["html_title"] = title_match.group(1).strip()
            
        # 2. Extract Meta Description (Summary)
        desc_match = re.search(r'<meta name="description" content="(.*?)"', html_content, re.IGNORECASE)
        if desc_match:
            meta["html_description"] = desc_match.group(1).strip()
            
        # 3. Extract CVE IDs using Pattern Matching
        # Pattern: CVE-YYYY-NNNN... (e.g., CVE-2024-1234)
        cves = re.findall(r'CVE-\d{4}-\d{4,7}', html_content)
        # De-duplicate using set()
        meta["cve_ids"] = list(set(cves)) 
        
    except Exception as e:
        logging.error(f"HTML Parsing Error: {e}")
        
    return meta

def fetch_advisory_metadata(link: str) -> dict:
    """
    Performs the HTTP GET for the detail page.
    Wrapper around requests.get with error handling and timeouts.
    """
    if not link or not link.startswith("http"):
        return {}
        
    try:
        logging.info(f"Crawling detail page: {link}")
        response = requests.get(link, headers=HEADERS, timeout=10)
        
        if response.status_code == 200:
            return extract_metadata_from_html(response.text)
        elif response.status_code == 404:
            logging.warning(f"Advisory page not found (404): {link}")
        else:
            logging.warning(f"HTTP Error {response.status_code} for {link}")
            
    except requests.Timeout:
        logging.error(f"Timeout fetching {link}")
    except Exception as e:
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
    """
    try:
        logging.info("Starting Feed Ingestion...")
        
        # STEP 1: Fetch the XML Feed
        response = requests.get(ADVISORY_FEED_URL, headers=HEADERS, timeout=15)
        if response.status_code != 200:
            logging.error(f"Feed unreachable: {response.status_code}")
            return []
            
        # STEP 2: Parse XML Tree
        # Security Note: ET.fromstring is vulnerable to "Billion Laughs" attack 
        # (XML Bombs) if parsing untrusted user uploads. For a vendor feed, risk is low.
        root = ET.fromstring(response.content)
        
        advisories = []
        
        # Traverse the XML structure (Channel -> Item)
        items = root.findall('./channel/item')
        if not items:
            items = root.findall('.//item') # Fallback recursive search
            
        count = 0
        
        # STEP 3: Iterate and Normalize
        for index, item in enumerate(items):
            # Pagination
            if index < start_index: continue
            if count >= limit: break
                
            # Safe Extraction (Handle missing tags gracefully)
            get_text = lambda tag: item.find(tag).text if item.find(tag) is not None else ""
            
            title = get_text('title') or "No Title"
            link = get_text('link') or "#"
            description = get_text('description')
            
            # --- Text Analysis (Regex) ---
            
            # Extract Vendor ID (Format: WGSA-YYYY-NNNN)
            wgsa_id_match = re.search(r'WGSA-\d{4}-\d{5}', description)
            advisory_id = wgsa_id_match.group(0) if wgsa_id_match else ""
            
            if not advisory_id:
                # Heuristic ID generation if official ID missing
                if link and link != "#":
                    advisory_id = link.rstrip('/').split('/')[-1]
                else:
                    advisory_id = f"unknown-{hash(title)}"
            
            # Extract CVSS Metrics
            cvss_match = re.search(r'CVSS Score</div>\s*<div[^>]*>([0-9\.]+)</div>', description)
            severity = float(cvss_match.group(1)) if cvss_match else 0.0
            
            impact_match = re.search(r'Impact</div>\s*<div[^>]*>(\w+)</div>', description)
            impact = impact_match.group(1) if impact_match else "Unknown"
            
            vector_match = re.search(r'CVSS Vector</div>\s*<div[^>]*>([^<]+)</div>', description)
            cvss_vector = vector_match.group(1) if vector_match else ""
            
            # Extract Date
            pub_date = datetime.now()
            date_match = re.search(r'datetime="([^"]+)"', description)
            if date_match:
                 try: pub_date = parser.parse(date_match.group(1))
                 except: pass
            
            # Sanitization (Strip HTML for safe preview)
            clean_desc = re.sub(r'<[^>]+>', '', description)
            clean_desc = re.sub(r'\s+', ' ', clean_desc).strip()
            preview_desc = (clean_desc[:250] + "...") if len(clean_desc) > 250 else clean_desc
            
            # --- Caching Optimization ---
            # Do we need to crawl the full page?
            should_fetch = True
            extra_meta = {}
            
            if database:
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
            
            if should_fetch and link.startswith("http"):
                extra_meta = fetch_advisory_metadata(link)
                extra_meta['html_fetched_at'] = datetime.now()
            
            # Assemble Record
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
        logging.error(f"Critical Crawler Error: {e}")
        return []

if __name__ == "__main__":
    # Test Harness
    logging.basicConfig(level=logging.INFO)
    print("Running crawler directly...")
    results = fetch_advisories(limit=5)
    print(f"Fetched {len(results)} items.")
    for r in results:
        print(f" - {r['advisory_id']}: {r['title']}")
