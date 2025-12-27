"""
MODULE: backend/advisory_feed.py
ProjectX Backend Service - Security Advisory Crawler & Parser

PURPOSE:
This module is responsible for ingesting external threat intelligence.
It fetches, parses, and normalizes security advisories from XML/RSS feeds
(specifically WatchGuard's PSIRT feed) and HTML pages.

ARCHITECTURAL ROLE:
-------------------
[AdvisoryWorker] -> [advisory_feed.py] -> [WatchGuard.com]
                                       -> [DatabaseManager]

This script acts like a "Micro-Crawler". It is called by the `AdvisoryWorker`
in a background thread to prevent network latency from blocking the UI.
It transforms raw XML/HTML into structured dictionaries that match the 
`advisories` table in our SQLite database.

SECURITY THEORY:
----------------
1.  **Input Sanitation**: External XML is dangerous (XXE attacks). We use `ElementTree` 
    which is relatively safe, but we must also sanitize the text content we extract
    using Regex to remove HTML tags before display.
2.  **Rate Limiting (Politeness)**: We implement "Smart Caching" (checking `html_fetched_at`)
    to avoid hammering the vendor's servers. We only re-fetch full HTML if our cache 
    is older than 7 days.

DEPENDENCIES:
-------------
- requests: The de-facto standard HTTP library for Python.
- xml.etree.ElementTree: Built-in XML parser.
- dateutil: Sophisticated date string parsing.
- re: Regular Expressions for extracting patterns (CVEs, IDs).
- db_manager: To check existing records for the cache logic.

AUTHOR: ProjectX Team
DATE: 2025-12-27
"""

import requests     # HTTP Client
import xml.etree.ElementTree as ET # XML Parser
from dateutil import parser # Date Parser
from datetime import datetime # Time manipulation
import re           # Regex
import logging      # Logging
import sys          # System specific parameters
import os           # OS Interface

# ---------------------------------------------------------
# PATH SETUP
# ---------------------------------------------------------
# Because this file is inside 'backend/', we need to help Python find 'db_manager.py'
# which is in the parent directory.
# We append the parent directory to sys.path at runtime.
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import db_manager as database

# ---------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------
# The source URL for the XML feed.
ADVISORY_FEED_URL = "https://www.watchguard.com/wgrd-psirt/advisories.xml"

# HTTP Headers to look like a legitimate client and avoid being blocked.
HEADERS = {
    "User-Agent": "ProjectX-SecurityScanner/1.0"
}

# ---------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------

def extract_metadata_from_html(html_content: str) -> dict:
    """
    Parses raw HTML content to extract metadata that isn't present in the XML feed.
    
    Why this is needed:
        RSS feeds often contain only a summary. The full details, like the specific
        list of CVE IDs or affected products, are often only on the web page itself.
        We use Regex parsing (a simple form of scraping) to get this data.
    
    Args:
        html_content (str): Raw HTML string from the website.
        
    Returns:
        dict: A dictionary containing extracted 'html_title', 'html_description', and 'cve_ids'.
    """
    meta = {
        "cve_ids": [],
        "products": [],
        "html_title": "",
        "html_description": ""
    }
    
    try:
        # Extract Title: <title>Text</title>
        # re.IGNORECASE helps match <TITLE> or <title>
        title_match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE)
        if title_match:
            meta["html_title"] = title_match.group(1).strip()
            
        # Extract Description Meta Tag: <meta name="description" content="...">
        desc_match = re.search(r'<meta name="description" content="(.*?)"', html_content, re.IGNORECASE)
        if desc_match:
            meta["html_description"] = desc_match.group(1).strip()
            
        # Extract CVE IDs: Pattern CVE-YYYY-NNNNN
        # \d{4} matches the year (2024), \d{4,7} matches the sequence number (4 to 7 digits)
        cves = re.findall(r'CVE-\d{4}-\d{4,7}', html_content)
        # Use set() to remove duplicates, then convert back to list
        meta["cve_ids"] = list(set(cves)) 
        
    except Exception as e:
        logging.error(f"Error extracting HTML metadata: {e}")
        
    return meta

def fetch_advisory_metadata(link: str) -> dict:
    """
    Fetches the HTML content of the advisory detail page.
    
    This function performs the HTTP GET request.
    
    Args:
        link (str): URL to the advisory page.
        
    Returns:
        dict: Extracted metadata or empty dict on failure.
    """
    try:
        # timeout=10 ensures we don't hang forever if the site is down
        response = requests.get(link, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            return extract_metadata_from_html(response.text)
    except Exception as e:
        logging.error(f"Failed to fetch metadata for {link}: {e}")
    return {}

# ---------------------------------------------------------
# MAIN LOGIC
# ---------------------------------------------------------

def fetch_advisories(limit=50, start_index=0) -> list:
    """
    Main function to fetch and process the security directory.
    
    Workflow:
    1. GET the XML feed.
    2. Parse XML into Python objects.
    3. Loop through items (Advisories).
    4. Normalize data (dates, IDs).
    5. Check Database Cache (Should we re-scrape details?).
    6. Return list of clean dictionaries.
    
    Args:
        limit (int): Max number of advisories to process (pagination limit).
        start_index (int): Offset for pagination (skip first N items).
        
    Returns:
        list: A list of dicts ready for insertion into the database.
    """
    try:
        logging.info(f"Fetching WatchGuard advisory feed (Limit: {limit}, Offset: {start_index})...")
        
        # 1. Fetch the XML
        response = requests.get(ADVISORY_FEED_URL, headers=HEADERS, timeout=15)
        if response.status_code != 200:
            raise Exception(f"Failed to fetch feed: {response.status_code}")
            
        # 2. Parse XML
        # ElementTree converts the raw bytes into a navigable tree structure
        root = ET.fromstring(response.content)
        
        advisories = []
        
        # XPath Selector: Find all <item> tags inside <channel>
        # This is standard RSS 2.0 format.
        items = root.findall('./channel/item')
        if not items:
            # Fallback: Find any <item> tag anywhere in the tree
            items = root.findall('.//item') 
            
        count = 0
        
        # 3. Iterate through Items
        for index, item in enumerate(items):
            # Pagination Handling
            if index < start_index:
                continue
            if count >= limit:
                break
                
            # XML Data Extraction using Safe Access (ternary operators)
            # "item.find('title').text" gets the content inside <title>...</title>
            title = item.find('title').text if item.find('title') is not None else "No Title"
            link = item.find('link').text if item.find('link') is not None else "#"
            description = item.find('description').text if item.find('description') is not None else ""
            
            # -----------------------------------------------------
            # ID Normalization Logic
            # -----------------------------------------------------
            # We try to extract a formal ID like "WGSA-2024-12345" from the text.
            wgsa_id_match = re.search(r'WGSA-\d{4}-\d{5}', description)
            advisory_id = wgsa_id_match.group(0) if wgsa_id_match else ""
            
            if not advisory_id:
                # Fallback: Use the URL slug as the ID
                if link and link != "#":
                    advisory_id = link.rstrip('/').split('/')[-1]
                else:
                    # Last Resort: Generate a unique ID hash based on title + time
                    advisory_id = f"unknown-{hash(title+str(datetime.now()))}"
            
            # -----------------------------------------------------
            # Regex Extraction of Embedded Data
            # -----------------------------------------------------
            # The feed description contains HTML with specific labels like "CVSS Score: 9.8".
            # We use Regex capture groups "()" to extract just the number.
            
            # CVSS Score (e.g., 9.8)
            cvss_match = re.search(r'CVSS Score</div>\s*<div[^>]*>([0-9\.]+)</div>', description)
            severity = float(cvss_match.group(1)) if cvss_match else 0.0
            
            # Impact (e.g., "Critical")
            impact_match = re.search(r'Impact</div>\s*<div[^>]*>(\w+)</div>', description)
            impact = impact_match.group(1) if impact_match else "Unknown"
            
            # CVSS Vector (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
            vector_match = re.search(r'CVSS Vector</div>\s*<div[^>]*>([^<]+)</div>', description)
            cvss_vector = vector_match.group(1) if vector_match else ""
            
            # -----------------------------------------------------
            # Date Parsing
            # -----------------------------------------------------
            pub_date = datetime.now()
            # Look for datetime attribute in HTML tag
            date_match = re.search(r'datetime="([^"]+)"', description)
            if date_match:
                 try:
                     pub_date = parser.parse(date_match.group(1))
                 except:
                     pass
            
            # -----------------------------------------------------
            # Text Cleaning
            # -----------------------------------------------------
            # Remove all HTML tags to get plain text for the preview
            clean_desc = re.sub(r'<[^>]+>', '', description)
            # Collapse multiple spaces into one
            clean_desc = re.sub(r'\s+', ' ', clean_desc).strip()
            # Truncate to 250 characters
            preview_desc = clean_desc[:250] + "..." if len(clean_desc) > 250 else clean_desc
            
            # -----------------------------------------------------
            # CACHE LOGIC (Smart Fetching)
            # -----------------------------------------------------
            # We check if we already have this advisory in the DB.
            existing = database.get_advisory_by_link(link)
            extra_meta = {}
            should_fetch = True
            
            if existing:
                last_fetched = existing.get('html_fetched_at')
                if last_fetched:
                    if isinstance(last_fetched, str):
                        try:
                            # Parse string back to datetime
                            last_fetched_dt = parser.parse(last_fetched)
                            # Logic: If fetched less than 7 days ago, don't re-fetch
                            if (datetime.now(last_fetched_dt.tzinfo) - last_fetched_dt).days < 7:
                                should_fetch = False
                        except:
                            should_fetch = True
            
            # If we decided to fetch (New record OR Old cache)
            if should_fetch and link and link != "#":
                logging.info(f"Fetching metadata for {advisory_id}...")
                extra_meta = fetch_advisory_metadata(link)
                extra_meta['html_fetched_at'] = datetime.now()
            
            # -----------------------------------------------------
            # DATA ASSEMBLY
            # -----------------------------------------------------
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
                # .get returns empty list/string if key missing, preventing KeyErrors
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
        # Catch-all exception handler to prevent the crash of the worker thread
        logging.error(f"Error fetching advisories: {e}")
        return []
