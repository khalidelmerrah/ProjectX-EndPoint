import requests
import xml.etree.ElementTree as ET
from dateutil import parser
from datetime import datetime
import re
import logging
import sys
import os

# Adjust path to import db_manager from root if running as package or script
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import db_manager as database

ADVISORY_FEED_URL = "https://www.watchguard.com/wgrd-psirt/advisories.xml"

HEADERS = {
    "User-Agent": "ProjectX-SecurityScanner/1.0"
}

def extract_metadata_from_html(html_content: str) -> dict:
    """
    Extracts additional metadata from the advisory page HTML.
    """
    meta = {
        "cve_ids": [],
        "products": [],
        "html_title": "",
        "html_description": ""
    }
    
    try:
        # Title
        title_match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE)
        if title_match:
            meta["html_title"] = title_match.group(1).strip()
            
        # Description
        desc_match = re.search(r'<meta name="description" content="(.*?)"', html_content, re.IGNORECASE)
        if desc_match:
            meta["html_description"] = desc_match.group(1).strip()
            
        # CVE IDs (Pattern: CVE-YYYY-NNNNN)
        cves = re.findall(r'CVE-\d{4}-\d{4,7}', html_content)
        meta["cve_ids"] = list(set(cves)) # Dedup
        
    except Exception as e:
        logging.error(f"Error extracting HTML metadata: {e}")
        
    return meta

def fetch_advisory_metadata(link: str) -> dict:
    """
    Fetches the HTML content of the advisory link and extracts metadata.
    """
    try:
        response = requests.get(link, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            return extract_metadata_from_html(response.text)
    except Exception as e:
        logging.error(f"Failed to fetch metadata for {link}: {e}")
    return {}

def fetch_advisories(limit=50, start_index=0) -> list:
    """
    Fetches and parses the WatchGuard advisory feed.
    Returns a list of advisory dictionaries.
    """
    try:
        logging.info(f"Fetching WatchGuard advisory feed (Limit: {limit}, Offset: {start_index})...")
        response = requests.get(ADVISORY_FEED_URL, headers=HEADERS, timeout=15)
        if response.status_code != 200:
            raise Exception(f"Failed to fetch feed: {response.status_code}")
            
        root = ET.fromstring(response.content)
        
        advisories = []
        
        # Handle standard RSS vs custom feed structures
        items = root.findall('./channel/item')
        if not items:
            items = root.findall('.//item') 
            
        count = 0
        
        for index, item in enumerate(items):
            if index < start_index:
                continue
            if count >= limit:
                break
                
            title = item.find('title').text if item.find('title') is not None else "No Title"
            link = item.find('link').text if item.find('link') is not None else "#"
            description = item.find('description').text if item.find('description') is not None else ""
            
            # ID Extraction
            wgsa_id_match = re.search(r'WGSA-\d{4}-\d{5}', description)
            advisory_id = wgsa_id_match.group(0) if wgsa_id_match else ""
            
            if not advisory_id:
                if link and link != "#":
                    advisory_id = link.rstrip('/').split('/')[-1]
                else:
                    advisory_id = f"unknown-{hash(title+str(datetime.now()))}"
            
            # Basic Metadata from XML
            cvss_match = re.search(r'CVSS Score</div>\s*<div[^>]*>([0-9\.]+)</div>', description)
            severity = float(cvss_match.group(1)) if cvss_match else 0.0
            
            impact_match = re.search(r'Impact</div>\s*<div[^>]*>(\w+)</div>', description)
            impact = impact_match.group(1) if impact_match else "Unknown"
            
            vector_match = re.search(r'CVSS Vector</div>\s*<div[^>]*>([^<]+)</div>', description)
            cvss_vector = vector_match.group(1) if vector_match else ""
            
            # Pub Date parsing
            pub_date = datetime.now()
            date_match = re.search(r'datetime="([^"]+)"', description)
            if date_match:
                 try:
                     pub_date = parser.parse(date_match.group(1))
                 except:
                     pass
            
            # Clean Description
            clean_desc = re.sub(r'<[^>]+>', '', description)
            clean_desc = re.sub(r'\s+', ' ', clean_desc).strip()
            preview_desc = clean_desc[:250] + "..." if len(clean_desc) > 250 else clean_desc
            
            # Smart Cache Check
            existing = database.get_advisory_by_link(link)
            extra_meta = {}
            should_fetch = True
            
            if existing:
                last_fetched = existing['html_fetched_at']
                if last_fetched:
                    if isinstance(last_fetched, str):
                        try:
                            last_fetched_dt = parser.parse(last_fetched)
                            if (datetime.now(last_fetched_dt.tzinfo) - last_fetched_dt).days < 7:
                                should_fetch = False
                        except:
                            should_fetch = True
            
            # Deep Fetch (HTML Scraping)
            if should_fetch and link and link != "#":
                logging.info(f"Fetching metadata for {advisory_id}...")
                extra_meta = fetch_advisory_metadata(link)
                extra_meta['html_fetched_at'] = datetime.now()
            
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
        logging.error(f"Error fetching advisories: {e}")
        return []
