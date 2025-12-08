#!/usr/bin/env python3
"""

Tenable CVE plugin listings (HTML table rows) for a given CVE.

Example:
    python nessus_detections.py CVE-2025-20828
    python nessus_detections.py CVE-2025-20828 --output json
"""

import sys
import json
import time
import logging
import argparse
import requests
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) "
        "Gecko/20100101 Firefox/128.0"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Referer": "https://www.tenable.com/",
}

def parse_plugins_from_table(html, base_url):
    """Parse plugin rows from Tenable CVE table HTML."""
    soup = BeautifulSoup(html, "html.parser")
    results = []

    rows = soup.find_all("tr")
    for row in rows:
        cols = row.find_all("td")
        if len(cols) < 5:
            continue  # skip malformed rows

        # Column 1: Plugin ID and link
        a_tag = cols[0].find("a", href=True)
        if not a_tag:
            continue
        plugin_id = a_tag.text.strip()
        plugin_url = a_tag["href"]

        # Column 2: Plugin name/description
        name = cols[1].get_text(strip=True)

        # Column 4: Family name
        family_link = cols[3].find("a")
        family = family_link.get_text(strip=True) if family_link else "N/A"

        # Column 5: Severity badge
        sev_span = cols[4].find("span", class_="badge")
        severity = sev_span.get_text(strip=True) if sev_span else "unknown"

        results.append(
            {
                "id": plugin_id,
                "name": name,
                "family": family,
                "severity": severity,
                "url": plugin_url if plugin_url.startswith("http") else base_url + plugin_url,
            }
        )
    return results


def scrape_tenable_cve(cve_id):
    """Scrape plugin list from Tenable's CVE page."""
    base_url = "https://www.tenable.com"
    target = f"{base_url}/cve/{cve_id}/plugins"
    logging.info("Fetching plugin list for %s", cve_id)
    html =  requests.get(target, headers=HEADERS, timeout=20)
    if html.status_code != 200:
        raise requests.HTTPError(f"HTTP Error: {html.status_code} for url: {target}", response=html.text)
    
    plugins = parse_plugins_from_table(html.text, base_url)
    return plugins


def main():
    parser = argparse.ArgumentParser(
        description="Tenable CVE plugin listings (HTML table rows) for a given CVE.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python nessus_detections.py CVE-2025-20828\n  python nessus_detections.py CVE-2025-20828 --output json"
    )
    parser.add_argument(
        "cve_id",
        help="CVE identifier (e.g., CVE-2025-20828)"
    )
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format: 'text' for human-readable format (default), 'json' for JSON format"
    )
    
    args = parser.parse_args()
    
    cve_id = args.cve_id.strip().upper()
    
    try:
        plugins = scrape_tenable_cve(cve_id)
    except requests.HTTPError as e:
        print(f"Problem fetching CVE {cve_id} from Tenable's website: {e}")
        sys.exit(0)
    
    if not plugins:
        if args.output == "json":
            print(json.dumps({"cve": cve_id, "plugins": []}, indent=2))
        else:
            print(f"No plugins found for {cve_id}.")
        sys.exit(0)

    if args.output == "json":
        output_data = {
            "cve": cve_id,
            "count": len(plugins),
            "plugins": plugins
        }
        print(json.dumps(output_data, indent=2))
    else:
        print(f"Found {len(plugins)} plugin(s) for {cve_id}:\n")
        for p in plugins:
            print(f"🧩 Plugin ID: {p['id']}")
            print(f"   Name: {p['name']}")
            print(f"   Family: {p['family']}")
            print(f"   Severity: {p['severity']}")
            print(f"   URL: {p['url']}\n")


if __name__ == "__main__":
    main()
