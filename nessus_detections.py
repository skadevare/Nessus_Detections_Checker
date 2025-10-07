#!/usr/bin/env python3
"""
tenable_cve_scraper.py
Scrape Tenable CVE plugin listings (HTML table rows) for a given CVE.

Example:
    python tenable_cve_scraper.py CVE-2025-20828
"""

import sys
import json
import time
import logging
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


def fetch_html(url):
    """Fetch page HTML with retries and polite delays."""
    for attempt in range(3):
        try:
            r = requests.get(url, headers=HEADERS, timeout=20)
            if r.status_code == 403:
                logging.warning("Access denied (HTTP 403) for %s", url)
            r.raise_for_status()
            return r.text
        except requests.RequestException as e:
            logging.warning("Attempt %d failed: %s", attempt + 1, e)
            time.sleep(2 + attempt)
    raise RuntimeError(f"Failed to fetch {url} after retries.")


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
    html = fetch_html(target)
    plugins = parse_plugins_from_table(html, base_url)
    return plugins


def main():
    if len(sys.argv) < 2:
        print("Usage: python tenable_cve_scraper.py CVE-YYYY-NNNNN")
        sys.exit(1)

    cve_id = sys.argv[1].strip().upper()
    plugins = scrape_tenable_cve(cve_id)

    if not plugins:
        print(f"No plugins found for {cve_id}.")
        sys.exit(0)

    print(f"Found {len(plugins)} plugin(s) for {cve_id}:\n")
    for p in plugins:
        print(f"🧩 Plugin ID: {p['id']}")
        print(f"   Name: {p['name']}")
        print(f"   Family: {p['family']}")
        print(f"   Severity: {p['severity']}")
        print(f"   URL: {p['url']}\n")

    # Also print JSON output at the end (optional)
    #print("JSON output:\n")
    #print(json.dumps(plugins, indent=2))


if __name__ == "__main__":
    main()
