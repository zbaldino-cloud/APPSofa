"""CISA Known Exploited Vulnerabilities source."""
import json
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_kev_ids():
    req = urllib.request.Request(KEV_URL, headers={"User-Agent": "AppSOFA/0.6"})
    with urllib.request.urlopen(req, timeout=30) as response:
        payload = json.load(response)
    return {item["cveID"].upper() for item in payload.get("vulnerabilities", []) if item.get("cveID")}
