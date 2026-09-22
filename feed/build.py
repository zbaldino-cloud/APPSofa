#!/usr/bin/env python3
import hashlib, json, pathlib, sys, urllib.request
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUTPUT = ROOT / "public" / "v1" / "macos_apps_data_feed.json"
CHROME_URL = "https://versionhistory.googleapis.com/v1/chrome/platforms/mac/channels/stable/versions"

from feed.sources.chrome_security import fetch_latest_mac_security_release
from feed.sources.firefox_security import fetch_latest_firefox_security_release, latest_firefox
from feed.sources.cisa_kev import fetch_kev_ids

def get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "AppSOFA/0.9"})
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)

def version_key(v):
    return tuple(int(p) for p in v.split("."))

def latest_chrome():
    versions = [v["version"] for v in get_json(CHROME_URL).get("versions", [])]
    if not versions:
        raise RuntimeError("Google VersionHistory returned no Chrome versions")
    return max(versions, key=version_key)

def enrich_security(security, kev_ids):
    for cve in security["CVEs"]:
        cve["CISAKEV"] = cve["CVE"].upper() in kev_ids

    severities = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    security["HighestSeverity"] = max(
        (c["Severity"] for c in security["CVEs"]),
        key=lambda s: severities.get(s, 0),
        default="Unknown",
    )
    security["CISAKEVCount"] = sum(1 for c in security["CVEs"] if c["CISAKEV"])
    return security

def build_feed():
    kev_ids = fetch_kev_ids()

    chrome_security = enrich_security(fetch_latest_mac_security_release(), kev_ids)
    firefox_security = enrich_security(fetch_latest_firefox_security_release(), kev_ids)

    applications = [
        {
            "Name": "Google Chrome",
            "BundleID": "com.google.Chrome",
            "ApplicationPath": "/Applications/Google Chrome.app",
            "LatestVersion": latest_chrome(),
            "MinimumSecureVersion": chrome_security["Version"],
            "SecurityReleases": [chrome_security],
        },
        {
            "Name": "Mozilla Firefox",
            "BundleID": "org.mozilla.firefox",
            "ApplicationPath": "/Applications/Firefox.app",
            "LatestVersion": latest_firefox(),
            "MinimumSecureVersion": firefox_security["Version"],
            "SecurityReleases": [firefox_security],
        },
    ]

    return {
        "FeedVersion": "1.0",
        "Generated": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "Applications": applications,
    }

def main():
    feed = build_feed()
    canonical = json.dumps(feed, sort_keys=True, separators=(",", ":")).encode()
    feed["UpdateHash"] = hashlib.sha256(canonical).hexdigest()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(feed, indent=2) + "\n", encoding="utf-8")

    for app in feed["Applications"]:
        sec = app["SecurityReleases"][0]
        print(f'{app["Name"]} latest:', app["LatestVersion"])
        print(f'{app["Name"]} minimum secure:', app["MinimumSecureVersion"])
        print("Security CVEs:", len(sec["CVEs"]))
        print("CISA KEV:", sec["CISAKEVCount"])

if __name__ == "__main__":
    main()
