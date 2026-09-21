#!/usr/bin/env python3
"""Build the AppSOFA v1 macOS application security feed."""

from __future__ import annotations
import hashlib
import json
import pathlib
import urllib.request
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "public" / "v1" / "macos_apps_data_feed.json"
CHROME_URL = "https://versionhistory.googleapis.com/v1/chrome/platforms/mac/channels/stable/versions"

def get_json(url: str) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "AppSOFA/0.5"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)

def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))

def latest_chrome() -> str:
    payload = get_json(CHROME_URL)
    versions = [entry["version"] for entry in payload.get("versions", [])]
    if not versions:
        raise RuntimeError("Google VersionHistory returned no Chrome versions")
    return max(versions, key=version_key)

def build_feed() -> dict:
    latest = latest_chrome()
    generated = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    # V0.5 deliberately does NOT claim that LatestVersion is the security floor.
    # MinimumSecureVersion stays null until a vendor-security adapter can prove it.
    return {
        "FeedVersion": "1.0",
        "Generated": generated,
        "Applications": [{
            "Name": "Google Chrome",
            "BundleID": "com.google.Chrome",
            "ApplicationPath": "/Applications/Google Chrome.app",
            "LatestVersion": latest,
            "MinimumSecureVersion": None,
            "SecurityReleases": []
        }]
    }

def main() -> None:
    feed = build_feed()
    canonical = json.dumps(feed, sort_keys=True, separators=(",", ":")).encode()
    feed["UpdateHash"] = hashlib.sha256(canonical).hexdigest()

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(feed, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT}")
    print(f"Chrome latest: {feed['Applications'][0]['LatestVersion']}")

if __name__ == "__main__":
    main()
