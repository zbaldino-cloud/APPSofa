"""Chrome desktop security-release source.

Uses Blogger's JSON feed for Chrome Releases and extracts Mac Stable
security releases, CVE IDs, and Google's severity labels.
"""
import html
import json
import re
import urllib.request

FEED_URL = "https://chromereleases.googleblog.com/feeds/posts/default?alt=json&max-results=100"
VERSION_RE = re.compile(
    r"(\d+\.\d+\.\d+\.\d+)(?:/\.(\d+))?\s+(?:for\s+)?Windows(?:\s+and|/)\s+Mac",
    re.I,
)
CVE_RE = re.compile(r"\b(Critical|High|Medium|Low)\s+(CVE-\d{4}-\d+)\b", re.I)

def _get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "AppSOFA/0.6"})
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)

def _version_key(v):
    return tuple(int(p) for p in v.split("."))

def _plain_text(value):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html.unescape(value))).strip()

def fetch_latest_mac_security_release():
    payload = _get_json(FEED_URL)
    entries = payload.get("feed", {}).get("entry", [])
    candidates = []

    for entry in entries:
        title = entry.get("title", {}).get("$t", "")
        if title.strip().lower() != "stable channel update for desktop":
            continue

        labels = {c.get("term", "").lower() for c in entry.get("category", [])}
        if "stable updates" not in labels:
            continue

        raw = entry.get("content", {}).get("$t") or entry.get("summary", {}).get("$t", "")
        text = _plain_text(raw)

        version_match = VERSION_RE.search(text)
        if not version_match:
            continue

        base, alternate_patch = version_match.groups()
        versions = [base]
        if alternate_patch:
            parts = base.split(".")
            parts[-1] = alternate_patch
            versions.append(".".join(parts))

        cves = []
        seen = set()
        for severity, cve_id in CVE_RE.findall(text):
            cve_id = cve_id.upper()
            if cve_id not in seen:
                cves.append({"CVE": cve_id, "Severity": severity.title()})
                seen.add(cve_id)

        if not cves:
            continue

        published = entry.get("published", {}).get("$t", "")
        source_url = next(
            (link.get("href") for link in entry.get("link", [])
             if link.get("rel") == "alternate"),
            None,
        )

        candidates.append({
            "Version": min(versions, key=_version_key),
            "MacVersions": sorted(versions, key=_version_key),
            "ReleaseDate": published[:10],
            "CVEs": cves,
            "SourceURL": source_url,
        })

    if not candidates:
        raise RuntimeError(
            "No Chrome Mac Stable security release found in the latest 100 Chrome Releases posts"
        )

    # Use publication time/version ordering rather than the newest Chrome version
    # because Early Stable may be newer but Windows-only.
    candidates.sort(key=lambda r: (r["ReleaseDate"], _version_key(r["Version"])))
    return candidates[-1]
