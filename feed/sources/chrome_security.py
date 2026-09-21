"""Chrome desktop security-release source.

Reads Google's public Chrome Releases Atom feed and extracts Mac Stable
security releases, CVE IDs, and Google's severity labels.
"""
import html
import re
import urllib.request
import xml.etree.ElementTree as ET

FEED_URL = "https://chromereleases.googleblog.com/feeds/posts/default/-/Stable%20updates"
ATOM = {"a": "http://www.w3.org/2005/Atom"}
VERSION_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)(?:/\.(\d+))?\s+for Windows and Mac", re.I)
CVE_RE = re.compile(r"\b(Critical|High|Medium|Low)\s+(CVE-\d{4}-\d+)\b", re.I)

def _get_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": "AppSOFA/0.6"})
    with urllib.request.urlopen(req, timeout=30) as response:
        return response.read()

def _version_key(v):
    return tuple(int(p) for p in v.split("."))

def fetch_latest_mac_security_release():
    root = ET.fromstring(_get_text(FEED_URL))
    candidates = []

    for entry in root.findall("a:entry", ATOM):
        title = entry.findtext("a:title", default="", namespaces=ATOM)
        if "Stable Channel Update for Desktop" not in title:
            continue

        content = entry.findtext("a:content", default="", namespaces=ATOM)
        text = re.sub(r"<[^>]+>", " ", html.unescape(content))
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

        # Only treat posts that actually publish CVE/security information as
        # security releases. This avoids equating a normal Stable update with
        # a security floor.
        if not cves:
            continue

        published = entry.findtext("a:published", default="", namespaces=ATOM)
        link = next((x.attrib.get("href") for x in entry.findall("a:link", ATOM)
                     if x.attrib.get("rel") == "alternate"), None)

        candidates.append({
            "Version": min(versions, key=_version_key),
            "MacVersions": sorted(versions, key=_version_key),
            "ReleaseDate": published[:10],
            "CVEs": cves,
            "SourceURL": link
        })

    if not candidates:
        raise RuntimeError("No Chrome Mac Stable security release found")

    return max(candidates, key=lambda r: _version_key(r["Version"]))
