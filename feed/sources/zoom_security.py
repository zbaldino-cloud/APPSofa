"""Zoom Workplace for macOS release/security source.

Zoom publishes separate Fast/Slow tracks. AppSOFA treats the macOS Fast Track
as LatestVersion and the macOS Slow Track as the security floor only when the
current Zoom client security bulletin set establishes CVEs for the client.
"""
import html
import re
import urllib.request
from html.parser import HTMLParser
from datetime import datetime

VERSION_POLICY_URL = "https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0061900"
SECURITY_URL = "https://www.zoom.com/en/trust/security-bulletin/?onlycontent=1&platform=mac&product=zoom"

VERSION_RE = re.compile(r"^\d+(?:\.\d+){2,3}$")
CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
ZSB_RE = re.compile(r"ZSB-\d{5}", re.I)
DATE_RE = re.compile(r"\b(\d{2}/\d{2}/\d{4})\b")
SEVERITIES = {"Critical", "High", "Medium", "Low"}

class _TableParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows = []
        self._row = None
        self._cell = None

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == "tr":
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._cell = []

    def handle_data(self, data):
        if self._cell is not None:
            self._cell.append(data)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in ("td", "th") and self._cell is not None:
            self._row.append(re.sub(r"\s+", " ", html.unescape(" ".join(self._cell))).strip())
            self._cell = None
        elif tag == "tr" and self._row is not None:
            if self._row:
                self.rows.append(self._row)
            self._row = None

def _request(url):
    req = urllib.request.Request(url, headers={"User-Agent": "AppSOFA/0.10"})
    with urllib.request.urlopen(req, timeout=30) as response:
        return response.read().decode("utf-8")

def _tables(page):
    parser = _TableParser()
    parser.feed(page)
    return parser.rows

def _version_key(version):
    return tuple(int(part) for part in version.split("."))

def fetch_zoom_mac_versions(page=None):
    rows = _tables(page if page is not None else _request(VERSION_POLICY_URL))
    for row in rows:
        if not row or row[0].strip().lower() != "macos":
            continue
        versions = [cell.strip() for cell in row[1:] if VERSION_RE.fullmatch(cell.strip())]
        if len(versions) < 2:
            raise RuntimeError("Zoom macOS version-policy row did not contain Fast and Slow versions")
        return {"LatestVersion": versions[0], "SlowTrackVersion": versions[1]}
    raise RuntimeError("Zoom macOS version-policy row not found")

def fetch_zoom_client_security(page=None):
    rows = _tables(page if page is not None else _request(SECURITY_URL))
    cves = []
    seen = set()
    dates = []

    for row in rows:
        joined = " ".join(row)
        if not ZSB_RE.search(joined):
            continue

        title = row[1] if len(row) > 1 else ""
        # Generic "Zoom Clients" / "Zoom Workplace Clients" bulletins apply to
        # the desktop client. Explicit Windows, VDI, Rooms, mobile/iOS/Android,
        # SDK, Node, and Contact Center product bulletins are not macOS
        # Workplace evidence.
        lower = title.lower()
        if not ("zoom clients" in lower or "zoom workplace clients" in lower):
            continue
        if any(term in lower for term in (
            "windows", "vdi", "rooms", "mobile", "ios", "android",
            "sdk", "node", "contact center",
        )):
            continue

        severity = next((cell.title() for cell in row if cell.title() in SEVERITIES), None)
        if severity is None:
            continue

        for cve_id in CVE_RE.findall(joined):
            cve_id = cve_id.upper()
            if cve_id not in seen:
                seen.add(cve_id)
                cves.append({"CVE": cve_id, "Severity": severity})

        for date_value in DATE_RE.findall(joined):
            dates.append(datetime.strptime(date_value, "%m/%d/%Y").date())

    if not cves:
        raise RuntimeError("No applicable Zoom macOS client security bulletins found")
    if not dates:
        raise RuntimeError("No publication date found for Zoom client security bulletins")

    return {
        "CVEs": cves,
        "ReleaseDate": max(dates).isoformat(),
        "SourceURL": SECURITY_URL,
    }

def fetch_zoom_security_release():
    versions = fetch_zoom_mac_versions()
    security = fetch_zoom_client_security()
    floor = versions["SlowTrackVersion"]

    return {
        "LatestVersion": versions["LatestVersion"],
        "SecurityRelease": {
            "Version": floor,
            "MacVersions": [floor],
            "ReleaseDate": security["ReleaseDate"],
            "CVEs": security["CVEs"],
            "SourceURL": security["SourceURL"],
            "PlatformEvidence": "VendorAdvisory",
        },
    }
