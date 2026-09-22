"""Zoom Workplace for macOS release/security source.

The latest macOS version is derived from Zoom's official latest PKG redirect.
Zoom's public security bulletin index supplies applicable client CVEs/severity.
Because the public bulletin index does not expose a fixed build, AppSOFA uses
the current vendor release as a conservative security floor when applicable
client security bulletins exist.
"""
import html
import re
import urllib.request
from html.parser import HTMLParser
from datetime import datetime

LATEST_MAC_PKG_URL = "https://zoom.us/client/latest/Zoom.pkg"
SECURITY_URL = "https://www.zoom.com/en/trust/security-bulletin/?onlycontent=1&platform=mac&product=zoom"

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
            self._row.append(
                re.sub(r"\s+", " ", html.unescape(" ".join(self._cell))).strip()
            )
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

def fetch_latest_zoom_mac(url=LATEST_MAC_PKG_URL):
    req = urllib.request.Request(url, headers={"User-Agent": "AppSOFA/0.10"})
    with urllib.request.urlopen(req, timeout=30) as response:
        final_url = response.geturl()

    match = re.search(
        r"/(?:client|prod)/(\d+(?:\.\d+){2,4})/",
        final_url,
        re.I,
    )
    if not match:
        raise RuntimeError(
            f"Zoom latest macOS package did not redirect to a versioned URL: {final_url}"
        )

    # Zoom CDN paths may append the build as an additional dotted component.
    # AppSOFA compares the public semantic version used by CFBundleShortVersionString.
    parts = match.group(1).split(".")
    return ".".join(parts[:3])

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
        lower = title.lower()
        if not ("zoom clients" in lower or "zoom workplace clients" in lower):
            continue
        if any(term in lower for term in (
            "windows", "vdi", "rooms", "mobile", "ios", "android",
            "sdk", "node", "contact center",
        )):
            continue

        severity = next(
            (cell.title() for cell in row if cell.title() in SEVERITIES),
            None,
        )
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
    latest = fetch_latest_zoom_mac()
    security = fetch_zoom_client_security()

    return {
        "LatestVersion": latest,
        "SecurityRelease": {
            "Version": latest,
            "MacVersions": [latest],
            "ReleaseDate": security["ReleaseDate"],
            "CVEs": security["CVEs"],
            "SourceURL": security["SourceURL"],
            "PlatformEvidence": "VendorAdvisory",
        },
    }
