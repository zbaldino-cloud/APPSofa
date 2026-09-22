"""Microsoft Office for Mac release/security source.

Microsoft's Office for Mac release notes publish release versions and security
updates by product. AppSOFA models each installed Office app independently and
inherits "Office Suite" CVEs into every core Office application.
"""
import html
import re
import urllib.request
from datetime import datetime
from html.parser import HTMLParser

RELEASE_NOTES_URL = "https://learn.microsoft.com/en-us/officeupdates/release-notes-office-for-mac"

APPS = {
    "Word": {
        "Name": "Microsoft Word",
        "BundleID": "com.microsoft.Word",
        "ApplicationPath": "/Applications/Microsoft Word.app",
    },
    "Excel": {
        "Name": "Microsoft Excel",
        "BundleID": "com.microsoft.Excel",
        "ApplicationPath": "/Applications/Microsoft Excel.app",
    },
    "PowerPoint": {
        "Name": "Microsoft PowerPoint",
        "BundleID": "com.microsoft.Powerpoint",
        "ApplicationPath": "/Applications/Microsoft PowerPoint.app",
    },
    "Outlook": {
        "Name": "Microsoft Outlook",
        "BundleID": "com.microsoft.Outlook",
        "ApplicationPath": "/Applications/Microsoft Outlook.app",
    },
    "OneNote": {
        "Name": "Microsoft OneNote",
        "BundleID": "com.microsoft.onenote.mac",
        "ApplicationPath": "/Applications/Microsoft OneNote.app",
    },
}

VERSION_RE = re.compile(r"Version\s+(\d+(?:\.\d+)+)", re.I)
CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)

class _ReleaseNotesParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.events = []
        self._tag = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in ("h2", "h3", "p", "li"):
            self._tag = tag
            self._text = []

    def handle_data(self, data):
        if self._tag is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self._tag == tag:
            value = re.sub(
                r"\s+", " ", html.unescape(" ".join(self._text))
            ).strip()
            if value:
                self.events.append((tag, value))
            self._tag = None
            self._text = []

def _request(url):
    req = urllib.request.Request(url, headers={"User-Agent": "AppSOFA/0.11"})
    with urllib.request.urlopen(req, timeout=30) as response:
        return response.read().decode("utf-8")

def _version_key(version):
    return tuple(int(part) for part in version.split("."))

def _parse_date(value):
    for fmt in ("%B %d, %Y", "%B %d %Y"):
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            pass
    return None

def parse_office_release_notes(page):
    parser = _ReleaseNotesParser()
    parser.feed(page)

    releases = []
    current = None
    section = None
    product = None

    for tag, text in parser.events:
        if tag == "h2":
            date = _parse_date(text)
            if date is not None:
                current = {
                    "ReleaseDate": date.isoformat(),
                    "Version": None,
                    "ProductsSeen": set(),
                    "Security": {},
                }
                releases.append(current)
                section = None
                product = None
            continue

        if current is None:
            continue

        if tag == "p" and current["Version"] is None:
            match = VERSION_RE.search(text)
            if match:
                current["Version"] = match.group(1)
            continue

        if tag == "h3":
            if text in ("Security updates", "Resolved issues", "Feature updates"):
                section = text
                product = None
            elif text in APPS or text == "Office Suite":
                product = text
                if text in APPS:
                    current["ProductsSeen"].add(text)
            continue

        if tag == "li" and section == "Security updates" and product:
            for cve_id in CVE_RE.findall(text):
                current["Security"].setdefault(product, []).append(cve_id.upper())

    return [release for release in releases if release["Version"]]

def fetch_office_applications(page=None):
    releases = parse_office_release_notes(
        page if page is not None else _request(RELEASE_NOTES_URL)
    )
    if not releases:
        raise RuntimeError("No Office for Mac releases found")

    applications = []
    for product, metadata in APPS.items():
        latest_release = next(
            (r for r in releases if product in r["ProductsSeen"]),
            None,
        )
        security_release = next(
            (
                r for r in releases
                if r["Security"].get("Office Suite") or r["Security"].get(product)
            ),
            None,
        )

        if latest_release is None:
            raise RuntimeError(f"No latest Office release found for {product}")
        if security_release is None:
            raise RuntimeError(f"No Office security release found for {product}")

        cve_ids = []
        for scope in ("Office Suite", product):
            for cve_id in security_release["Security"].get(scope, []):
                if cve_id not in cve_ids:
                    cve_ids.append(cve_id)

        if not cve_ids:
            raise RuntimeError(f"Office security release for {product} had no CVEs")

        security = {
            "Version": security_release["Version"],
            "MacVersions": [security_release["Version"]],
            "ReleaseDate": security_release["ReleaseDate"],
            "CVEs": [
                {"CVE": cve_id, "Severity": "Unknown"}
                for cve_id in cve_ids
            ],
            "SourceURL": RELEASE_NOTES_URL,
            "PlatformEvidence": "VendorAdvisory",
        }

        applications.append({
            **metadata,
            "LatestVersion": latest_release["Version"],
            "MinimumSecureVersion": security_release["Version"],
            "SecurityRelease": security,
        })

    return applications
