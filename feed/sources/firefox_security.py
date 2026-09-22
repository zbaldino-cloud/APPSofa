"""Mozilla Firefox release and security-advisory source."""
import html
import json
import re
import urllib.request
from html.parser import HTMLParser

VERSIONS_URL = "https://product-details.mozilla.org/1.0/firefox_versions.json"
ADVISORIES_URL = "https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox/"
ADVISORY_BASE = "https://www.mozilla.org/en-US/security/advisories/"

FIREFOX_ADVISORY_TEXT_RE = re.compile(
    r"Security Vulnerabilities fixed in Firefox\s+([0-9]+(?:\.[0-9]+)*)$",
    re.I,
)
ADVISORY_ID_RE = re.compile(r"/security/advisories/(mfsa\d{4}-\d+)/?", re.I)
CVE_BLOCK_RE = re.compile(
    r'(CVE-\d{4}-\d+).*?Impact\s*</[^>]+>\s*'
    r'(?:<[^>]+>\s*)*(critical|high|moderate|low)\b',
    re.I | re.S,
)

class _LinkCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            self.links.append((self._href, " ".join(self._text)))
            self._href = None
            self._text = []

def _request(url):
    req = urllib.request.Request(url, headers={"User-Agent": "AppSOFA/0.9"})
    with urllib.request.urlopen(req, timeout=30) as response:
        return response.read().decode("utf-8")

def _get_json(url):
    return json.loads(_request(url))

def _version_key(version):
    return tuple(int(p) for p in version.split("."))

def latest_firefox():
    version = _get_json(VERSIONS_URL).get("LATEST_FIREFOX_VERSION")
    if not version:
        raise RuntimeError("Mozilla product-details returned no Firefox version")
    return version

def _latest_advisory_reference(index_html):
    parser = _LinkCollector()
    parser.feed(index_html)
    matches = []

    for href, link_text in parser.links:
        advisory_match = ADVISORY_ID_RE.search(href or "")
        if not advisory_match:
            continue

        normalized_text = re.sub(r"\s+", " ", html.unescape(link_text)).strip()
        version_match = FIREFOX_ADVISORY_TEXT_RE.search(normalized_text)
        if not version_match:
            continue

        matches.append((advisory_match.group(1).lower(), version_match.group(1)))

    if not matches:
        raise RuntimeError("No Firefox security advisory found")

    return max(matches, key=lambda item: _version_key(item[1]))

def _parse_advisory(advisory_html, advisory_id, version):
    text = html.unescape(advisory_html)
    cves = []
    seen = set()
    severity_map = {"critical": "Critical", "high": "High", "moderate": "Medium", "low": "Low"}

    for cve_id, severity in CVE_BLOCK_RE.findall(text):
        cve_id = cve_id.upper()
        if cve_id in seen:
            continue
        seen.add(cve_id)
        cves.append({"CVE": cve_id, "Severity": severity_map[severity.lower()]})

    if not cves:
        raise RuntimeError(f"No CVEs found in Mozilla advisory {advisory_id}")

    plain = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text))
    date_match = re.search(
        r"Announced\s+([A-Z][a-z]+\s+\d{1,2},\s+\d{4})",
        plain,
        re.I,
    )
    if not date_match:
        raise RuntimeError(f"No announcement date found in Mozilla advisory {advisory_id}")

    from datetime import datetime
    release_date = datetime.strptime(date_match.group(1), "%B %d, %Y").date().isoformat()

    return {
        "Version": version,
        "MacVersions": [version],
        "ReleaseDate": release_date,
        "CVEs": cves,
        "SourceURL": f"{ADVISORY_BASE}{advisory_id}/",
        "PlatformEvidence": "VendorAdvisory",
    }

def fetch_latest_firefox_security_release():
    advisory_id, version = _latest_advisory_reference(_request(ADVISORIES_URL))
    return _parse_advisory(_request(f"{ADVISORY_BASE}{advisory_id}/"), advisory_id, version)
