"""Chrome desktop security-release source.

Parses Google's Chrome Releases feed conservatively. A post is eligible to
set the macOS security floor only when it is a Stable desktop security post,
contains published CVEs, and explicitly associates the version text with Mac.
"""
import html
import json
import re
import urllib.request

FEED_URL = "https://chromereleases.googleblog.com/feeds/posts/default?alt=json&max-results=100"
CVE_RE = re.compile(r"\b(Critical|High|Medium|Low)\s+(CVE-\d{4}-\d+)\b", re.I)

# Google has used both:
#   153.0.8010.52/.53 for Windows and Mac
#   153.0.8010.36/.37 Windows/Mac
MAC_VERSION_PATTERNS = [
    re.compile(
        r"(\d+\.\d+\.\d+\.\d+)(?:/\.(\d+))?\s+for\s+Windows\s+and\s+Mac\b",
        re.I,
    ),
    re.compile(
        r"(\d+\.\d+\.\d+\.\d+)(?:/\.(\d+))?\s+Windows\s*/\s*Mac\b",
        re.I,
    ),
]

def _get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "AppSOFA/0.8"})
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)

def _version_key(v):
    return tuple(int(p) for p in v.split("."))

def _plain_text(value):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html.unescape(value))).strip()

def _extract_mac_versions(text):
    for pattern in MAC_VERSION_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        base, alternate_patch = match.groups()
        versions = [base]
        if alternate_patch:
            parts = base.split(".")
            parts[-1] = alternate_patch
            versions.append(".".join(parts))
        return sorted(set(versions), key=_version_key)
    return []

def fetch_latest_mac_security_release():
    payload = _get_json(FEED_URL)
    entries = payload.get("feed", {}).get("entry", [])
    candidates = []

    for entry in entries:
        title = entry.get("title", {}).get("$t", "").strip().lower()
        if title != "stable channel update for desktop":
            continue

        labels = {c.get("term", "").lower() for c in entry.get("category", [])}
        if "stable updates" not in labels:
            continue

        raw = entry.get("content", {}).get("$t") or entry.get("summary", {}).get("$t", "")
        text = _plain_text(raw)
        mac_versions = _extract_mac_versions(text)

        # Fail closed: never infer a Mac floor from a Windows-only or ambiguous post.
        if not mac_versions:
            continue

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
            # Google publishes paired Windows/Mac patch builds without mapping
            # each patch to one OS. Both are explicitly valid for Mac in the
            # release statement, so the lower accepted build is the floor.
            "Version": min(mac_versions, key=_version_key),
            "MacVersions": mac_versions,
            "ReleaseDate": published[:10],
            "CVEs": cves,
            "SourceURL": source_url,
            "PlatformEvidence": "ExplicitMac",
        })

    if not candidates:
        raise RuntimeError(
            "No explicitly Mac-qualified Chrome Stable security release found"
        )

    candidates.sort(key=lambda r: (r["ReleaseDate"], _version_key(r["Version"])))
    return candidates[-1]
