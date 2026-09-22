import unittest
from unittest.mock import patch

from feed.sources.zoom_security import fetch_latest_zoom_mac, fetch_zoom_client_security

class _FakeResponse:
    def __init__(self, url):
        self.url = url
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def geturl(self):
        return self.url

class ZoomSecurityParserTests(unittest.TestCase):
    @patch("feed.sources.zoom_security.urllib.request.urlopen")
    def test_latest_mac_release_from_package_redirect(self, urlopen):
        urlopen.return_value = _FakeResponse(
            "https://cdn.zoom.us/prod/7.2.1.88329/Zoom.pkg"
        )
        self.assertEqual(fetch_latest_zoom_mac(), "7.2.1")

    def test_security_parser_excludes_other_products(self):
        page = """
        <table>
        <tr><td>ZSB-26017</td><td>Zoom Clients - Use After Free</td><td>High</td><td>CVE-2026-53415</td><td>08/11/2026</td><td>08/14/2026</td></tr>
        <tr><td>ZSB-26016</td><td>Zoom Clients - Buffer Over-read</td><td>Medium</td><td>CVE-2026-53414</td><td>08/11/2026</td><td>08/14/2026</td></tr>
        <tr><td>ZSB-26015</td><td>Zoom Clients - Buffer Over-write</td><td>High</td><td>CVE-2026-53413</td><td>08/11/2026</td><td>08/14/2026</td></tr>
        <tr><td>ZSB-26014</td><td>Zoom Workplace for Windows - Improper Input Validation</td><td>Critical</td><td>CVE-2026-53412</td><td>07/14/2026</td><td>07/15/2026</td></tr>
        <tr><td>ZSB-26018</td><td>Zoom VDI - Path Traversal</td><td>High</td><td>CVE-2026-53416</td><td>08/11/2026</td><td>08/11/2026</td></tr>
        </table>
        """
        result = fetch_zoom_client_security(page)
        self.assertEqual(result["ReleaseDate"], "2026-08-14")
        self.assertEqual(result["CVEs"], [
            {"CVE": "CVE-2026-53415", "Severity": "High"},
            {"CVE": "CVE-2026-53414", "Severity": "Medium"},
            {"CVE": "CVE-2026-53413", "Severity": "High"},
        ])

if __name__ == "__main__":
    unittest.main()
