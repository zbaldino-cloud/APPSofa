import unittest

from feed.sources.zoom_security import fetch_latest_zoom_mac, fetch_zoom_client_security

class ZoomSecurityParserTests(unittest.TestCase):
    def test_latest_mac_release_from_full_versions_rows(self):
        page = """
        <table>
        <tr><th>Windows</th><th>macOS</th><th>Linux</th><th>Android</th></tr>
        <tr><td>7.1.0 (41345)</td><td>7.1.0 (83064)</td><td>7.1.0 (3715)</td><td>7.1.0 (41065)</td></tr>
        </table>
        <table>
        <tr><th>Windows</th><th>macOS</th><th>Linux</th><th>Android</th></tr>
        <tr><td>7.2.1 (48556)</td><td>7.2.1 (88329)</td><td>7.2.1 (5760)</td><td>7.2.1 (43844)</td></tr>
        </table>
        """
        self.assertEqual(fetch_latest_zoom_mac(page), "7.2.1")

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
