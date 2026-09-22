import unittest

from feed.sources.zoom_security import fetch_zoom_mac_versions, fetch_zoom_client_security

class ZoomSecurityParserTests(unittest.TestCase):
    def test_mac_fast_and_slow_tracks(self):
        page = """
        <table><tr><th>App by platform</th><th>Fast track</th><th>Slow track</th><th>Prompted</th><th>Minimum</th></tr>
        <tr><td>Windows</td><td>7.2.1</td><td>7.0.6</td><td>7.0.6</td><td>5.17.5</td></tr>
        <tr><td>macOS</td><td>7.2.1</td><td>7.0.6</td><td>7.0.6</td><td>6.0.2</td></tr></table>
        """
        self.assertEqual(fetch_zoom_mac_versions(page), {
            "LatestVersion": "7.2.1",
            "SlowTrackVersion": "7.0.6",
        })

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
