import unittest

from feed.sources.microsoft_office import fetch_office_applications

class MicrosoftOfficeParserTests(unittest.TestCase):
    def test_per_app_latest_and_suite_security_inheritance(self):
        page = """
        <h2>September 19, 2026</h2>
        <p>Version 16.113.1 (Build 26091740)</p>
        <h3>Resolved issues</h3>
        <h3>Excel</h3><ul><li>Quality improvements.</li></ul>
        <h3>OneNote</h3><ul><li>Quality improvements.</li></ul>
        <h3>Outlook</h3><ul><li>Quality improvements.</li></ul>

        <h2>September 16, 2026</h2>
        <p>Version 16.113 (Build 26091433)</p>
        <h3>Resolved issues</h3>
        <h3>PowerPoint</h3><ul><li>Quality improvements.</li></ul>
        <h3>Word</h3><ul><li>Quality improvements.</li></ul>
        <h3>Security updates</h3>
        <h3>Excel</h3>
        <ul><li>CVE-2026-85875</li><li>CVE-2026-81960</li></ul>
        <h3>PowerPoint</h3>
        <ul><li>CVE-2026-78513</li></ul>
        <h3>Office Suite</h3>
        <ul><li>CVE-2026-81955</li><li>CVE-2026-81952</li></ul>
        """
        apps = {app["Name"]: app for app in fetch_office_applications(page)}

        self.assertEqual(apps["Microsoft Excel"]["LatestVersion"], "16.113.1")
        self.assertEqual(apps["Microsoft Outlook"]["LatestVersion"], "16.113.1")
        self.assertEqual(apps["Microsoft Word"]["LatestVersion"], "16.113")
        self.assertEqual(apps["Microsoft PowerPoint"]["LatestVersion"], "16.113")

        for app in apps.values():
            self.assertEqual(app["MinimumSecureVersion"], "16.113")

        excel_cves = {
            c["CVE"] for c in apps["Microsoft Excel"]["SecurityRelease"]["CVEs"]
        }
        self.assertEqual(
            excel_cves,
            {"CVE-2026-85875", "CVE-2026-81960", "CVE-2026-81955", "CVE-2026-81952"},
        )

        word_cves = {
            c["CVE"] for c in apps["Microsoft Word"]["SecurityRelease"]["CVEs"]
        }
        self.assertEqual(word_cves, {"CVE-2026-81955", "CVE-2026-81952"})

if __name__ == "__main__":
    unittest.main()
