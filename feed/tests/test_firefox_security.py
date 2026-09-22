import unittest

from feed.sources.firefox_security import _latest_advisory_reference, _parse_advisory

class FirefoxSecurityParserTests(unittest.TestCase):
    def test_latest_firefox_advisory_ignores_esr(self):
        page = """
        <a href="/en-US/security/advisories/mfsa2026-92/"><span>2026-92</span> Security Vulnerabilities fixed in Firefox ESR 140.16</a>
        <a class="mzp-c-cta-link" href="/en-US/security/advisories/mfsa2026-90/"><span>2026-90</span> Security Vulnerabilities fixed in Firefox 156</a>
        <a href="/en-US/security/advisories/mfsa2026-82/">2026-82 <strong>Security Vulnerabilities fixed in Firefox 155</strong></a>
        """
        self.assertEqual(_latest_advisory_reference(page), ("mfsa2026-90", "156"))

    def test_parse_advisory(self):
        page = """
        <div>Announced September 15, 2026</div>
        <h4>CVE-2026-92005: Use-after-free</h4><div>Impact</div><span>high</span>
        <h4>CVE-2026-92039: Animation issue</h4><div>Impact</div><span>moderate</span>
        """
        result = _parse_advisory(page, "mfsa2026-90", "156")
        self.assertEqual(result["Version"], "156")
        self.assertEqual(result["ReleaseDate"], "2026-09-15")
        self.assertEqual(result["PlatformEvidence"], "VendorAdvisory")
        self.assertEqual(result["CVEs"][0]["Severity"], "High")
        self.assertEqual(result["CVEs"][1]["Severity"], "Medium")

if __name__ == "__main__":
    unittest.main()
