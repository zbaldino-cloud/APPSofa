import unittest

from feed.sources.chrome_security import _extract_mac_versions

class ChromeSecurityParserTests(unittest.TestCase):
    def test_for_windows_and_mac_pair(self):
        text = "The Stable channel has been updated to 153.0.8010.52/.53 for Windows and Mac"
        self.assertEqual(_extract_mac_versions(text), ["153.0.8010.52", "153.0.8010.53"])

    def test_windows_slash_mac_pair(self):
        text = "Chrome 153.0.8010.36/.37 Windows/Mac contains a number of fixes"
        self.assertEqual(_extract_mac_versions(text), ["153.0.8010.36", "153.0.8010.37"])

    def test_windows_only_fails_closed(self):
        text = "The Stable channel has been updated to 154.0.8037.44 for Windows"
        self.assertEqual(_extract_mac_versions(text), [])

if __name__ == "__main__":
    unittest.main()
