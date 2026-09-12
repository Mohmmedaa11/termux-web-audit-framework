import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parents[1]))
from audit import TOOLS, Finding, normalize_target, render_md, severity_for_output, summarize

class AuditTests(unittest.TestCase):
    def test_normalize_http_and_reject_non_http(self):
        self.assertEqual(normalize_target("example.com"), "https://example.com/")
        with self.assertRaises(ValueError): normalize_target("ftp://example.com")

    def test_catalog_contains_core_and_discovery_profiles(self):
        for name in ("nmap", "nuclei", "httpx", "dnsx", "subfinder", "openssl", "katana", "gau", "waybackurls"):
            self.assertIn(name, TOOLS)

    def test_severity_mapping(self):
        self.assertEqual(severity_for_output("remote code execution"), "Critical")
        self.assertEqual(severity_for_output("missing security header"), "Medium")
        self.assertEqual(severity_for_output(""), "Info")

    def test_summary_score_and_markdown(self):
        findings = [Finding("X", "sample", "High", "High", "evidence", "fix")]
        summary = summarize(findings, ["httpx"])
        self.assertEqual(summary["risk_score"], 8)
        text = render_md({"targets":["https://example.com/"], "started_at":"now", "summary":summary, "findings":[{**findings[0].__dict__, "target":"https://example.com/"}]})
        self.assertIn("تقرير فحص", text)
        self.assertIn("High", text)
        self.assertIn("https://example.com/", text)

if __name__ == "__main__": unittest.main()
