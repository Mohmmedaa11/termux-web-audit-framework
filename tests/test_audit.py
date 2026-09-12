import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parents[1]))
from audit import TOOLS, Finding, in_scope, normalize_target, render_md, severity_for_output, summarize

class AuditTests(unittest.TestCase):
    def test_scope_exact_and_subdomain(self):
        self.assertTrue(in_scope("https://example.com/path", ["example.com"]))
        self.assertTrue(in_scope("https://api.example.com", ["example.com"]))
        self.assertFalse(in_scope("https://example.com.attacker.test", ["example.com"]))

    def test_normalize_rejects_non_http(self):
        self.assertEqual(normalize_target("example.com"), "https://example.com/")
        with self.assertRaises(ValueError): normalize_target("ftp://example.com")

    def test_catalog_contains_core_profiles(self):
        for name in ("nmap", "nuclei", "httpx", "dnsx", "subfinder", "openssl"):
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
