import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parents[1]))
from audit import in_scope, normalize_target, render_md

class AuditTests(unittest.TestCase):
    def test_scope_exact_and_subdomain(self):
        self.assertTrue(in_scope("https://example.com/path", ["example.com"]))
        self.assertTrue(in_scope("https://api.example.com", ["example.com"]))
        self.assertFalse(in_scope("https://example.com.attacker.test", ["example.com"]))

    def test_normalize_rejects_non_http(self):
        self.assertEqual(normalize_target("example.com"), "https://example.com/")
        with self.assertRaises(ValueError): normalize_target("ftp://example.com")

    def test_markdown_has_summary(self):
        text = render_md({"target":"https://example.com/", "started_at":"now", "scope_file":"scope", "summary":{"max_severity":"Low"}, "findings":[]})
        self.assertIn("تقرير فحص", text)
        self.assertIn("Low", text)

if __name__ == "__main__": unittest.main()
