import os
import tempfile
import unittest
import sys

# Allow running tests from repo root without installing package.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools.paths import detect_format
from tools.reporting import HIGH, MEDIUM, build_findings, format_report, top_priority_fix


class ReportingTests(unittest.TestCase):
    def test_detect_format_for_basic_magic(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x7fELF" + b"\x00" * 8)
            path = f.name
        try:
            self.assertEqual(detect_format(path), "ELF")
        finally:
            os.unlink(path)

    def test_high_risk_and_review_calls_are_separate(self):
        scan = {
            "format": "ELF",
            "protections": {
                "nx": "disabled",
                "pie": "enabled",
                "canary": "disabled",
                "relro": "partial",
            },
            "symbols": {
                "dangerous_functions": ["gets"],
                "review_functions": ["printf", "memcpy"],
            },
            "strings": {"interesting": {}},
            "secrets": {"findings": {}},
        }

        findings, overall, high_count, med_count = build_findings(scan)
        flags = {item["flag"]: item for item in findings}

        self.assertEqual(overall, HIGH)
        self.assertGreaterEqual(high_count, 3)
        self.assertGreaterEqual(med_count, 2)
        self.assertEqual(flags["Dangerous C-runtime calls"]["risk"], HIGH)
        self.assertEqual(flags["Memory/input routines need review"]["risk"], MEDIUM)

    def test_reverse_engineering_leads_are_reported(self):
        scan = {
            "format": "ELF",
            "protections": {},
            "symbols": {"behavioral_imports": {"strcmp": "string comparison"}},
            "strings": {"interesting": {}},
            "secrets": {"findings": {}},
            "reverse_engineering": {
                "priority_functions": [{"name": "check_license", "score": 6}],
            },
        }

        findings, overall, high_count, med_count = build_findings(scan)
        top_fix = top_priority_fix(findings)
        report = format_report("sample.bin", scan, findings, overall, high_count, med_count, top_fix)

        self.assertIn("Reverse-engineering leads", report)
        self.assertIn("check_license", report)
        self.assertEqual(overall, MEDIUM)


if __name__ == "__main__":
    unittest.main()
