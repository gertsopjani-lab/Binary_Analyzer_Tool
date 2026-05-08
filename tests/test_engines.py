import os
import sys
import unittest

# Allow running tests from repo root without installing package.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engines.import_engine import ImportEngine
from engines.packing_engine import detect_generic_packing
from analysis.confidence import confidence_for_finding
from analysis.evidence_graph import EvidenceItem, Finding, merge_findings


class EngineTests(unittest.TestCase):
    def test_import_scoring_hits_and_clusters(self):
        engine = ImportEngine()
        result = engine.score_imports(
            [
                "VirtualAlloc",
                "VirtualProtect",
                "CreateRemoteThread",
                "IsDebuggerPresent",
                "LoadLibraryW",
            ]
        )
        self.assertGreaterEqual(result.score, 5 + 6 + 10 + 4 + 3)
        self.assertIn("process_injection", result.clusters)
        self.assertIn("anti_debug", result.clusters)

    def test_generic_packing_entropy_runs(self):
        # Use a low-entropy byte pattern: should not classify as packed.
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"A" * 20000)
            path = f.name
        try:
            res = detect_generic_packing(path)
            self.assertFalse(res.packed)
            self.assertGreaterEqual(res.confidence, 0.0)
        finally:
            os.unlink(path)

    def test_confidence_increases_with_signals(self):
        base = confidence_for_finding("Hardcoded secrets / license data", ["matched secret regex"], {})
        boosted = confidence_for_finding(
            "Hardcoded secrets / license data",
            ["matched secret regex", "xref to string in sub_401000", "string literal found"],
            {"engines": ["strings", "radare2"], "xrefs_confirmed": True, "string_literal": True},
        )
        self.assertGreater(boosted.confidence, base.confidence)

    def test_dedup_merges_signatures(self):
        f1 = Finding(
            finding="Hardcoded secrets",
            severity="HIGH",
            confidence=0.6,
            evidence=[EvidenceItem("string", "LICENSE-KEY-123", {})],
            source="strings",
        )
        f2 = Finding(
            finding="Hardcoded secrets",
            severity="HIGH",
            confidence=0.9,
            evidence=[EvidenceItem("string", "LICENSE-KEY-123", {}), EvidenceItem("function", "sub_401000", {})],
            source="radare2",
        )
        merged = merge_findings([f1, f2])
        self.assertEqual(len(merged), 1)
        self.assertAlmostEqual(merged[0].confidence, 0.9)
        self.assertGreaterEqual(len(merged[0].evidence), 2)


if __name__ == "__main__":
    unittest.main()

