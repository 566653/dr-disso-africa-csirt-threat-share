import pathlib
import sys
import tempfile
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from engine import assess, run, MAX_EVENTS


class TestEnhancedEngine(unittest.TestCase):
    def test_explainable_match(self):
        f = assess([{"id": "case-1", "event": "Ransomware detected"}])[0]
        self.assertEqual((f["severity"], f["matched_rule"], f["event_id"]), ("critical", "ransomware", "case-1"))

    def test_word_boundaries(self):
        self.assertEqual(assess([{"event": "unpatchedness"}])[0]["severity"], "info")

    def test_severity_priority(self):
        self.assertEqual(assess([{"event": "warning ransomware"}])[0]["severity"], "critical")

    def test_hyphenated_rule(self):
        self.assertEqual(assess([{"event": "SIM-SWAP reported"}])[0]["severity"], "high")

    def test_empty_list(self):
        self.assertEqual(assess([]), [])

    def test_invalid_nested_field(self):
        with self.assertRaises(ValueError):
            assess([{"event": {"unexpected": True}}])

    def test_large_batch_rejected(self):
        with self.assertRaises(ValueError):
            assess([{}] * (MAX_EVENTS + 1))

    def test_oversized_text_rejected(self):
        with self.assertRaises(ValueError):
            assess([{"event": "x" * 20001}])

    def test_summary_and_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / "events.json"
            p.write_text('[{"event":"ransomware"},{"event":"normal"}]', encoding="utf-8")
            result = run(p)
            self.assertEqual(result["severity_counts"]["critical"], 1)
            self.assertEqual(result["severity_counts"]["info"], 1)
            self.assertEqual(len(result["input_sha256"]), 64)

    def test_input_size_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / "events.json"
            p.write_bytes(b" " * (5 * 1024 * 1024 + 1))
            with self.assertRaises(ValueError):
                run(p)
