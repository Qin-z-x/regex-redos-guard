"""Source-file scanning tests (Python AST extraction)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from redos_guard.files import extract_python_patterns, scan_file

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples" / "llm_generated_patterns.py"

SOURCE = '''\
import re

SAFE = re.compile(r"^\\d{4}-\\d{2}-\\d{2}$")
RISKY = re.compile(r"(a+)+$")
MATCHED = re.match(r"^(\\w+)\\1+$", value)
DYNAMIC = re.compile(prefix + "+")
'''

SAFE_SOURCE = '''\
import re
PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
'''


class ExtractionTests(unittest.TestCase):
    def test_extracts_constant_patterns(self):
        patterns, dynamic_skipped = extract_python_patterns(SOURCE)
        values = [item["pattern"] for item in patterns]
        self.assertIn(r"(a+)+$", values)
        self.assertIn(r"^\d{4}-\d{2}-\d{2}$", values)
        self.assertEqual(dynamic_skipped, 1)

    def test_records_line_and_column(self):
        patterns, _ = extract_python_patterns(SOURCE)
        risky = [item for item in patterns if item["pattern"] == r"(a+)+$"][0]
        self.assertEqual(risky["line"], 4)
        self.assertGreaterEqual(risky["column"], 1)

    def test_deduplicates_identical_source_positions(self):
        patterns, _ = extract_python_patterns('re.compile(r"a+")\n')
        self.assertEqual(len(patterns), 1)

    def test_invalid_python_raises_syntax_error(self):
        with self.assertRaises(SyntaxError):
            extract_python_patterns("def broken(:\n")


class ScanFileTests(unittest.TestCase):
    def test_scan_example_file(self):
        result = scan_file(EXAMPLES)
        self.assertEqual(len(result["errors"]), 0)
        self.assertGreaterEqual(result["summary"]["patterns"], 8)
        codes = {finding["code"] for finding in result["findings"]}
        self.assertIn("RG-NESTED-QUANT", codes)
        self.assertIn("RG-OVERLAP-ALT", codes)
        self.assertIn("RG-BACKREF-REPEAT", codes)
        self.assertEqual(result["summary"]["dynamic_skipped"], 1)

    def test_safe_file_has_no_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "safe.py"
            path.write_text(SAFE_SOURCE, encoding="utf-8")
            result = scan_file(path)
            self.assertEqual(result["findings"], [])
            self.assertEqual(result["summary"]["patterns"], 1)

    def test_directory_scan_is_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "b.py").write_text('re.compile(r"(a+)+$")\n', encoding="utf-8")
            (root / "a.py").write_text('re.compile(r"a+")\n', encoding="utf-8")
            first = scan_file(root)
            second = scan_file(root)
            self.assertEqual(first["findings"], second["findings"])
            self.assertEqual([entry["source_file"] for entry in first["entries"]], ["a.py", "b.py"])

    def test_syntax_error_is_recorded_not_fatal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.py"
            path.write_text("def broken(:\n", encoding="utf-8")
            result = scan_file(path)
            self.assertEqual(len(result["errors"]), 1)
            self.assertEqual(result["findings"], [])

    def test_missing_path_raises(self):
        with self.assertRaises(FileNotFoundError):
            scan_file(Path(tempfile.gettempdir()) / "definitely-missing-regex-dir")

    def test_dynamic_scan_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "risky.py"
            path.write_text('import re\nP = re.compile(r"(a+)+$")\n', encoding="utf-8")
            result = scan_file(path, timeout_s=0.3)
            self.assertTrue(result["dynamic_enabled"])
            self.assertGreaterEqual(result["summary"]["dynamic_timeouts"], 1)


if __name__ == "__main__":
    unittest.main()
