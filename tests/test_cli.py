"""CLI tests: check / scan-file / explain, exit codes, JSON output."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples" / "llm_generated_patterns.py"


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "redos_guard", *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=180,
    )


class CheckCliTests(unittest.TestCase):
    def test_safe_pattern_exits_zero(self):
        result = run_cli("check", r"^\d{4}-\d{2}-\d{2}$")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("summary:", result.stdout)

    def test_risky_pattern_without_gate_exits_zero(self):
        result = run_cli("check", "(a+)+$")
        self.assertEqual(result.returncode, 0)
        self.assertIn("RG-NESTED-QUANT", result.stdout)

    def test_fail_on_high_exits_one(self):
        result = run_cli("check", "(a+)+$", "--fail-on", "high")
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL:", result.stdout)

    def test_safe_pattern_fail_on_high_exits_zero(self):
        self.assertEqual(run_cli("check", "a+$", "--fail-on", "high").returncode, 0)

    def test_json_output_shape(self):
        result = run_cli("check", "(a+)+$", "--json")
        payload = json.loads(result.stdout)
        self.assertEqual(payload["tool"], "redos-guard")
        self.assertEqual(payload["summary"]["high"], 1)
        self.assertEqual(payload["dynamic_enabled"], False)
        self.assertIn("caveat", payload)

    def test_json_dynamic_probe_timeout(self):
        result = run_cli("check", "(a+)+$", "--timeout", "0.3", "--size", "40", "--json", "--fail-on", "high")
        payload = json.loads(result.stdout)
        codes = [finding["code"] for finding in payload["findings"]]
        self.assertIn("RG-DYNAMIC-TIMEOUT", codes)
        self.assertEqual(result.returncode, 1)

    def test_invalid_pattern_exits_two(self):
        result = run_cli("check", "(")
        self.assertEqual(result.returncode, 2)
        self.assertIn("error:", result.stderr)

    def test_explain_output(self):
        result = run_cli("explain", "(a+)+$")
        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["valid"])
        self.assertTrue(payload["suggestions"])

    def test_explain_invalid_exits_two(self):
        self.assertEqual(run_cli("explain", "(").returncode, 2)

    def test_version(self):
        result = run_cli("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("0.1.0", result.stdout)

    def test_unknown_option_exits_two(self):
        self.assertEqual(run_cli("check", "a+", "--bogus").returncode, 2)


class ScanFileCliTests(unittest.TestCase):
    def test_scan_file_reports_risks(self):
        result = run_cli("scan-file", str(EXAMPLES), "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertGreaterEqual(payload["summary"]["high"], 2)
        self.assertGreaterEqual(payload["summary"]["patterns"], 8)

    def test_scan_file_gate_exits_one(self):
        result = run_cli("scan-file", str(EXAMPLES), "--fail-on", "high")
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL:", result.stdout)

    def test_scan_file_human_output_lists_patterns(self):
        result = run_cli("scan-file", str(EXAMPLES))
        self.assertEqual(result.returncode, 0)
        self.assertIn("RISK", result.stdout)
        self.assertIn("summary:", result.stdout)

    def test_missing_path_exits_two(self):
        result = run_cli("scan-file", str(ROOT / "does-not-exist.py"))
        self.assertEqual(result.returncode, 2)

    def test_scan_file_safe_file_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "safe.py"
            path.write_text('import re\nP = re.compile(r"^[a-z]+$")\n', encoding="utf-8")
            result = run_cli("scan-file", str(path), "--fail-on", "high")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
