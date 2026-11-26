"""Dynamic probe tests: input generation, child-process timeout behaviour."""

from __future__ import annotations

import unittest

from redos_guard import RegexParseError, build_adversarial_inputs
from redos_guard.dynamic import (
    SLOW_THRESHOLD_S,
    check,
    dynamic_findings,
    dynamic_scan,
    probe,
)


class InputGenerationTests(unittest.TestCase):
    def test_generates_bounded_deterministic_inputs(self):
        first = build_adversarial_inputs(r"(a+)+$", size=24, max_inputs=3)
        second = build_adversarial_inputs(r"(a+)+$", size=24, max_inputs=3)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 3)
        self.assertTrue(all(len(item["text"]) <= 26 for item in first))

    def test_first_input_has_non_matching_terminator(self):
        inputs = build_adversarial_inputs(r"(a+)+$", size=12, max_inputs=1)
        self.assertNotIn("a", inputs[0]["text"][-1])

    def test_class_hint_used(self):
        inputs = build_adversarial_inputs(r"^[0-9]+$", size=8, max_inputs=1)
        self.assertTrue(set(inputs[0]["text"][:-1]) <= set("0123456789"))

    def test_small_size_is_clamped(self):
        inputs = build_adversarial_inputs("a+", size=1, max_inputs=1)
        self.assertGreaterEqual(len(inputs[0]["text"]), 4)


class ProbeTests(unittest.TestCase):
    def test_safe_pattern_completes_fast(self):
        result = probe(r"a+$", "a" * 32 + "!", timeout_s=5.0)
        self.assertEqual(result["status"], "completed")
        self.assertLess(result["elapsed_s"], 0.5)
        self.assertLess(result["wall_s"], 5.0)

    def test_catastrophic_pattern_times_out(self):
        result = probe(r"(a+)+$", "a" * 40 + "!", timeout_s=0.3)
        self.assertEqual(result["status"], "timeout")
        self.assertGreaterEqual(result["wall_s"], 0.25)
        self.assertLess(result["wall_s"], 10.0)

    def test_plain_search_still_returns_matched(self):
        result = probe(r"\d+", "abc 123", timeout_s=5.0)
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["matched"])

    def test_invalid_pattern_reports_invalid(self):
        result = probe("(", "abc", timeout_s=5.0)
        self.assertEqual(result["status"], "invalid")
        self.assertIn("error", result)


class ClassificationTests(unittest.TestCase):
    def test_timeout_result_becomes_high_finding(self):
        results = [
            {
                "status": "timeout",
                "wall_s": 2.01,
                "timeout_s": 2.0,
                "input_length": 41,
                "input_preview": "aaa…",
                "label": "repeat + non-matching terminator",
                "matched": None,
            }
        ]
        findings = dynamic_findings(results)
        self.assertEqual([(finding.code, finding.severity) for finding in findings], [("RG-DYNAMIC-TIMEOUT", "high")])

    def test_slow_result_becomes_medium_finding(self):
        results = [
            {
                "status": "completed",
                "elapsed_s": SLOW_THRESHOLD_S + 0.1,
                "wall_s": 0.2,
                "timeout_s": 2.0,
                "input_length": 41,
                "input_preview": "aaa…",
                "label": "repeat + non-matching terminator",
                "matched": False,
            }
        ]
        findings = dynamic_findings(results)
        self.assertEqual([(finding.code, finding.severity) for finding in findings], [("RG-DYNAMIC-SLOW", "medium")])

    def test_fast_results_produce_no_findings(self):
        results = [
            {
                "status": "completed",
                "elapsed_s": 0.000001,
                "wall_s": 0.05,
                "timeout_s": 2.0,
                "input_length": 41,
                "input_preview": "aaa…",
                "label": "repeat",
                "matched": False,
            }
        ]
        self.assertEqual(dynamic_findings(results), [])


class CheckTests(unittest.TestCase):
    def test_static_only_when_timeout_is_none(self):
        result = check(r"(a+)+$")
        self.assertTrue(result["dynamic_enabled"] is False)
        self.assertEqual(result["dynamic"], [])
        self.assertEqual([finding["code"] for finding in result["findings"]], ["RG-NESTED-QUANT"])

    def test_safe_pattern_dynamic_run_has_no_dynamic_findings(self):
        result = check(r"a+$", timeout_s=0.5, size=8, max_inputs=1)
        self.assertTrue(result["dynamic_enabled"])
        self.assertEqual([finding["code"] for finding in result["findings"]], [])

    def test_catastrophic_pattern_dynamic_run_reports_timeout(self):
        result = check(r"(a+)+$", timeout_s=0.3, size=40, max_inputs=1)
        codes = [finding["code"] for finding in result["findings"]]
        self.assertIn("RG-NESTED-QUANT", codes)
        self.assertIn("RG-DYNAMIC-TIMEOUT", codes)

    def test_invalid_pattern_raises(self):
        with self.assertRaises(RegexParseError):
            check("(")

    def test_dynamic_scan_honours_max_inputs(self):
        results = dynamic_scan(r"(a|aa)+$", timeout_s=0.2, size=32, max_inputs=2)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(result["status"] in ("timeout", "completed", "invalid", "error") for result in results))

    def test_user_input_is_used(self):
        result = check(r"a+$", timeout_s=1.0, text="aaa")
        self.assertEqual(len(result["dynamic"]), 1)
        self.assertEqual(result["dynamic"][0]["label"], "user-provided input")


if __name__ == "__main__":
    unittest.main()
