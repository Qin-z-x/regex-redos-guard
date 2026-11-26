"""Static heuristics: known ReDoS patterns vs safe patterns."""

from __future__ import annotations

import unittest

from redos_guard import RegexParseError, explain, parse_pattern, scan_pattern


def codes(pattern):
    return [finding.code for finding in scan_pattern(pattern)]


def high(pattern):
    return [finding.code for finding in scan_pattern(pattern) if finding.severity == "high"]


class NestedQuantifierTests(unittest.TestCase):
    def test_classic_catastrophic_nested_quantifier(self):
        self.assertEqual(high("(a+)+$"), ["RG-NESTED-QUANT"])

    def test_star_inside_star(self):
        self.assertEqual(high("(a*)*"), ["RG-NESTED-QUANT"])

    def test_dot_star_group(self):
        self.assertEqual(high("(.*)*"), ["RG-NESTED-QUANT"])

    def test_digit_nested(self):
        self.assertEqual(high(r"^(\d+)+$"), ["RG-NESTED-QUANT"])

    def test_word_nested_with_optional_space(self):
        self.assertEqual(high(r"(\w+\s?)+"), ["RG-NESTED-QUANT"])

    def test_bounded_outer_is_medium(self):
        findings = scan_pattern("(a+){3}")
        self.assertEqual([(finding.code, finding.severity) for finding in findings], [("RG-NESTED-QUANT", "medium")])

    def test_atomic_group_is_not_flagged(self):
        self.assertEqual(scan_pattern("(?>a+)+"), [])

    def test_possessive_quantifier_is_not_flagged(self):
        self.assertEqual(scan_pattern("a++"), [])
        self.assertEqual(scan_pattern("(a+)++"), [])

    def test_single_quantifier_is_safe(self):
        self.assertEqual(scan_pattern("a+"), [])

    def test_delimited_group_repeat_is_safe(self):
        # Mandatory separator between iterations: no ambiguous split -> safe.
        self.assertEqual(scan_pattern(r"(?:-[a-z0-9]+)*"), [])
        self.assertEqual(scan_pattern(r"([a-z0-9]+\.)+"), [])
        self.assertEqual(scan_pattern(r"^[a-z0-9]+(?:-[a-z0-9]+)*$"), [])

    def test_alternation_with_inner_repeat_is_ambiguous(self):
        self.assertEqual(high("(foo|a+)*"), ["RG-NESTED-QUANT"])


class AlternationTests(unittest.TestCase):
    def test_overlapping_prefix_alternation(self):
        self.assertEqual(high("(a|aa)+$"), ["RG-OVERLAP-ALT"])

    def test_identical_branches(self):
        self.assertEqual(high("(a|a)+$"), ["RG-OVERLAP-ALT"])

    def test_longer_prefix_branch(self):
        self.assertEqual(high("(foo|foobar)+"), ["RG-OVERLAP-ALT"])

    def test_disjoint_alternation_is_safe(self):
        self.assertEqual(scan_pattern("(foo|bar)+"), [])

    def test_alternation_without_repeat_is_safe(self):
        self.assertEqual(scan_pattern("(a|aa)"), [])

    def test_bounded_overlapping_alternation_is_medium(self):
        findings = scan_pattern("(a|aa){2}")
        self.assertEqual([(finding.code, finding.severity) for finding in findings], [("RG-OVERLAP-ALT", "medium")])


class BackreferenceTests(unittest.TestCase):
    def test_repeated_backreference_is_high(self):
        self.assertEqual(high(r"^(\w+)\1+$"), ["RG-BACKREF-REPEAT"])

    def test_backreference_inside_repeated_group_is_high(self):
        self.assertTrue(scan_pattern(r"((\w+)\2)+"))

    def test_plain_backreference_is_not_flagged(self):
        self.assertEqual(scan_pattern(r"(\w+)-\1"), [])


class AdjacentRepeatTests(unittest.TestCase):
    def test_overlapping_adjacent_word_repeats(self):
        findings = scan_pattern(r"\w+\w+")
        self.assertEqual([(finding.code, finding.severity) for finding in findings], [("RG-ADJACENT-REPEAT", "medium")])

    def test_dot_repeats_are_quadratic_risk(self):
        self.assertIn("RG-ADJACENT-REPEAT", codes(".*.*"))

    def test_disjoint_adjacent_repeats_are_safe(self):
        self.assertEqual(scan_pattern(r"\w+\s+"), [])

    def test_bounded_adjacent_repeats_are_safe(self):
        self.assertEqual(scan_pattern(r"\w{2,4}\w{2,4}"), [])


class SafePatternTests(unittest.TestCase):
    def test_date_pattern(self):
        self.assertEqual(scan_pattern(r"^\d{4}-\d{2}-\d{2}$"), [])

    def test_character_class(self):
        self.assertEqual(scan_pattern("^[a-z]+$"), [])

    def test_email_ish(self):
        self.assertEqual(scan_pattern(r"^[\w.+-]+@[\w-]+\.[\w.]+$"), [])

    def test_group_repeat_without_nesting(self):
        self.assertEqual(scan_pattern(r"(?:ab)+$"), [])

    def test_inline_flags(self):
        self.assertEqual(scan_pattern("(?i)abc"), [])

    def test_anchors_and_classes(self):
        self.assertEqual(scan_pattern(r"^https?://[a-z0-9.-]+/[a-z0-9/_-]*$"), [])


class ParseAndExplainTests(unittest.TestCase):
    def test_invalid_regex_raises(self):
        with self.assertRaises(RegexParseError):
            scan_pattern("(")

    def test_empty_pattern_raises(self):
        with self.assertRaises(RegexParseError):
            scan_pattern("")

    def test_unbalanced_class_raises(self):
        with self.assertRaises(RegexParseError):
            scan_pattern("[abc")

    def test_parse_returns_tree(self):
        tree = parse_pattern(r"ab(c|d)+")
        self.assertEqual(tree["type"], "seq")

    def test_explain_lists_suggestions(self):
        result = explain("(a+)+$")
        self.assertTrue(result["valid"])
        self.assertFalse(result["safe_static"])
        self.assertEqual(len(result["suggestions"]), 1)
        self.assertIn("quantifier", result["suggestions"][0]["suggestion"].lower())

    def test_explain_safe_pattern(self):
        result = explain(r"^\d{4}-\d{2}-\d{2}$")
        self.assertTrue(result["safe_static"])
        self.assertEqual(result["suggestions"], [])

    def test_explain_invalid_pattern(self):
        result = explain("(")
        self.assertFalse(result["valid"])
        self.assertIn("error", result)

    def test_findings_are_deterministic_and_ordered(self):
        first = [finding.to_dict() for finding in scan_pattern(r"(\w+\s?)+$")]
        second = [finding.to_dict() for finding in scan_pattern(r"(\w+\s?)+$")]
        self.assertEqual(first, second)
        keys = [(finding["start"], finding["end"], finding["code"]) for finding in first]
        self.assertEqual(keys, sorted(keys))


if __name__ == "__main__":
    unittest.main()
