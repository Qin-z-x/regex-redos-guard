"""Validate emitted JSON against the published JSON Schemas."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from redos_guard.dynamic import check
from redos_guard.files import scan_file
from tests.schema_lite import validate

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
EXAMPLES = ROOT / "examples" / "llm_generated_patterns.py"


def load_schema(name: str) -> dict:
    return json.loads((DOCS / name).read_text(encoding="utf-8"))


class SchemaTests(unittest.TestCase):
    def test_schemas_are_valid_json(self):
        for name in ("finding.schema.json", "check-result.schema.json", "scan-file-result.schema.json"):
            schema = load_schema(name)
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_check_result_matches_schema(self):
        result = check("(a+)+$")
        self.assertEqual(validate(result, load_schema("check-result.schema.json")), [])
        finding_schema = load_schema("finding.schema.json")
        for finding in result["findings"]:
            self.assertEqual(validate(finding, finding_schema), [])

    def test_check_result_with_dynamic_matches_schema(self):
        result = check(r"a+$", timeout_s=0.5, size=8, max_inputs=1)
        self.assertEqual(validate(result, load_schema("check-result.schema.json")), [])

    def test_scan_file_result_matches_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "patterns.py"
            path.write_text('import re\nP = re.compile(r"(a+)+$")\n', encoding="utf-8")
            result = scan_file(path)
        self.assertEqual(validate(result, load_schema("scan-file-result.schema.json")), [])

    def test_schema_rejects_bad_finding(self):
        schema = load_schema("finding.schema.json")
        bad = {"code": "NOPE", "severity": "critical", "start": -1, "end": 0, "message": "", "suggestion": "", "data": {}}
        self.assertNotEqual(validate(bad, schema), [])


if __name__ == "__main__":
    unittest.main()
