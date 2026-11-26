"""Scan source files for regex literals and analyse them.

Python files are parsed with :mod:`ast`: calls such as ``re.compile(...)``,
``re.search(...)``, ``re.fullmatch(...)`` with a **constant string** first
argument are analysed. Non-constant patterns (f-strings, variables) cannot be
analysed statically and are counted as skipped rather than guessed. Other
languages are not parsed (see docs/THREAT_MODEL.md); a JavaScript/PCRE literal
pass is intentionally left out to avoid heuristic false positives.
"""

from __future__ import annotations

import ast
from pathlib import Path

from .core import VERSION, RegexParseError, scan_pattern, summarize

REGEX_CALL_NAMES = frozenset(
    {"compile", "search", "match", "fullmatch", "findall", "finditer", "sub", "subn", "split"}
)
SKIP_DIRS = frozenset(
    {".git", "__pycache__", ".venv", "venv", "env", "build", "dist", "site-packages", "node_modules", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
)


def _call_name(node: ast.Call) -> str | None:
    function = node.func
    if isinstance(function, ast.Attribute) and function.attr in REGEX_CALL_NAMES:
        return function.attr
    if isinstance(function, ast.Name) and function.id in REGEX_CALL_NAMES:
        return function.id
    return None


def extract_python_patterns(text: str) -> tuple[list[dict], int]:
    """Return (patterns, dynamic_skipped_count) found in Python source ``text``."""
    tree = ast.parse(text)
    patterns: list[dict] = []
    dynamic = 0
    seen: set[tuple[int, int, str]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if not name or not node.args:
            continue
        first = node.args[0]
        if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
            dynamic += 1
            continue
        key = (node.lineno, node.col_offset, first.value)
        if key in seen:
            continue
        seen.add(key)
        patterns.append(
            {
                "pattern": first.value,
                "line": node.lineno,
                "column": node.col_offset + 1,
                "call": name,
            }
        )
    patterns.sort(key=lambda item: (item["line"], item["column"], item["pattern"]))
    return patterns, dynamic


def discover_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    files: list[Path] = []
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        files.append(path)
    return files


def scan_file(
    path: str | Path,
    timeout_s: float | None = None,
    size: int = 40,
    max_inputs: int = 2,
) -> dict:
    """Scan a Python file or directory for risky regexes."""
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(str(path))
    entries: list[dict] = []
    errors: list[dict] = []
    findings_flat: list[dict] = []
    dynamic_skipped_total = 0
    dynamic_timeouts = 0
    files = discover_files(root)
    for file_path in files:
        source = file_path.name if root.is_file() else file_path.relative_to(root).as_posix()
        try:
            text = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            errors.append({"file": source, "error": "cannot read UTF-8: %s" % exc})
            continue
        try:
            patterns, dynamic_skipped = extract_python_patterns(text)
        except SyntaxError as exc:
            errors.append({"file": source, "error": "invalid Python: %s" % exc.msg})
            continue
        dynamic_skipped_total += dynamic_skipped
        if dynamic_skipped:
            entries.append(
                {
                    "source_file": source,
                    "pattern": None,
                    "line": 0,
                    "column": 0,
                    "dynamic_skipped": dynamic_skipped,
                    "note": "non-constant pattern argument cannot be analysed statically",
                }
            )
        for pattern_info in patterns:
            finding_list = []
            dynamic_results: list[dict] = []
            error = None
            try:
                findings = scan_pattern(pattern_info["pattern"])
                if timeout_s is not None and timeout_s > 0:
                    from .dynamic import dynamic_findings, dynamic_scan

                    dynamic_results = dynamic_scan(
                        pattern_info["pattern"], timeout_s=timeout_s, size=size, max_inputs=max_inputs
                    )
                    findings = findings + dynamic_findings(dynamic_results)
                    dynamic_timeouts += sum(1 for result in dynamic_results if result["status"] == "timeout")
                finding_list = [finding.to_dict() for finding in findings]
            except RegexParseError as exc:
                error = str(exc)
            entries.append(
                {
                    "source_file": source,
                    "pattern": pattern_info["pattern"],
                    "line": pattern_info["line"],
                    "column": pattern_info["column"],
                    "call": pattern_info["call"],
                    "findings": finding_list,
                    "dynamic": dynamic_results,
                    "error": error,
                }
            )
            for finding in finding_list:
                findings_flat.append(
                    {
                        **finding,
                        "pattern": pattern_info["pattern"],
                        "source_file": source,
                        "line": pattern_info["line"],
                        "column": pattern_info["column"],
                    }
                )
    findings_flat.sort(
        key=lambda finding: (finding["source_file"], finding["line"], finding["start"], finding["code"])
    )
    summary = summarize([type("F", (), {"severity": finding["severity"]})() for finding in findings_flat])
    summary.update(
        {
            "files": len(files),
            "patterns": len([entry for entry in entries if entry.get("pattern") is not None]),
            "dynamic_skipped": dynamic_skipped_total,
            "dynamic_timeouts": dynamic_timeouts,
        }
    )
    return {
        "tool": "redos-guard",
        "version": VERSION,
        "path": str(path),
        "entries": entries,
        "findings": findings_flat,
        "errors": errors,
        "summary": summary,
        "dynamic_enabled": timeout_s is not None and timeout_s > 0,
        "caveat": "Static heuristics plus sampled dynamic timing; not a proof for all inputs.",
    }
