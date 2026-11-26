"""redos-guard: static + dynamic ReDoS analysis for LLM-generated regexes.

Public API::

    from redos_guard import scan_pattern, explain, check, scan_file

    findings = scan_pattern(r"(a+)+$")            # static structural findings
    result   = check(r"(a+)+$", timeout_s=2.0)    # + dynamic child-process probes
    report   = scan_file("patterns.py")           # scan a Python file/directory
"""

from __future__ import annotations

from .core import (
    Finding,
    RegexParseError,
    SEVERITY_ORDER,
    explain,
    format_finding_line,
    parse_pattern,
    scan_pattern,
    severity_at_least,
    summarize,
)
from .dynamic import build_adversarial_inputs, check, dynamic_findings, dynamic_scan, probe
from .files import extract_python_patterns, scan_file

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "RegexParseError",
    "SEVERITY_ORDER",
    "build_adversarial_inputs",
    "check",
    "dynamic_findings",
    "dynamic_scan",
    "explain",
    "extract_python_patterns",
    "format_finding_line",
    "parse_pattern",
    "probe",
    "scan_file",
    "scan_pattern",
    "severity_at_least",
    "summarize",
    "__version__",
]
