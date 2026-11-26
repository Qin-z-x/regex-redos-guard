"""Command line interface for redos-guard.

Exit codes (stable, CI-gate friendly)::

    0  success (for check/scan-file: no finding at/above the --fail-on threshold)
    1  --fail-on threshold reached
    2  usage error, unreadable path, or a pattern the analyser cannot parse
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .core import SEVERITY_ORDER, RegexParseError, explain, severity_at_least
from .dynamic import check
from .files import scan_file

_TOOL = "redos-guard " + __version__


def _force_utf8_output() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):  # pragma: no cover
                pass


def _shorten(text: str, limit: int = 72) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _print_finding(finding: dict, indent: str = "") -> None:
    print(
        "%s%s %-20s @%d-%d  %s"
        % (
            indent,
            finding["severity"].upper().ljust(6),
            finding["code"],
            finding["start"],
            finding["end"],
            finding["message"],
        )
    )
    if finding.get("suggestion"):
        print("%s    suggestion: %s" % (indent, finding["suggestion"]))


def _print_dynamic(results: list[dict]) -> None:
    for result in results:
        if result["status"] == "timeout":
            print(
                "DYNAMIC TIMEOUT  exceeded %.2fs on %r (%d chars); total wall time %.2fs"
                % (result["timeout_s"], result["label"], result["input_length"], result["wall_s"])
            )
        elif result["status"] == "completed":
            print(
                "DYNAMIC          %.4fs on %r (%d chars), matched=%s"
                % (result["elapsed_s"], result["label"], result["input_length"], result["matched"])
            )
        else:
            print("DYNAMIC ERROR    %r: %s" % (result["label"], result.get("error", result["status"])))


def _gate(findings: list[dict], fail_on: str | None, quiet: bool) -> int:
    if not fail_on:
        return 0
    hits = [finding for finding in findings if severity_at_least(finding["severity"], fail_on)]
    if hits:
        if not quiet:
            print("FAIL: %d finding(s) at or above severity %r (--fail-on %s)" % (len(hits), fail_on, fail_on))
        return 1
    if not quiet:
        print("OK: no finding at or above severity %r" % fail_on)
    return 0


def _print_check(args) -> int:
    try:
        result = check(args.pattern, timeout_s=args.timeout, text=args.input, size=args.size)
    except RegexParseError as exc:
        print("error: cannot parse pattern: %s" % exc, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("%s  check  %r" % (_TOOL, args.pattern))
        for finding in result["findings"]:
            _print_finding(finding)
        if result["dynamic"]:
            _print_dynamic(result["dynamic"])
        summary = result["summary"]
        print(
            "summary: %d finding(s): %d high, %d medium, %d low%s"
            % (
                summary["total"],
                summary["high"],
                summary["medium"],
                summary["low"],
                " | dynamic probes: %d" % len(result["dynamic"]) if result["dynamic"] else " (static only; pass --timeout N for dynamic probes)",
            )
        )
    return _gate(result["findings"], args.fail_on, args.json)


def _print_scan_file(args) -> int:
    try:
        result = scan_file(args.path, timeout_s=args.timeout, size=args.size)
    except FileNotFoundError:
        print("error: path not found: %s" % args.path, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        summary = result["summary"]
        print(
            "%s  scan-file  %s  (%d files, %d constant patterns%s)"
            % (
                _TOOL,
                result["path"],
                summary["files"],
                summary["patterns"],
                ", dynamic probes enabled" if result["dynamic_enabled"] else "",
            )
        )
        for error in result["errors"]:
            print("warning: %s: %s" % (error["file"], error["error"]))
        for entry in result["entries"]:
            if entry.get("pattern") is None:
                print("note: %s: %s" % (entry["source_file"], entry.get("note", "skipped")))
                continue
            status = "SAFE  " if not entry["findings"] else "RISK  "
            print("%s %s:%d  %r" % (status, entry["source_file"], entry["line"], _shorten(entry["pattern"], 88)))
            if entry.get("error"):
                print("    error: cannot parse pattern: %s" % entry["error"])
            for finding in entry["findings"]:
                _print_finding(finding, indent="    ")
        print(
            "summary: %d pattern(s) analysed, %d finding(s): %d high, %d medium, %d low"
            % (summary["patterns"], summary["total"], summary["high"], summary["medium"], summary["low"])
        )
    return _gate(result["findings"], args.fail_on, args.json)


def _print_explain(args) -> int:
    explanation = explain(args.pattern)
    print(json.dumps(explanation, indent=2, ensure_ascii=False))
    return 0 if explanation["valid"] else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redos-guard",
        description="Detect catastrophic-backtracking (ReDoS) risk in LLM-generated regular expressions.",
    )
    parser.add_argument("--version", action="version", version=_TOOL)
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check", help="analyse one regex pattern")
    check_parser.add_argument("pattern", help="the regular expression to analyse")
    check_parser.add_argument(
        "--timeout", type=float, metavar="SECONDS", help="enable dynamic probes with this per-input timeout (e.g. 2)"
    )
    check_parser.add_argument("--input", help="use this exact input for the dynamic probe instead of generated inputs")
    check_parser.add_argument("--size", type=int, default=40, help="length of generated adversarial inputs (default 40)")
    check_parser.add_argument("--json", action="store_true", help="machine-readable JSON output")
    check_parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default=None)
    check_parser.set_defaults(func=_print_check)

    scan_parser = subparsers.add_parser("scan-file", help="scan a Python file or directory for regex literals")
    scan_parser.add_argument("path")
    scan_parser.add_argument("--timeout", type=float, metavar="SECONDS", help="enable dynamic probes with this per-input timeout")
    scan_parser.add_argument("--size", type=int, default=40)
    scan_parser.add_argument("--json", action="store_true", help="machine-readable JSON output")
    scan_parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default=None)
    scan_parser.set_defaults(func=_print_scan_file)

    explain_parser = subparsers.add_parser("explain", help="static findings + safer-pattern suggestions as JSON")
    explain_parser.add_argument("pattern")
    explain_parser.set_defaults(func=_print_explain)

    return parser


def main(argv: list[str] | None = None) -> int:
    _force_utf8_output()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
