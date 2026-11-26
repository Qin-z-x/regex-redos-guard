"""Dynamic ReDoS probing: measure real wall time in a child process.

The static analysis in :mod:`redos_guard.core` is structural; this module tests
actual behaviour on generated adversarial inputs. Each attempt runs in a separate
Python child process with a hard timeout, so a catastrophic pattern is killed
without hanging the scanning process. Results are measurements for the sampled
inputs — not a proof about all inputs (see docs/THREAT_MODEL.md).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time

from .core import VERSION, Finding, scan_pattern, summarize

SLOW_THRESHOLD_S = 0.1
DEFAULT_TIMEOUT_S = 2.0
DEFAULT_INPUT_SIZE = 40

_CHILD_RUNNER = r"""
import json, re, sys, time

payload = json.loads(sys.argv[1])
pattern = payload["pattern"]
text = payload["text"]
try:
    compiled = re.compile(pattern)
except re.error as exc:
    print(json.dumps({"status": "invalid", "error": str(exc)}))
    raise SystemExit(0)
start = time.perf_counter()
try:
    match = compiled.search(text)
except Exception as exc:  # noqa: BLE001 - report engine errors honestly
    print(json.dumps({"status": "error", "error": str(exc)}))
    raise SystemExit(0)
elapsed = time.perf_counter() - start
print(json.dumps({"status": "completed", "elapsed_s": elapsed, "matched": bool(match)}))
"""


def _base_char(pattern: str) -> str:
    """Pick a character likely to match the repeated atom (for adversarial input)."""
    if "\\d" in pattern:
        return "7"
    if "\\w" in pattern:
        return "a"
    if "\\s" in pattern:
        return " "
    class_match = re.search(r"\[(?:\^)?([^\]\\])", pattern)
    if class_match:
        candidate = class_match.group(1)
        if candidate.isalnum() and candidate not in ".*+?(){}[]|^$":
            return candidate
    literals = [char for char in pattern if char.isalnum()]
    if literals:
        return literals[0]
    escaped = re.search(r"\\([^A-Za-z0-9])", pattern)
    if escaped:
        return escaped.group(1)
    return "a"


def _terminator(pattern: str, base: str) -> str:
    for candidate in ("!", "#", "\n", "%", "Z", "~"):
        if candidate != base and candidate not in pattern:
            return candidate
    for candidate in ("!", "#", "%", "Z"):
        if candidate != base:
            return candidate
    return "!"


def build_adversarial_inputs(
    pattern: str,
    size: int = DEFAULT_INPUT_SIZE,
    max_inputs: int = 3,
) -> list[dict]:
    """Generate a small set of inputs that stress ambiguous repetition.

    Strategy: a long run of the likely repeated character, optionally followed by a
    character that does not match, so the engine must try many partitions before
    failing. Deliberately small and deterministic.
    """
    if size < 4:
        size = 4
    base = _base_char(pattern)
    terminator = _terminator(pattern, base)
    candidates = [
        {"label": "repeat + non-matching terminator", "text": base * size + terminator},
        {"label": "plain repeat", "text": base * size},
        {"label": "repeat + separator + repeat", "text": base * (size // 2) + terminator + base * (size // 2)},
    ]
    inputs: list[dict] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate["text"] in seen:
            continue
        seen.add(candidate["text"])
        inputs.append(candidate)
        if len(inputs) >= max_inputs:
            break
    return inputs


def probe(
    pattern: str,
    text: str,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    python: str | None = None,
) -> dict:
    """Run one regex match in a child process and report wall time or timeout."""
    python = python or sys.executable
    payload = json.dumps({"pattern": pattern, "text": text})
    started = time.perf_counter()
    try:
        process = subprocess.run(
            [python, "-c", _CHILD_RUNNER, payload],
            capture_output=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        wall = time.perf_counter() - started
        return {
            "status": "timeout",
            "wall_s": wall,
            "timeout_s": timeout_s,
            "input_length": len(text),
            "input_preview": _preview(text),
            "matched": None,
        }
    wall = time.perf_counter() - started
    stdout = process.stdout.decode("utf-8", "replace").strip().splitlines()
    result: dict = {"wall_s": wall, "timeout_s": timeout_s, "input_length": len(text), "input_preview": _preview(text)}
    if stdout:
        try:
            payload_result = json.loads(stdout[-1])
        except ValueError:
            payload_result = {"status": "error", "error": "unparsable child output: %r" % stdout[-1][:200]}
        result.update(payload_result)
    else:
        result.update({"status": "error", "error": "child produced no output (exit %d)" % process.returncode})
    if process.returncode != 0 and result.get("status") == "completed":
        result["status"] = "error"
        result["error"] = "child exited %d" % process.returncode
    return result


def _preview(text: str, limit: int = 24) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "…(%d chars)" % len(text)


def dynamic_scan(
    pattern: str,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    size: int = DEFAULT_INPUT_SIZE,
    max_inputs: int = 3,
    python: str | None = None,
    inputs: list[dict] | None = None,
) -> list[dict]:
    """Probe generated adversarial inputs and report measurements."""
    inputs = inputs if inputs is not None else build_adversarial_inputs(pattern, size=size, max_inputs=max_inputs)
    results: list[dict] = []
    for candidate in inputs:
        result = probe(pattern, candidate["text"], timeout_s=timeout_s, python=python)
        result["label"] = candidate["label"]
        results.append(result)
    return results


def dynamic_findings(results: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for result in results:
        if result["status"] == "timeout":
            findings.append(
                Finding(
                    code="RG-DYNAMIC-TIMEOUT",
                    severity="high",
                    start=0,
                    end=0,
                    message="dynamic probe exceeded %.2fs on %r (%d chars): measured wall time ≥%.2fs"
                    % (
                        result["timeout_s"],
                        result["label"],
                        result["input_length"],
                        result["wall_s"],
                    ),
                    suggestion="Constrain the repetition (bounded {m,n}), remove nested quantifiers, or "
                    "use an atomic/possessive construct; consider an input length cap before matching.",
                    data=result,
                )
            )
        elif result["status"] == "completed" and float(result.get("elapsed_s", 0.0)) >= SLOW_THRESHOLD_S:
            findings.append(
                Finding(
                    code="RG-DYNAMIC-SLOW",
                    severity="medium",
                    start=0,
                    end=0,
                    message="dynamic probe took %.3fs on %r (%d chars): slower than the %.2fs threshold"
                    % (float(result["elapsed_s"]), result["label"], result["input_length"], SLOW_THRESHOLD_S),
                    suggestion="Consider bounding the repetition; verify performance with longer inputs and a "
                    "realistic input size limit.",
                    data=result,
                )
            )
    return findings


def check(
    pattern: str,
    timeout_s: float | None = None,
    text: str | None = None,
    size: int = DEFAULT_INPUT_SIZE,
    max_inputs: int = 3,
) -> dict:
    """Static scan + optional dynamic probes, returning a JSON-serializable result."""
    static_findings = scan_pattern(pattern)
    dynamic_results: list[dict] = []
    dynamic: list[Finding] = []
    if timeout_s is not None and timeout_s > 0:
        if text is not None:
            result = probe(pattern, text, timeout_s=timeout_s)
            result["label"] = "user-provided input"
            dynamic_results = [result]
        else:
            dynamic_results = dynamic_scan(pattern, timeout_s=timeout_s, size=size, max_inputs=max_inputs)
        dynamic = dynamic_findings(dynamic_results)
    findings = static_findings + dynamic
    payload = {
        "tool": "redos-guard",
        "version": VERSION,
        "pattern": pattern,
        "findings": [finding.to_dict() for finding in findings],
        "summary": summarize(findings),
        "static_summary": summarize(static_findings),
        "dynamic": dynamic_results,
        "dynamic_enabled": bool(dynamic_results),
        "caveat": "Heuristic static analysis plus sampled dynamic timing; not a proof for all inputs.",
    }
    return payload
