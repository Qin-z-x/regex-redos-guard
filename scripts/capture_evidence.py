"""Capture the real evidence used by docs/EVIDENCE.md.

Everything is measured on the build machine: static results are deterministic;
dynamic results are real wall-clock measurements from child processes with hard
timeouts (including genuine timeouts and one completed safe rewrite for contrast).

Regenerates:

  * evidence/static_cases.json       (static analysis of the case matrix)
  * evidence/dynamic_runs.json       (real child-process timings/timeouts)
  * evidence/scan_file.json          (scan of examples/llm_generated_patterns.py)
  * evidence/explain.json            (explanation + rewrite hints)
  * evidence/terminal/*.txt          (verbatim CLI session text)
  * evidence/raw/unit_test_output.txt
  * docs/screenshots/terminal_*.png  (rendered from the captured text)
  * docs/EVIDENCE.md

Usage::

    python scripts/capture_evidence.py
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from redos_guard import __version__, explain, scan_pattern  # noqa: E402
from redos_guard.dynamic import build_adversarial_inputs, probe  # noqa: E402

STATIC_CASES = [
    ("(a+)+$", "catastrophic: nested quantifiers"),
    ("(a|aa)+$", "catastrophic: overlapping alternation"),
    (r"^(\w+)\1+$", "catastrophic: repeated backreference"),
    (r"(\w+\s?)+", "catastrophic: nested words"),
    ("(a+){3}", "bounded nested quantifier"),
    (r"\w+\w+", "quadratic: adjacent overlapping repeats"),
    (r"^\d{4}-\d{2}-\d{2}$", "safe: date"),
    ("(?:ab)+$", "safe: delimited group repeat"),
    (r"(?:-[a-z0-9]+)*", "safe: separator-delimited group repeat"),
]

DYNAMIC_CASES = [
    ("catastrophic nested quantifier", "(a+)+$", 40, 2.0),
    ("catastrophic overlapping alternation", "(a|aa)+$", 40, 2.0),
    ("safe rewrite of the nested pattern", "a+$", 40, 2.0),
    ("safe delimited group repeat", "(?:-[a-z0-9]+)*$", 40, 2.0),
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def write_json(path: Path, payload) -> None:
    write_text(path, json.dumps(payload, indent=2, ensure_ascii=True) + "\n")


def run_python(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *args], cwd=str(ROOT), capture_output=True, timeout=900)


def run_cli(*args: str) -> dict:
    process = run_python(["-m", "redos_guard", *args])
    stdout = process.stdout.decode("utf-8", "replace")
    stderr = process.stderr.decode("utf-8", "replace")
    return {
        "argv": ["python", "-m", "redos_guard", *args],
        "exit_code": process.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_sha256": sha256_text(stdout),
    }


def terminal_session(runs: list[dict]) -> str:
    lines = ["Windows PowerShell - redos-guard evidence session (real captured output)", ""]
    for run in runs:
        lines.append("$ " + " ".join(run["argv"]))
        lines.append(run["stdout"].rstrip("\n"))
        if run["stderr"].strip():
            lines.append(run["stderr"].rstrip("\n"))
        lines.append("[exit code: %d]" % run["exit_code"])
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def run_ps_render(input_file: Path, output_file: Path, title: str) -> dict:
    script = ROOT / "scripts" / "render_terminal_screenshot.ps1"
    process = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-InputFile",
            str(input_file),
            "-OutputFile",
            str(output_file),
            "-Title",
            title,
        ],
        cwd=str(ROOT),
        capture_output=True,
        timeout=180,
    )
    result = {
        "input": str(input_file.relative_to(ROOT)),
        "output": str(output_file.relative_to(ROOT)),
        "exit_code": process.returncode,
        "stdout": process.stdout.decode("utf-8", "replace").strip(),
        "stderr": process.stderr.decode("utf-8", "replace").strip()[-400:],
    }
    if output_file.is_file():
        data = output_file.read_bytes()
        result["bytes"] = len(data)
        result["sha256"] = sha256_bytes(data)
    return result


def main() -> int:
    captured_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    env = {"os": platform.platform(), "python": platform.python_version(), "captured_at": captured_at}

    # 1) Static case matrix (deterministic).
    static_cases = []
    for pattern, label in STATIC_CASES:
        findings = [finding.to_dict() for finding in scan_pattern(pattern)]
        static_cases.append({"pattern": pattern, "label": label, "findings": findings})
    write_json(ROOT / "evidence" / "static_cases.json", static_cases)

    # 2) Dynamic measurements: real child processes with hard timeouts.
    dynamic_runs = []
    for label, pattern, size, timeout_s in DYNAMIC_CASES:
        generated = build_adversarial_inputs(pattern, size=size, max_inputs=1)[0]
        result = probe(pattern, generated["text"], timeout_s=timeout_s)
        result.update({"case": label, "pattern": pattern, "input_label": generated["label"]})
        dynamic_runs.append(result)
        print("dynamic %-38s %-34r %s (wall %.2fs)" % (label, pattern, result["status"], result["wall_s"]))
    write_json(ROOT / "evidence" / "dynamic_runs.json", dynamic_runs)

    # 3) Explanation output (suggestions).
    explanation = explain("(a+)+$")
    write_json(ROOT / "evidence" / "explain.json", explanation)

    # 4) CLI sessions + exit codes.
    static_runs = [
        run_cli("check", "(a+)+$"),
        run_cli("check", "(a+)+$", "--fail-on", "high"),
        run_cli("check", r"^\d{4}-\d{2}-\d{2}$", "--fail-on", "high"),
    ]
    dynamic_input = "a" * 40 + "!"
    dynamic_runs_cli = [
        run_cli("check", "(a+)+$", "--timeout", "1", "--input", dynamic_input),
        run_cli("check", "a+$", "--timeout", "1", "--input", dynamic_input),
    ]
    scan_file_human = run_cli("scan-file", "examples/llm_generated_patterns.py")
    scan_file_json_run = run_cli("scan-file", "examples/llm_generated_patterns.py", "--json", "--fail-on", "high")
    scan_file_payload = json.loads(scan_file_json_run["stdout"]) if scan_file_json_run["stdout"].strip() else {}
    write_json(ROOT / "evidence" / "scan_file.json", scan_file_payload)
    scan_verify = run_python(
        [
            "-c",
            "import json\n"
            "from redos_guard import scan_file\n"
            "result = scan_file('examples/llm_generated_patterns.py')\n"
            "print('patterns analysed:', result['summary']['patterns'])\n"
            "print('findings:', result['summary']['total'], 'high:', result['summary']['high'])\n"
            "print('dynamic skipped (non-constant):', result['summary']['dynamic_skipped'])\n"
            "print('risky patterns:', [f'{e[\"source_file\"]}:{e[\"line\"]} {e[\"pattern\"]}' for e in result['entries'] if e.get('findings')])\n",
        ]
    )
    scan_verify_run = {
        "argv": ["python", "-c", "<scan-file verification one-liner>"],
        "exit_code": scan_verify.returncode,
        "stdout": scan_verify.stdout.decode("utf-8", "replace"),
        "stderr": scan_verify.stderr.decode("utf-8", "replace"),
        "stdout_sha256": sha256_text(scan_verify.stdout.decode("utf-8", "replace")),
    }
    all_runs = static_runs + dynamic_runs_cli + [scan_file_human, scan_file_json_run, scan_verify_run]
    write_json(ROOT / "evidence" / "raw" / "cli_runs.json", {"python": sys.executable, "runs": all_runs})
    write_text(ROOT / "evidence" / "terminal" / "terminal_static.txt", terminal_session(static_runs))
    write_text(ROOT / "evidence" / "terminal" / "terminal_dynamic.txt", terminal_session(dynamic_runs_cli))
    write_text(ROOT / "evidence" / "terminal" / "terminal_scan_file.txt", terminal_session([scan_file_human, scan_verify_run]))

    # 5) Tests.
    tests_proc = run_python(["-m", "unittest", "discover", "-s", "tests", "-t", "."])
    tests_text = tests_proc.stdout.decode("utf-8", "replace") + tests_proc.stderr.decode("utf-8", "replace")
    write_text(ROOT / "evidence" / "raw" / "unit_test_output.txt", tests_text)
    count_match = re.search(r"Ran (\d+) test", tests_text)
    tests = {
        "count": int(count_match.group(1)) if count_match else 0,
        "result": "OK" if tests_proc.returncode == 0 else "FAILED",
        "exit_code": tests_proc.returncode,
        "tail": "\n".join(tests_text.strip().splitlines()[-6:]),
    }
    write_text(
        ROOT / "evidence" / "terminal" / "terminal_tests.txt",
        "Windows PowerShell - unittest output\n\n" + tests_text.replace("\r\n", "\n").rstrip() + "\n",
    )

    # 6) Screenshots from the captured text.
    shots = {
        "static": run_ps_render(
            ROOT / "evidence" / "terminal" / "terminal_static.txt",
            ROOT / "docs" / "screenshots" / "terminal_static.png",
            "Windows PowerShell - redos-guard static check (real captured output)",
        ),
        "dynamic": run_ps_render(
            ROOT / "evidence" / "terminal" / "terminal_dynamic.txt",
            ROOT / "docs" / "screenshots" / "terminal_dynamic.png",
            "Windows PowerShell - redos-guard dynamic probe (real captured output)",
        ),
        "scan_file": run_ps_render(
            ROOT / "evidence" / "terminal" / "terminal_scan_file.txt",
            ROOT / "docs" / "screenshots" / "terminal_scan_file.png",
            "Windows PowerShell - redos-guard scan-file (real captured output)",
        ),
        "tests": run_ps_render(
            ROOT / "evidence" / "terminal" / "terminal_tests.txt",
            ROOT / "docs" / "screenshots" / "terminal_tests.png",
            "Windows PowerShell - redos-guard unit tests (real captured output)",
        ),
    }
    for name, shot in shots.items():
        print("render %s: %s" % (name, shot.get("stdout") or shot.get("stderr")))

    # 7) Assertions + report.
    dynamic_by_pattern = {run["pattern"]: run for run in dynamic_runs}
    catastrophic = [run for run in dynamic_runs if run["case"].startswith("catastrophic")]
    safe_rewrite = dynamic_by_pattern["a+$"]
    safe_delimited = dynamic_by_pattern["(?:-[a-z0-9]+)*$"]
    static_safe_clean = all(
        not [finding for finding in case["findings"] if finding["severity"] == "high"]
        for case in static_cases
        if case["label"].startswith("safe")
    )
    catastrophic_static_high = all(
        any(finding["severity"] == "high" for finding in case["findings"])
        for case in static_cases
        if case["label"].startswith("catastrophic")
    )
    assertions = {
        "static_detects_all_catastrophic_cases": catastrophic_static_high,
        "static_safe_controls_have_no_high_findings": static_safe_clean,
        "dynamic_evil_patterns_timeout": len(catastrophic) == 2 and all(run["status"] == "timeout" for run in catastrophic),
        "dynamic_timeout_wall_time_reaches_limit": all(run["wall_s"] >= run["timeout_s"] * 0.9 for run in catastrophic),
        "safe_rewrite_completes_fast": safe_rewrite["status"] == "completed" and safe_rewrite["elapsed_s"] < 0.01,
        "safe_delimited_pattern_completes_fast": safe_delimited["status"] == "completed" and safe_delimited["elapsed_s"] < 0.01,
        "scan_file_finds_risky_patterns": scan_file_payload.get("summary", {}).get("high", 0) >= 2,
        "tests_pass": tests_proc.returncode == 0,
    }
    finding_rows = "\n".join(
        "| `%s` | %s | %s |"
        % (
            case["pattern"],
            case["label"],
            ", ".join("`%s` %s" % (finding["code"], finding["severity"]) for finding in case["findings"]) or "– (no findings)",
        )
        for case in static_cases
    )
    dynamic_rows = "\n".join(
        "| %s | `%s` | %d | %s | %.4f | %.1f | %s |"
        % (
            run["case"],
            run["pattern"],
            run["input_length"],
            run["status"],
            run["wall_s"],
            run["timeout_s"],
            ("%.6f" % run["elapsed_s"]) if "elapsed_s" in run else "–",
        )
        for run in dynamic_runs
    )
    scan_file_rows = "\n".join(
        "| `%s` | `%s:%d` | %s |"
        % (
            entry["pattern"],
            entry["source_file"],
            entry["line"],
            ", ".join("`%s` %s" % (finding["code"], finding["severity"]) for finding in entry.get("findings", [])) or "– (safe)",
        )
        for entry in scan_file_payload.get("entries", [])
        if entry.get("pattern") is not None
    )
    assertion_rows = "\n".join(
        "| `%s` | **%s** |" % (name, "PASS" if value else "FAIL") for name, value in assertions.items()
    )
    screenshot_lines = []
    for name in ("terminal_static.png", "terminal_dynamic.png", "terminal_scan_file.png", "terminal_tests.png"):
        path = ROOT / "docs" / "screenshots" / name
        if path.is_file():
            data = path.read_bytes()
            screenshot_lines.append("- `docs/screenshots/%s` (%d bytes, sha256 `%s`)" % (name, len(data), sha256_bytes(data)[:16] + "…"))
    cli_rows = "\n".join(
        "| `%s` | %d |" % (" ".join(run["argv"][2:]), run["exit_code"]) for run in all_runs
    )
    explain_suggestion = (explanation.get("suggestions") or [{"suggestion": "–"}])[0]["suggestion"]

    report = f"""# Evidence log

This file is generated by `python scripts/capture_evidence.py` on the machine that built the project.
Static results are deterministic. Dynamic results are **real wall-clock measurements** from child
processes with hard timeouts on the build machine; they are not estimated. A timeout is a measured
misfortune of the sampled input, not a proof about every input — see the caveat.

## Scope and honesty statement

`regex-redos-guard` is a **static heuristic + sampled dynamic timing tool**, not a formal
worst-case-complexity proof. The attack class (ReDoS / catastrophic backtracking) is public prior
art; this project does not disclose a new vulnerability and does not claim a new CVE. Patterns are
standard textbook examples used for demonstration.

## Environment

| item | value |
| --- | --- |
| operating system | {env["os"]} |
| Python (CPython regex engine) | {env["python"]} |
| regex-redos-guard version | {__version__} |
| capture time (UTC) | {env["captured_at"]} |

## 1. Static analysis case matrix

| pattern | expectation | findings |
| --- | --- | --- |
{finding_rows}

The safe controls (date pattern, delimited group repeat `(?:ab)+`, separator-delimited
`(?:-[a-z0-9]+)*`) produce no high-severity findings. The nested-quantifier check only fires when
the repeated group's start and end character sets overlap (no mandatory delimiter between
iterations), which avoids flagging common safe patterns like `^[a-z0-9]+(?:-[a-z0-9]+)*$`.

## 2. Measured dynamic behaviour (child process, hard timeout)

Each probe runs a real `re.search` in a child Python process; the parent kills it on timeout.

| case | pattern | input length | status | parent wall time (s) | timeout (s) | in-child elapsed (s) |
| --- | --- | --- | --- | --- | --- | --- |
{dynamic_rows}

Measured result: `(a+)+$` and `(a|aa)+$` **did not finish within the timeout** and were killed;
their safe rewrites (`a+$`; delimited group repeat) completed in microseconds. This is the concrete
"hang vs. safe" demonstration for the video/README. Timeouts are wall-clock measurements; the exact
milliseconds vary by machine and load.

## 3. Rewrite hint reported by `explain("(a+)+$")`

> {explain_suggestion}

The `explain` JSON (including every finding's suggestion) is saved as `evidence/explain.json`.

## 4. Source-file scan (`scan-file`)

`examples/llm_generated_patterns.py` is a synthetic "LLM-generated" validation file with safe and
risky patterns and one non-constant pattern (counted as skipped, not guessed).

| pattern | location | findings |
| --- | --- | --- |
{scan_file_rows}

CLI exit code with `--fail-on high`: **{scan_file_json_run["exit_code"]}** (1 = risky patterns found).
JSON result: `evidence/scan_file.json`.

## 5. CLI runs (verbatim exit codes)

| command | exit code |
| --- | --- |
{cli_rows}

The dynamic CLI runs use `--input` with 41 characters (`a`×40 + `!`): the unsafe pattern was killed
after the 1 s timeout; the safe rewrite completed immediately.

## 6. Tests

```
{tests["tail"]}
```

| measurement | value |
| --- | --- |
| tests run | **{tests["count"]}** |
| result | **{tests["result"]}** |
| output | `evidence/raw/unit_test_output.txt` |

## 7. Assertions (computed from the captured objects)

| assertion | result |
| --- | --- |
{assertion_rows}

## 8. Screenshots (rendered from the captured terminal text, no re-typing)

""" + "\n".join(screenshot_lines) + """

## 9. Reproduce

```bash
python scripts/check_core_deps.py
python -m unittest discover -s tests -t .
python -m redos_guard check '(a+)+$'                         # static findings + suggestion
python -m redos_guard check '(a+)+$' --fail-on high          # CI gate (exit 1)
python -m redos_guard check '(a+)+$' --timeout 2             # static + dynamic probes
python -m redos_guard check 'a+$' --timeout 2 --input "$(python -c 'print("a"*40+"!")')"
python -m redos_guard scan-file examples/llm_generated_patterns.py
python scripts/capture_evidence.py                           # regenerate this file + raw evidence
```

## Known limits

- Static analysis is heuristic: unsupported syntax is rejected rather than guessed at; patterns that
  are risky in ways outside the covered structures can pass. A clean static result is not proof.
- Dynamic probes only measure **generated/supplied inputs**; a timeout says the pattern is dangerous
  on that input, while a fast completion says only that this input was fast. Engines differ (Python
  `re` is a backtracking engine; RE2/RE2J are linear-time and immune to this class).
- Quadratic (not necessarily exponential) patterns such as `\\w+\\w+` are flagged medium; whether that
  matters depends on input size limits in the calling service.
- `scan-file` analyses Python AST constant patterns only; f-strings/variables are reported as skipped.
  Other languages are out of scope (no guessy JS literal parser).
- A safe rewrite depends on intent; `explain` suggestions are hints, not automatic fixes.
"""

    write_text(ROOT / "docs" / "EVIDENCE.md", report)
    summary = {
        "tool": "redos-guard",
        "version": __version__,
        "captured_at_utc": captured_at,
        "environment": env,
        "static_cases": [
            {"pattern": case["pattern"], "findings": [finding["code"] for finding in case["findings"]]}
            for case in static_cases
        ],
        "dynamic_runs": dynamic_runs,
        "scan_file_summary": scan_file_payload.get("summary", {}),
        "tests": tests,
        "cli_exit_codes": [{"argv": run["argv"], "exit_code": run["exit_code"]} for run in all_runs],
        "screenshots": {
            name: {"path": shot["output"], "sha256": shot.get("sha256"), "bytes": shot.get("bytes")} for name, shot in shots.items()
        },
        "assertions": assertions,
        "all_assertions_pass": all(assertions.values()),
    }
    write_json(ROOT / "evidence" / "capture_summary.json", summary)
    print("assertions:", assertions)
    return 0 if summary["all_assertions_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
