## regex-redos-guard v0.1.0

Detect catastrophic-backtracking (ReDoS) risk in LLM-generated regular expressions:
structural static analysis plus real measured timing in isolated child processes.

### What is included

- `python -m redos_guard check|scan-file|explain` with `--json`,
  `--fail-on {low,medium,high}` CI gating (exit codes 0/1/2), opt-in
  `--timeout SECONDS` dynamic probes and `--input` for an explicit test string.
- A small recursive-descent regex parser (literals, classes, groups incl.
  non-capturing/atomic/lookarounds, alternation, quantifiers with lazy/possessive
  suffixes, backreferences, anchors, inline flags). Unsupported syntax is rejected,
  not guessed.
- Static rules: `RG-NESTED-QUANT` (delimiter-aware so common safe patterns such as
  `^[a-z0-9]+(?:-[a-z0-9]+)*$` are not flagged), `RG-OVERLAP-ALT`,
  `RG-BACKREF-REPEAT`, `RG-ADJACENT-REPEAT`; every finding carries a rewrite
  suggestion.
- Dynamic probing in a **separate Python child process** with a hard timeout:
  `RG-DYNAMIC-TIMEOUT` (high) and `RG-DYNAMIC-SLOW` (medium), with measured wall
  time. The scanner process never executes a hostile regex directly.
- `scan-file` extracts constant regexes from Python `re.compile/search/...` calls
  via AST; non-constant patterns are counted as skipped.
- 86 unit tests (unittest + pytest) including real timeouts and safe-control
  patterns; GitHub Actions CI on Python 3.10–3.13; JSON Schemas for findings,
  check results and scan-file results.
- Evidence: `(a+)+$` and `(a|aa)+$` on `a`×40 + `!` were killed after **2.03 s** /
  **2.02 s** wall time, while the safe rewrite `a+$` completed the same input in
  ~6 µs (`docs/EVIDENCE.md`, `evidence/dynamic_runs.json`).

### Honest notes

- Static analysis is heuristic and finite; a clean result is **not** a proof of
  linear-time behaviour. Unsupported constructs are reported as parse errors.
- Dynamic probes measure only the generated or supplied inputs: a timeout proves
  danger on that input, a fast run proves nothing about other inputs.
- Risk is engine-dependent: Python `re`, Java `Pattern`, PCRE and JavaScript
  backtrack; RE2/RE2J are linear-time and immune.
- `explain`/`suggestion` rewrites are hints, not verified automatic fixes. The demo
  patterns are textbook examples; no new vulnerability or CVE is claimed.
