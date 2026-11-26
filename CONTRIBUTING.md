# Contributing to regex-redos-guard

Thanks for helping catch catastrophic-backtracking regexes. This is a small,
dependency-free project; contributions are expected to stay that way.

## Ground rules

* The `redos_guard/` package must import **only the Python standard library**
  (`scripts/check_core_deps.py` enforces this). Test-only dependencies (pytest) are
  optional.
* Tests must pass on Python 3.10–3.13:
  `python -m unittest discover -s tests -t .` and `python -m pytest`.
* **Never run an untrusted regex in the test process.** Dynamic tests go through
  `redos_guard.dynamic.probe`, which uses a child process with a hard timeout; keep
  timeouts short (≤1 s) in tests.
* Keep results deterministic: stable codes, sorted findings, JSON-serializable data.
* Be honest in docs/messages: a clean static result is not a proof; a fast dynamic
  run proves nothing about other inputs. Do not claim new vulnerabilities/CVEs.
* Add a test for every new heuristic, for every false positive you fix (lock in the
  safe control), and update `docs/THREAT_MODEL.md` when severity changes.

## Development

```bash
git clone https://github.com/Qin-Z-x/regex-redos-guard.git
cd regex-redos-guard
python -m pip install -e ".[dev]"

python scripts/check_core_deps.py
python -m unittest discover -s tests -t .
python -m pytest
python -m redos_guard check '(a+)+$'
python -m redos_guard scan-file examples/llm_generated_patterns.py
```

## Pull requests

1. Describe the pattern class or false positive with a minimal regex and, if
   relevant, measured behaviour.
2. Add tests (`tests/test_static.py`, `tests/test_dynamic.py`,
   `tests/test_files.py`, `tests/test_cli.py`).
3. Regenerate `docs/EVIDENCE.md` if the evidence changes.
4. CI must be green.

## Reporting security issues

Please use GitHub Security Advisories for this repository. Evasion reports and
false-positive reports are welcome; both are documented as limitations rather than
silently patched over.
