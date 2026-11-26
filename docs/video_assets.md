# Video assets — regex-redos-guard (5-minute demo)

All commands below were run on the build machine; quoted outputs are copied from
the captured evidence. Raw material: `docs/screenshots/`, `docs/EVIDENCE.md`,
`evidence/`.

## Files ready for the edit

| asset | path | what it shows |
| --- | --- | --- |
| Static check terminal | `docs/screenshots/terminal_static.png` | 1 high finding + rewrite suggestion for `(a+)+$`, gate exit 1, safe date pattern exit 0 |
| Dynamic probe terminal | `docs/screenshots/terminal_dynamic.png` | real 1 s timeout for `(a+)+$` vs a fast safe rewrite on the same input |
| scan-file terminal | `docs/screenshots/terminal_scan_file.png` | risky patterns found in the synthetic "LLM-generated" file |
| Test terminal | `docs/screenshots/terminal_tests.png` | 86 tests passing |
| Raw evidence | `docs/EVIDENCE.md` | static case matrix + measured child-process timings |

## Suggested 5-minute structure

| time | beat | command / asset | expected output (real) |
| --- | --- | --- | --- |
| 0:00–0:30 | Hook: "one regex can hang your service" | `docs/screenshots/terminal_dynamic.png`; Cloudflare July 2019 outage | `DYNAMIC TIMEOUT exceeded 1.00s …` |
| 0:30–1:05 | What ReDoS is | `docs/THREAT_MODEL.md` §1 | `(a+)+$` on `a`×40 + `!`; exponential backtracking |
| 1:05–1:40 | Why LLM-generated code matters | README intro; `examples/llm_generated_patterns.py` | model writes plausible validation regexes; review checks semantics, not complexity |
| 1:40–2:20 | Static scan | `python -m redos_guard check '(a+)+$'` | `HIGH RG-NESTED-QUANT … suggestion: …`, `summary: 1 finding(s): 1 high` |
| 2:20–2:50 | CI gate | `python -m redos_guard check '(a+)+$' --fail-on high` | `FAIL: 1 finding(s) at or above severity 'high'`, `[exit code: 1]` |
| 2:50–3:30 | Real measured hang | `python -m redos_guard check '(a+)+$' --timeout 2` | `DYNAMIC TIMEOUT exceeded 2.00s … total wall time 2.03s` |
| 3:30–3:55 | Safe rewrite on the same input | `python -m redos_guard check 'a+$' --timeout 2 --input "$(python -c 'print("a"*40+"!")')"` | `DYNAMIC 0.0000xxs … matched=False`, `summary: 0 finding(s)` |
| 3:55–4:25 | Scan whole files | `python -m redos_guard scan-file examples/llm_generated_patterns.py --fail-on high` | nested/overlap/backref patterns flagged; non-constant pattern skipped |
| 4:25–4:45 | Tests | `python -m unittest discover -s tests -t .` | `Ran 86 tests … OK` |
| 4:45–5:00 | Limits + call to action | `docs/THREAT_MODEL.md` §4 | heuristic + sampled timing; not a proof; engine-dependent |

## Exact commands for screen recording

```bash
# 1. Static analysis + suggestion
python -m redos_guard check '(a+)+$'

# 2. CI gate (expected exit 1)
python -m redos_guard check '(a+)+$' --fail-on high

# 3. Dynamic measurement with a hard child-process timeout
python -m redos_guard check '(a+)+$' --timeout 2

# 4. The same adversarial input against the safe rewrite
python -m redos_guard check 'a+$' --timeout 2 --input "$(python -c 'print("a"*40+"!")')"

# 5. Whole-file scan
python -m redos_guard scan-file examples/llm_generated_patterns.py --fail-on high

# 6. JSON for the overlay
python -m redos_guard scan-file examples/llm_generated_patterns.py --json

# 7. Tests
python -m unittest discover -s tests -t .
```

## Key on-screen numbers (copy-safe)

* `(a+)+$` on 41 chars: **timeout after 2.03 s** (parent wall time, child killed).
* `(a|aa)+$` on 41 chars: **timeout after 2.02 s**.
* Safe rewrite `a+$` on the same input: **completed in ~6 µs**.
* Delimited group repeat: completed in ~2 µs.
* Static matrix: 4/4 catastrophic patterns high; 3/3 safe controls clean.
* 86 tests, all passing; stdlib-only core.

## Caveats to state on camera

* Static analysis is heuristic; a clean result is not a proof. Unsupported syntax is
  rejected, not guessed.
* Dynamic probes measure only the generated/supplied inputs; fast ≠ safe for all
  inputs, timeout = real danger on that input.
* Engine-dependent: Python `re`/Java/PCRE/JS backtrack; RE2/RE2J are linear-time.
* Rewrite suggestions are hints; verify equivalence before shipping.
* The demo patterns are textbook examples, not a new vulnerability.
