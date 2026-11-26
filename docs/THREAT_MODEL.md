# Threat model: ReDoS in LLM-generated regular expressions

This document explains what `regex-redos-guard` defends against, how severity is
assigned, why the heuristics can produce false positives/negatives, and what the
project does **not** claim.

> **Honesty statement.** This is a heuristic static analyser plus a sampled dynamic
> timing tool. It does not provide a formal worst-case-complexity proof, does not
> disclose a new vulnerability and does not claim a new CVE. ReDoS is public prior
> art; the cited patterns are textbook examples.

## 1. The vulnerability class

Backtracking regex engines (Python `re`, Java `Pattern`, PCRE, JavaScript's
RegExp) try alternatives until a match succeeds or every path is exhausted. When a
pattern has **ambiguous repetition**, the number of paths grows exponentially with
input length, and a short crafted string can consume unbounded CPU:

```python
re.search(r"(a+)+$", "a" * 40 + "!")     # effectively hangs
```

Classic shapes:

* nested quantifiers — `(a+)+`, `(a*)*`, `(.*)*`, `(\w+\s?)+`;
* overlapping alternation inside a repeat — `(a|aa)+`, `(foo|foobar)+`;
* backreferences under repetition — `^(\w+)\1+$`;
* adjacent overlapping repetitions (quadratic) — `\w+\w+`, `.*.*`;
* ambiguous bounded repeats — `(a|aa){2}` (less severe, still flagged medium).

Real incidents matter: the July 2019 Cloudflare outage was triggered by a
permissive WAF regex, and popular npm packages have shipped ReDoS regexes
(e.g. `ansi-regex`, CVE-2021-3807). For LLM-generated code the risk is practical:
a model writes a plausible-looking validation regex, review checks semantics, and
worst-case complexity is never considered.

**Engine-dependent.** RE2/RE2J do not backtrack (linear time) and are immune to this
class. The tool targets backtracking engines (Python `re` is one).

## 2. What the tool does

### Static analysis (deterministic, no execution)

A recursive-descent parser builds an AST for the supported syntax: literals,
character classes, `.`, groups (capture / non-capturing / atomic / lookarounds),
alternation, quantifiers (`* + ? {m,n}`, lazy/possessive suffixes), backreferences,
anchors and inline flags. Unsupported syntax raises a parse error instead of being
guessed at.

Heuristics then report:

| Rule | Severity | Condition |
| --- | --- | --- |
| `RG-NESTED-QUANT` | high / medium | quantified group contains an unbounded quantifier **and** the group's start/end character sets overlap (boundaries are ambiguous) |
| `RG-OVERLAP-ALT` | high / medium | quantified group's alternation branches overlap (identical, prefix-related, or shared first characters) |
| `RG-BACKREF-REPEAT` | high | a backreference appears inside a repeated group |
| `RG-ADJACENT-REPEAT` | medium | adjacent unbounded repeats with overlapping character sets |

Each finding carries a `suggestion` (rewrite hints: reduce to a single quantifier,
bound `{m,n}`, use atomic/possessive constructs where supported, add a mandatory
separator, or restrict the input length).

### Dynamic probing (optional, child process)

With `--timeout SECONDS`, the tool generates a small deterministic set of
adversarial inputs (long run of the likely repeated character plus a non-matching
terminator) and runs each in a **separate Python child process** with
`subprocess.run(timeout=...)`. On timeout the child is killed; the parent records
the measured wall time and reports `RG-DYNAMIC-TIMEOUT` (high). Completed runs slower
than 100 ms are reported as `RG-DYNAMIC-SLOW` (medium).

This gives a concrete "hang vs. safe" measurement, but only for the sampled inputs.

## 3. Severity model

| Severity | Meaning | Example |
| --- | --- | --- |
| `high` | structural ambiguity that can be exponential, or a measured timeout | `(a+)+`, `(a|aa)+`, repeated backreference, dynamic timeout |
| `medium` | quadratic (not necessarily exponential) risk or bounded ambiguity | `\w+\w+`, `(a|aa){2}`, dynamic run >100 ms |
| `low` | reserved for informational findings (currently unused) | – |

Findings are sorted deterministically by `(start, end, code)`; dynamic findings use
`start=end=0` and carry the measured data.

## 4. Detection strategy and false positives

The heuristics are deliberately conservative about the most common false positives:

* **Separator-delimited repeats are safe by construction.** `^[a-z0-9]+(?:-[a-z0-9]+)*$`
  and `([a-z0-9]+\.)+` have an outer group whose end characters do not overlap its
  start characters, so iteration boundaries are unambiguous. The nested-quantifier
  rule compares first/last character sets and does **not** flag them (tests lock
  this in).
* **Atomic groups and possessive quantifiers are not flagged.** `(?>a+)+` cannot
  backtrack into the group, so the ambiguity is removed.
* **Disjoint alternations are safe.** `(foo|bar)+` has no ambiguous split.
* **Bounded repeats are medium at most.** `(a+){3}` is not the unbounded classic but
  is still worth a look; it is reported medium.
* **The dynamic probe is optional.** Static analysis is deterministic and fast, so
  it can be a CI gate; dynamic probing costs up to `timeout × inputs` and is opt-in.

Known false-positive/negative surfaces:

* Language/engine differences: possessive/atomic syntax is not accepted by every
  engine; the parser accepts it (Python 3.11+/PCRE), and flags it safe.
* Character-set overlap is approximate (`ANY` for dot/negated classes/backrefs), so
  some patterns are flagged more conservatively than a precise analysis would.
* Unsupported constructs (conditionals, recursion, `\p{...}`, subroutines, `(?(1)...)`)
  are rejected as parse errors, not analysed.
* Patterns that are exponential for reasons outside the covered structures can pass.
* A fast dynamic run proves nothing about other inputs; a timeout proves danger on
  that input only. Engines may take different paths even for the same pattern.

## 5. Non-goals / out of scope

* Not a formal complexity analysis and not a regex equivalence checker.
* Not a regex fuzzer; the dynamic probe uses a small deterministic input set.
* Not a runtime protection layer: it does not intercept or time-limit matching in
  production (though the README suggests pairing it with input length caps).
* Not a multi-language source scanner: `scan-file` parses Python AST constant
  patterns; JavaScript/Java scanners are out of scope to avoid guessy heuristics.
* No new vulnerability/CVE claim; the patterns used are public textbook examples.

## 6. Recommended deployment

1. Run `redos-guard scan-file src/ --fail-on high` in CI for services that accept
   user-controlled input and use backtracking engines.
2. Gate model-generated code reviews with `check '<pattern>' --fail-on high` (static)
   and optionally `--timeout 2` for a concrete demonstration.
3. Pair with a hard input length cap before regex matching, and consider RE2-style
   engines for untrusted input.
4. Treat `suggestion` as a starting point: verify the rewrite preserves intent.
5. Re-run dynamic probes on suspicious patterns with the real-world input lengths
   and engine you deploy.

## 7. References

1. S. Crosby, D. Wallach, *Regular Expression Denial of Service: Attack and
   Defense*, USENIX Security 2003 — the original ReDoS analysis.
2. OWASP, *Regular expression Denial of Service - ReDoS*:
   <https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS>
3. Cloudflare, *Details of the Cloudflare outage on July 2, 2019*:
   <https://blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/>
4. CVE-2021-3807 (`ansi-regex` ReDoS):
   <https://nvd.nist.gov/vuln/detail/CVE-2021-3807>
5. Python `re` documentation (backtracking engine):
   <https://docs.python.org/3/library/re.html>

These citations describe prior art. `regex-redos-guard` is independent and not
affiliated with the authors or vendors above.
