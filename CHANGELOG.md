# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-11-26

Initial release.

### Added

* A small recursive-descent regex parser (literals, classes, dot, groups including
  non-capturing/atomic/lookarounds, alternation, quantifiers with lazy/possessive
  suffixes, backreferences, anchors, inline flags) that rejects unsupported syntax
  instead of guessing.
* Static ReDoS heuristics: `RG-NESTED-QUANT` (delimiter-aware), `RG-OVERLAP-ALT`,
  `RG-BACKREF-REPEAT`, `RG-ADJACENT-REPEAT`, each with a rewrite `suggestion`.
* Optional dynamic probing in a separate Python child process with a hard timeout,
  generating adversarial inputs and reporting measured wall time; findings
  `RG-DYNAMIC-TIMEOUT` (high) and `RG-DYNAMIC-SLOW` (medium).
* `scan-file` for Python files/directories: extracts constant regexes from
  `re.compile/search/match/fullmatch/...` calls via AST; non-constant patterns are
  counted as skipped.
* CLI `python -m redos_guard check|scan-file|explain` with `--timeout`,
  `--input`, `--size`, `--json` and `--fail-on {low,medium,high}`; exit codes 0/1/2.
* 86 unit tests (unittest + pytest) including real child-process timeout tests,
  safe-pattern controls (delimited group repeats, atomic groups, possessive
  quantifiers) and JSON schema validation.
* Evidence capture (`scripts/capture_evidence.py`): static case matrix, real
  measured timeouts (2.03 s / 2.02 s) versus ~6 µs safe rewrites, scan-file output,
  CLI exit codes, terminal screenshots, `docs/EVIDENCE.md`.
* GitHub Actions CI on Python 3.10–3.13 with a real dynamic timeout gate.

### Notes

* This is a heuristic + sampled-timing tool: it is not a formal complexity proof and
  does not disclose a new vulnerability or CVE. See `docs/THREAT_MODEL.md`.

## [Unreleased]

- (planned) optional JS/PCRE literal extraction with explicit opt-in and documented
  heuristic limits.
