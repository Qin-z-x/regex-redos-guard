"""Static ReDoS analysis for LLM-generated regular expressions.

The threat: code-generating models produce regexes such as ``(a+)+$`` or
``(a|aa)+$`` that are semantically fine on short inputs but can make a service
hang on adversarial input (catastrophic backtracking). This module parses a
useful subset of Python/PCRE-style regex syntax and applies well-understood
structural heuristics:

* quantified group containing an unbounded quantifier (nested quantifiers);
* quantified group whose alternation branches overlap (common prefix / identical);
* backreferences inside a repeated group (exponential in backtracking engines);
* adjacent unbounded repeats with overlapping character sets (quadratic risk).

This is a heuristic, not a proof: it does not execute the regex, and some real
ReDoS patterns are outside the supported syntax (see docs/THREAT_MODEL.md). The
optional dynamic probe (``redos_guard.dynamic``) measures actual wall time on
generated adversarial inputs in a child process.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

VERSION = "0.1.0"
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}

MAX_REPEAT_BOUNDED = 1000  # {1000,} and above count as unbounded for risk purposes
ANY = "<any>"
EMPTY = "<empty>"

# Characters that can start a match for a class escape, used for overlap checks.
CLASS_CHARS = {
    "d": set("0123456789"),
    "w": set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"),
    "s": set(" \t\r\n\f\v"),
}
CLASS_NEGATIONS = {"D": "d", "W": "w", "S": "s"}


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    start: int
    end: int
    message: str
    suggestion: str = ""
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity,
            "start": self.start,
            "end": self.end,
            "message": self.message,
            "suggestion": self.suggestion,
            "data": self.data,
        }


class RegexParseError(ValueError):
    pass


def severity_at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold]


def summarize(findings: list[Finding]) -> dict:
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        counts[finding.severity] += 1
    return {"total": len(findings), **counts}


def format_finding_line(finding: Finding) -> str:
    return "%s %-20s @%d-%d  %s" % (
        finding.severity.upper().ljust(6),
        finding.code,
        finding.start,
        finding.end,
        finding.message,
    )


# ---------------------------------------------------------------------------
# Parser: a deliberately small regex AST (literals, classes, groups, alternation,
# quantifiers, backreferences, anchors). Unknown constructs raise RegexParseError
# rather than being silently misanalysed.
# ---------------------------------------------------------------------------


class _Parser:
    def __init__(self, pattern: str):
        self.pattern = pattern
        self.index = 0
        self.group_count = 0

    def parse(self) -> dict:
        node = self.parse_alternation()
        if self.index != len(self.pattern):
            raise RegexParseError("unexpected %r at position %d" % (self.pattern[self.index], self.index))
        return node

    def peek(self) -> str | None:
        return self.pattern[self.index] if self.index < len(self.pattern) else None

    def take(self) -> str:
        char = self.pattern[self.index]
        self.index += 1
        return char

    def parse_alternation(self) -> dict:
        branches = [self.parse_sequence()]
        while self.peek() == "|":
            self.take()
            branches.append(self.parse_sequence())
        if len(branches) == 1:
            return branches[0]
        return {"type": "alt", "branches": branches, "start": branches[0]["start"]}

    def parse_sequence(self) -> dict:
        items: list[dict] = []
        start = self.index
        while True:
            char = self.peek()
            if char is None or char == "|" or char == ")":
                break
            atom = self.parse_atom()
            atom = self.parse_quantifier(atom)
            items.append(atom)
        return {"type": "seq", "items": items, "start": start, "end": self.index}

    def parse_quantifier(self, atom: dict) -> dict:
        char = self.peek()
        start = self.index
        minimum: int | None = None
        maximum: int | None = None
        if char == "*":
            minimum, maximum = 0, None
            self.take()
        elif char == "+":
            minimum, maximum = 1, None
            self.take()
        elif char == "?":
            minimum, maximum = 0, 1
            self.take()
        elif char == "{":
            match = re.match(r"\{(\d+)(,(\d*))?\}", self.pattern[self.index :])
            if not match:
                return atom  # literal '{' handled by parse_atom normally
            self.index += match.end()
            minimum = int(match.group(1))
            if match.group(2) is None:
                maximum = minimum
            elif match.group(3):
                maximum = int(match.group(3))
            else:
                maximum = None
        if minimum is None:
            return atom
        lazy = False
        possessive = False
        if self.peek() == "?":
            lazy = True
            self.take()
        elif self.peek() == "+":
            possessive = True
            self.take()
        return {
            "type": "quant",
            "min": minimum,
            "max": maximum,
            "lazy": lazy,
            "possessive": possessive,
            "child": atom,
            "start": start,
            "end": self.index,
        }

    def parse_atom(self) -> dict:
        char = self.peek()
        assert char is not None
        if char == "(":
            return self.parse_group()
        if char == "[":
            return self.parse_char_class()
        if char == ".":
            self.take()
            return {"type": "dot", "start": self.index - 1, "end": self.index}
        if char == "^":
            self.take()
            return {"type": "anchor", "kind": "start", "start": self.index - 1, "end": self.index}
        if char == "$":
            self.take()
            return {"type": "anchor", "kind": "end", "start": self.index - 1, "end": self.index}
        if char == "\\":
            return self.parse_escape()
        if char in "*+?":
            raise RegexParseError("nothing to repeat at position %d" % self.index)
        self.take()
        if char in "{}":
            raise RegexParseError("unescaped %r at position %d" % (char, self.index - 1))
        return {"type": "lit", "char": char, "start": self.index - 1, "end": self.index}

    def parse_escape(self) -> dict:
        start = self.index
        self.take()  # backslash
        char = self.peek()
        if char is None:
            raise RegexParseError("trailing backslash")
        self.take()
        if char in CLASS_CHARS:
            return {"type": "class", "chars": set(CLASS_CHARS[char]), "negated": False, "start": start, "end": self.index}
        if char in CLASS_NEGATIONS:
            return {"type": "class", "chars": set(CLASS_CHARS[CLASS_NEGATIONS[char]]), "negated": True, "start": start, "end": self.index}
        if char == ".":
            return {"type": "lit", "char": ".", "start": start, "end": self.index}
        if char == "b" or char == "B":
            return {"type": "anchor", "kind": "word-boundary", "start": start, "end": self.index}
        if char in "AZz":
            return {"type": "anchor", "kind": "start" if char == "A" else "end", "start": start, "end": self.index}
        if char.isdigit():
            group = int(char)
            while self.peek() is not None and self.peek().isdigit():
                group = group * 10 + int(self.take())
            return {"type": "backref", "group": group, "start": start, "end": self.index}
        if char in "xuU":
            length = {"x": 2, "u": 4, "U": 8}[char]
            hexdigits = self.pattern[self.index : self.index + length]
            if len(hexdigits) != length or not all(digit in "0123456789abcdefABCDEF" for digit in hexdigits):
                raise RegexParseError("bad \\%s escape at position %d" % (char, start))
            self.index += length
            return {"type": "lit", "char": chr(int(hexdigits, 16)), "start": start, "end": self.index}
        if char == "n":
            return {"type": "lit", "char": "\n", "start": start, "end": self.index}
        if char == "t":
            return {"type": "lit", "char": "\t", "start": start, "end": self.index}
        if char == "r":
            return {"type": "lit", "char": "\r", "start": start, "end": self.index}
        return {"type": "lit", "char": char, "start": start, "end": self.index}

    def parse_char_class(self) -> dict:
        start = self.index
        self.take()  # '['
        negated = False
        if self.peek() == "^":
            negated = True
            self.take()
        chars: set[str] = set()
        previous: str | None = None
        ranged = False
        while True:
            char = self.peek()
            if char is None:
                raise RegexParseError("unterminated character class at position %d" % start)
            if char == "]" and (chars or previous is not None):
                self.take()
                break
            if char == "\\":
                escape = self.parse_escape()
                if escape["type"] == "lit":
                    new_char = escape["char"]
                elif escape["type"] == "class":
                    chars.update(escape["chars"])
                    previous = None
                    continue
                else:
                    raise RegexParseError("unsupported escape inside character class")
            elif char == "-":
                self.take()
                if previous is not None and self.peek() is not None and self.peek() != "]":
                    end_char = self.take()
                    if end_char == "\\":
                        self.index -= 1
                        escape = self.parse_escape()
                        end_char = escape.get("char", "")
                    chars.update(chr(code) for code in range(ord(previous), ord(end_char) + 1) if code < 0x110000)
                    previous = None
                    ranged = True
                    continue
                chars.add("-")
                previous = "-"
                continue
            else:
                self.take()
                new_char = char
            chars.add(new_char)
            previous = new_char
        if len(chars) > 500:
            chars = set(chars)
        return {
            "type": "class",
            "chars": chars,
            "negated": negated,
            "start": start,
            "end": self.index,
            "ranged": ranged,
        }

    def parse_group(self) -> dict:
        start = self.index
        self.take()  # '('
        kind = "capture"
        atomic = False
        name = None
        if self.peek() == "?":
            self.take()
            marker = self.peek()
            if marker == ":":
                self.take()
                kind = "noncapture"
            elif marker == "=" or marker == "!":
                self.take()
                kind = "lookahead"
            elif marker == ">":
                self.take()
                kind = "atomic"
                atomic = True
            elif marker == "<":
                self.take()
                lookbehind = self.peek()
                if lookbehind in ("=", "!"):
                    self.take()
                    kind = "lookbehind"
                elif lookbehind == "P":
                    # (?P<name> ...)
                    self.take()
                    if self.peek() != ">":
                        raise RegexParseError("bad named group at position %d" % start)
                    self.take()
                    name = self.pattern[self.index : self.pattern.index(">", self.index)]
                    self.index = self.pattern.index(">", self.index) + 1
                else:
                    raise RegexParseError("unknown group construct at position %d" % start)
            elif marker == "P":
                self.take()
                if self.peek() != ">":
                    raise RegexParseError("bad named group at position %d" % start)
                self.take()
                name = self.pattern[self.index : self.pattern.index(">", self.index)]
                self.index = self.pattern.index(">", self.index) + 1
            elif marker is not None and marker in "iLmsux":
                # inline flags (?i) / (?im)
                flags = []
                while self.peek() is not None and self.peek() in "iLmsux":
                    flags.append(self.take())
                if self.peek() == ")":
                    self.take()
                    return {"type": "flags", "flags": "".join(flags), "start": start, "end": self.index}
                if self.peek() == ":":
                    self.take()
                    kind = "noncapture"
                    # scoped flags group; children still parsed
            elif marker is not None and marker in "a":
                self.take()
            else:
                raise RegexParseError("unknown group construct at position %d" % start)
        if kind == "capture":
            self.group_count += 1
            number = self.group_count
        else:
            number = 0
        body = self.parse_alternation()
        if self.peek() != ")":
            raise RegexParseError("unterminated group at position %d" % start)
        self.take()
        return {
            "type": "group",
            "kind": kind,
            "atomic": atomic,
            "number": number,
            "name": name,
            "body": body,
            "start": start,
            "end": self.index,
        }


def parse_pattern(pattern: str) -> dict:
    """Parse ``pattern`` into an AST dict; raises RegexParseError on unsupported syntax."""
    if not isinstance(pattern, str) or not pattern:
        raise RegexParseError("empty pattern")
    return _Parser(pattern).parse()


# ---------------------------------------------------------------------------
# Structural helpers
# ---------------------------------------------------------------------------


def _walk(node: dict):
    yield node
    kind = node["type"]
    if kind == "seq":
        for item in node["items"]:
            yield from _walk(item)
    elif kind == "alt":
        for branch in node["branches"]:
            yield from _walk(branch)
    elif kind == "group":
        yield from _walk(node["body"])
    elif kind == "quant":
        yield from _walk(node["child"])


def _is_unbounded(quant: dict) -> bool:
    return quant["max"] is None or (isinstance(quant["max"], int) and quant["max"] >= MAX_REPEAT_BOUNDED)


def _quantified_unbounded(quant: dict) -> bool:
    return _is_unbounded(quant) and quant["min"] <= 1


def _has_unbounded_quant(node: dict) -> dict | None:
    for child in _walk(node):
        if child["type"] == "quant" and _is_unbounded(child):
            return child
    return None


def _literal_prefix(node: dict) -> str:
    """Longest literal string that any match of ``node`` must start with."""
    kind = node["type"]
    if kind == "lit":
        return node["char"]
    if kind == "seq":
        pieces: list[str] = []
        for item in node["items"]:
            piece = _literal_prefix(item)
            pieces.append(piece)
            if piece == "":
                break
        return "".join(pieces)
    if kind == "alt":
        prefixes = [_literal_prefix(branch) for branch in node["branches"]]
        if not prefixes:
            return ""
        shortest = min(prefixes, key=len)
        return shortest
    if kind == "group":
        return _literal_prefix(node["body"])
    if kind == "quant":
        if node["min"] >= 1 and node["max"] == 1:
            return _literal_prefix(node["child"])
        return ""
    return ""


def _first_chars(node: dict) -> set[str]:
    """Approximate set of characters a match can start with ({ANY} means unknown)."""
    kind = node["type"]
    if kind == "lit":
        return {node["char"]}
    if kind == "class":
        if node["negated"]:
            return {ANY}
        return set(node["chars"]) if node["chars"] else set()
    if kind == "dot":
        return {ANY}
    if kind == "anchor" or kind == "flags":
        return set()
    if kind == "backref":
        return {ANY}
    if kind == "seq":
        result: set[str] = set()
        for item in node["items"]:
            item_first = _first_chars(item)
            if not item_first:
                continue  # zero-width
            result = item_first
            break
        return result
    if kind == "alt":
        result = set()
        for branch in node["branches"]:
            result |= _first_chars(branch)
        return result
    if kind == "group":
        return _first_chars(node["body"])
    if kind == "quant":
        return _first_chars(node["child"])
    return set()


def _last_chars(node: dict) -> set[str]:
    """Approximate set of characters a match can end with ({ANY} means unknown)."""
    kind = node["type"]
    if kind == "lit":
        return {node["char"]}
    if kind == "class":
        if node["negated"]:
            return {ANY}
        return set(node["chars"]) if node["chars"] else set()
    if kind == "dot":
        return {ANY}
    if kind in ("anchor", "flags"):
        return set()
    if kind == "backref":
        return {ANY}
    if kind == "seq":
        result: set[str] = set()
        for item in reversed(node["items"]):
            item_last = _last_chars(item)
            if item_last:
                result |= item_last
            if not _can_match_empty(item):
                break
        return result
    if kind == "alt":
        result = set()
        for branch in node["branches"]:
            result |= _last_chars(branch)
        return result
    if kind == "group":
        return _last_chars(node["body"])
    if kind == "quant":
        return _last_chars(node["child"])
    return set()


def _joined_group_is_ambiguous(body: dict) -> bool:
    r"""Heuristic: can the repeated group's end overlap its next iteration's start?

    ``(a+)+`` and ``(\w+\s?)+`` are ambiguous (iteration boundaries are not
    delimited); ``(?:-[a-z0-9]+)*`` and ``([a-z0-9]+\.)+`` are delimited by a
    mandatory separator, so nested quantifiers there are not catastrophic.
    """
    return _chars_overlap(_first_chars(body), _last_chars(body))


def _chars_overlap(left: set[str], right: set[str]) -> bool:
    if ANY in left or ANY in right:
        return True
    return bool(left & right)


def _can_match_empty(node: dict) -> bool:
    kind = node["type"]
    if kind in ("lit", "class", "dot", "backref"):
        return False
    if kind in ("anchor", "flags"):
        return True
    if kind == "seq":
        return all(_can_match_empty(item) for item in node["items"])
    if kind == "alt":
        return any(_can_match_empty(branch) for branch in node["branches"])
    if kind == "group":
        return _can_match_empty(node["body"])
    if kind == "quant":
        return node["min"] == 0 or _can_match_empty(node["child"])
    return True


def _describe(node: dict) -> str:
    """Short human-readable description of a node for messages."""
    kind = node["type"]
    if kind == "lit":
        return repr(node["char"])
    if kind == "class":
        return "[%s%s]" % ("^" if node["negated"] else "", "".join(sorted(node["chars"]))[:12])
    if kind == "dot":
        return "."
    if kind == "quant":
        symbol = {0: "*", 1: "+"}.get(node["min"])
        if symbol and node["max"] is None:
            return "%s%s" % (_describe(node["child"]), symbol)
        if node["max"] is None:
            return "%s{%d,}" % (_describe(node["child"]), node["min"])
        if node["min"] == node["max"]:
            return "%s{%d}" % (_describe(node["child"]), node["min"])
        return "%s{%d,%d}" % (_describe(node["child"]), node["min"], node["max"])
    if kind == "group":
        return "(…)"
    if kind == "seq":
        return "".join(_describe(item) for item in node["items"])
    if kind == "alt":
        return "|".join(_describe(branch) for branch in node["branches"])
    if kind == "backref":
        return "\\%d" % node["group"]
    return kind


def _suggestion_for_nested(node: dict) -> str:
    child = node["child"]
    while child["type"] == "group":
        child = child["body"]
    if child["type"] == "quant" and child["child"]["type"] in ("lit", "class", "dot"):
        return (
            "A repetition of a repetition can usually be reduced: `(X+)+` matches the same "
            "strings as `X+`. Use a single quantifier, a bounded {m,n}, or an atomic group / "
            "possessive quantifier when the engine supports it."
        )
    return (
        "Avoid applying an unbounded quantifier to a group that itself repeats. Reduce to a "
        "single quantifier, bound the inner repetition ({1,100}), or use an atomic group / "
        "possessive quantifier where the engine supports it."
    )


# ---------------------------------------------------------------------------
# Static scan
# ---------------------------------------------------------------------------


def scan_pattern(pattern: str) -> list[Finding]:
    """Return deterministic static ReDoS findings for ``pattern``."""
    tree = parse_pattern(pattern)
    findings: list[Finding] = []

    def add(code: str, severity: str, start: int, end: int, message: str, suggestion: str = "", data: dict | None = None):
        findings.append(
            Finding(
                code=code,
                severity=severity,
                start=start,
                end=end,
                message=message,
                suggestion=suggestion,
                data=data or {},
            )
        )

    for node in _walk(tree):
        kind = node["type"]
        if kind == "quant":
            primitive = node["child"]
            unwrapped = primitive
            while unwrapped["type"] == "group":
                if unwrapped.get("atomic"):
                    break
                unwrapped = unwrapped["body"]
            # 1) Nested unbounded quantifier.
            if not node.get("possessive") and not (primitive["type"] == "group" and primitive.get("atomic")):
                inner = _has_unbounded_quant(primitive)
                if inner is not None and _joined_group_is_ambiguous(unwrapped if unwrapped["type"] != "flag" else primitive):
                    outer_unbounded = _is_unbounded(node)
                    severity = "high" if outer_unbounded else "medium"
                    add(
                        "RG-NESTED-QUANT",
                        severity,
                        node["start"],
                        node["end"],
                        "nested quantifiers: %s repeats a group that already repeats %s — "
                        "backtracking can be exponential"
                        % (_describe(node), _describe(inner)),
                        _suggestion_for_nested(node),
                        {"outer": _describe(node), "inner": _describe(inner), "outer_unbounded": outer_unbounded},
                    )
            # 2) Overlapping alternation under a quantifier.
            alternation = primitive
            while alternation["type"] == "group":
                alternation = alternation["body"]
            if alternation["type"] == "alt" and len(alternation["branches"]) > 1:
                overlapping = _find_overlapping_branch_pair(alternation["branches"])
                if overlapping is not None:
                    first, second, reason = overlapping
                    outer_unbounded = _is_unbounded(node)
                    severity = "high" if outer_unbounded else "medium"
                    add(
                        "RG-OVERLAP-ALT",
                        severity,
                        node["start"],
                        node["end"],
                        "overlapping alternation branches %r and %r inside a repeated group (%s): "
                        "ambiguous matching can backtrack exponentially"
                        % (_describe(first), _describe(second), reason),
                        "Make the branches unambiguous (e.g. `(a|aa)` -> `a+` if equivalent, or order "
                        "branches longest-first and use an atomic/possessive group), or replace the "
                        "alternation with a character class if the branches are single characters.",
                        {"branches": [_describe(first), _describe(second)], "reason": reason, "outer_unbounded": outer_unbounded},
                    )
            # 3) Backreference under repetition.
            for child in _walk(primitive):
                if child["type"] == "backref":
                    add(
                        "RG-BACKREF-REPEAT",
                        "high",
                        node["start"],
                        node["end"],
                        "backreference \\%d appears inside a repeated group: backtracking engines can "
                        "exhibit exponential behaviour matching backreferences" % child["group"],
                        "Avoid repeating a group that contains a backreference, or bound the "
                        "repetition and anchor the pattern.",
                        {"backref_group": child["group"]},
                    )
                    break

        if kind == "seq":
            items = [item for item in node["items"] if item["type"] != "flags"]
            for left, right in zip(items, items[1:]):
                if left["type"] != "quant" or right["type"] != "quant":
                    continue
                if not (_is_unbounded(left) and _is_unbounded(right)):
                    continue
                if _can_match_empty(left["child"]) or _can_match_empty(right["child"]):
                    continue
                left_first = _first_chars(left["child"])
                right_first = _first_chars(right["child"])
                if not _chars_overlap(left_first, right_first):
                    continue
                add(
                    "RG-ADJACENT-REPEAT",
                    "medium",
                    left["start"],
                    right["end"],
                    "adjacent unbounded repeats with overlapping character sets (%s, %s) can cause "
                    "quadratic backtracking on long inputs" % (_describe(left), _describe(right)),
                    "Merge the repetitions into one quantifier where possible (e.g. `\\w+\\w+` -> "
                    "`\\w+`), or insert a mandatory separator between them.",
                    {"left": _describe(left), "right": _describe(right)},
                )

    unique: dict[tuple, Finding] = {}
    for finding in findings:
        unique.setdefault((finding.start, finding.end, finding.code), finding)
    return sorted(unique.values(), key=lambda finding: (finding.start, finding.end, finding.code))


def _find_overlapping_branch_pair(branches: list[dict]) -> tuple[dict, dict, str] | None:
    for index, first in enumerate(branches):
        for second in branches[index + 1 :]:
            first_chars = _first_chars(first)
            second_chars = _first_chars(second)
            if _chars_overlap(first_chars, second_chars):
                return first, second, "first characters overlap"
            first_prefix = _literal_prefix(first)
            second_prefix = _literal_prefix(second)
            if first_prefix and second_prefix and (
                first_prefix.startswith(second_prefix) or second_prefix.startswith(first_prefix)
            ):
                return first, second, "one branch is a prefix of the other"
    return None


def explain(pattern: str) -> dict:
    """Static explanation: findings plus human-oriented suggestions."""
    try:
        findings = scan_pattern(pattern)
    except RegexParseError as exc:
        return {
            "tool": "redos-guard",
            "version": VERSION,
            "pattern": pattern,
            "valid": False,
            "error": str(exc),
            "findings": [],
            "summary": {"total": 0, "high": 0, "medium": 0, "low": 0},
            "safe": None,
            "suggestions": [],
        }
    summary = summarize(findings)
    return {
        "tool": "redos-guard",
        "version": VERSION,
        "pattern": pattern,
        "valid": True,
        "findings": [finding.to_dict() for finding in findings],
        "summary": summary,
        "safe_static": summary["high"] == 0 and summary["medium"] == 0,
        "suggestions": [
            {"code": finding.code, "severity": finding.severity, "suggestion": finding.suggestion} for finding in findings
        ],
        "caveat": "Static heuristics: a clean result is not a proof of linear-time behaviour on every input.",
    }
