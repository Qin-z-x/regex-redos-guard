"""Synthetic "LLM-generated" validation regexes, used by the evidence capture.

The risky patterns are deliberately the kind of thing a code-generating model
produces naively; the safe patterns are the rewrites you want instead.
"""

import re

# Safe: bounded / unambiguous.
EMAIL = re.compile(r"^[\w.+-]+@[\w-]+\.[\w.]+$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

# Risky: nested quantifiers (catastrophic backtracking on a long non-matching run).
USERNAME = re.compile(r"^(\w+)+$")

# Risky: overlapping alternation inside a repeated group.
WEAK_SLUG = re.compile(r"^(a|aa)+$")

# Risky: backreference inside a repeated group.
REPEATED_TOKEN = re.compile(r"^(\w+)\1+$")


def is_date(value: str) -> bool:
    return re.match(r"^\d{4}-\d{2}-\d{2}$", value) is not None


def is_username(value: str) -> bool:
    return re.match(r"^(\w+)+$", value) is not None


def is_repeated_token(value: str) -> bool:
    return re.match(r"^(\w+)\1+$", value) is not None


def build_dynamic(prefix: str):
    # Non-constant pattern: cannot be analysed statically; counted as skipped.
    return re.compile(prefix + r"(\w+)+")
