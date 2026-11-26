"""Fail if the redos_guard core imports anything outside the Python standard library.

The core promise is "stdlib-only": the CLI must run in a locked-down CI runner or
air-gapped environment with no third-party packages.

    python scripts/check_core_deps.py
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "redos_guard"


def main() -> int:
    stdlib = set(sys.stdlib_module_names)
    failures: list[str] = []
    for path in sorted(PACKAGE.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top not in stdlib:
                        failures.append("%s:%d imports %r" % (path.name, node.lineno, alias.name))
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    continue  # relative import inside the package
                top = (node.module or "").split(".")[0]
                if top and top not in stdlib:
                    failures.append("%s:%d imports from %r" % (path.name, node.lineno, node.module))
    if failures:
        print("third-party imports found in the stdlib-only core:")
        for failure in failures:
            print("  " + failure)
        return 1
    print("OK: redos_guard core imports only the Python standard library")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
