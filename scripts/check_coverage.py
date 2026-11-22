"""Fail the quality gate when coverage is below the thresholds (docs/14 COB-01, COB-02).

Reads ``coverage.json`` (written by ``make test``) and the core globs from
``[tool.core_coverage] paths`` in ``pyproject.toml``. Percentages are line+branch.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
import tomllib
from pathlib import Path
from typing import Any

GLOBAL_THRESHOLD = 80.0
CORE_THRESHOLD = 95.0


def load_core_globs(pyproject: Path) -> list[str]:
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    paths = data.get("tool", {}).get("core_coverage", {}).get("paths", [])
    return [str(p) for p in paths]


def check(report: dict[str, Any], core_globs: list[str]) -> list[str]:
    """Return the list of violations (empty when the gate passes)."""
    problems: list[str] = []
    total = float(report["totals"]["percent_covered"])
    if total < GLOBAL_THRESHOLD:
        problems.append(f"global coverage {total:.2f}% < {GLOBAL_THRESHOLD:.0f}%")
    for name, info in sorted(report["files"].items()):
        normalized = name.replace("\\", "/")
        if not any(fnmatch.fnmatch(normalized, glob) for glob in core_globs):
            continue
        percent = float(info["summary"]["percent_covered"])
        if percent < CORE_THRESHOLD:
            problems.append(f"core file {normalized} coverage {percent:.2f}% < {CORE_THRESHOLD:.0f}%")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=Path("coverage.json"))
    parser.add_argument("--pyproject", type=Path, default=Path("pyproject.toml"))
    args = parser.parse_args(argv)
    if not args.report.is_file():
        sys.stderr.write(f"{args.report} not found: run `make test` first\n")
        return 2
    report = json.loads(args.report.read_text(encoding="utf-8"))
    problems = check(report, load_core_globs(args.pyproject))
    for problem in problems:
        sys.stderr.write(f"FAIL: {problem}\n")
    if problems:
        return 1
    total = float(report["totals"]["percent_covered"])
    sys.stdout.write(f"coverage OK: global {total:.2f}% (>= {GLOBAL_THRESHOLD:.0f}%), core >= {CORE_THRESHOLD:.0f}%\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
