"""Fail the quality gate when coverage is below the thresholds (docs/14 COB-01, COB-02).

Reads ``coverage.json`` (written by ``make test``) and the core globs from
``[tool.core_coverage] paths`` in ``pyproject.toml``. Line and branch coverage are
checked separately; a file or project without branches passes the branch check.
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


def _percentages(summary: dict[str, Any]) -> tuple[float, float | None]:
    """Return (line %, branch % or None when there are no branches)."""
    statements = int(summary["num_statements"])
    lines = 100.0 if statements == 0 else 100.0 * int(summary["covered_lines"]) / statements
    branches = int(summary.get("num_branches", 0))
    if branches == 0:
        return lines, None
    return lines, 100.0 * int(summary["covered_branches"]) / branches


def _violations(label: str, summary: dict[str, Any], threshold: float) -> list[str]:
    lines, branches = _percentages(summary)
    problems: list[str] = []
    if lines < threshold:
        problems.append(f"{label} line coverage {lines:.2f}% < {threshold:.0f}%")
    if branches is not None and branches < threshold:
        problems.append(f"{label} branch coverage {branches:.2f}% < {threshold:.0f}%")
    return problems


def check(report: dict[str, Any], core_globs: list[str]) -> list[str]:
    """Return the list of violations (empty when the gate passes)."""
    problems = _violations("global", report["totals"], GLOBAL_THRESHOLD)
    for name, info in sorted(report["files"].items()):
        normalized = name.replace("\\", "/")
        if any(fnmatch.fnmatch(normalized, glob) for glob in core_globs):
            problems.extend(_violations(f"core file {normalized}", info["summary"], CORE_THRESHOLD))
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
    lines, branches = _percentages(report["totals"])
    branch_text = "n/a" if branches is None else f"{branches:.2f}%"
    sys.stdout.write(
        f"coverage OK: global lines {lines:.2f}%, branches {branch_text} "
        f"(>= {GLOBAL_THRESHOLD:.0f}%), core >= {CORE_THRESHOLD:.0f}%\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
