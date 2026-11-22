"""Unit tests for scripts/check_coverage.py."""

import json
from pathlib import Path
from typing import Any

import check_coverage
import pytest

GLOBS = ["src/core/scoring/*"]


def summary(lines: float, branches: float | None) -> dict[str, Any]:
    """Build a coverage.py summary with 100 statements and, if given, 100 branches."""
    data: dict[str, Any] = {"num_statements": 100, "covered_lines": lines, "num_branches": 0, "covered_branches": 0}
    if branches is not None:
        data.update(num_branches=100, covered_branches=branches)
    return data


def report(total: tuple[float, float | None], files: dict[str, tuple[float, float | None]]) -> dict[str, Any]:
    return {
        "totals": summary(*total),
        "files": {name: {"summary": summary(*pct)} for name, pct in files.items()},
    }


def test_passes_when_thresholds_met() -> None:
    data = report((80, 80), {"src/core/scoring/a.py": (95, 95), "src/api/app.py": (10, 10)})
    assert check_coverage.check(data, GLOBS) == []


def test_fails_below_global_line_threshold() -> None:
    problems = check_coverage.check(report((79, 100), {}), GLOBS)
    assert problems == ["global line coverage 79.00% < 80%"]


def test_fails_below_global_branch_threshold_even_if_combined_passes() -> None:
    # Combined (lines + branches) would be 85%, but branches alone are 70%.
    problems = check_coverage.check(report((100, 70), {}), GLOBS)
    assert problems == ["global branch coverage 70.00% < 80%"]


def test_core_branch_below_threshold_even_if_combined_passes() -> None:
    data = report((100, 100), {"src/core/scoring/a.py": (100, 90)})
    assert check_coverage.check(data, GLOBS) == ["core file src/core/scoring/a.py branch coverage 90.00% < 95%"]


def test_fails_when_core_file_line_below_threshold() -> None:
    problems = check_coverage.check(report((99, 99), {"src/core/scoring/a.py": (94, 100)}), GLOBS)
    assert problems == ["core file src/core/scoring/a.py line coverage 94.00% < 95%"]


def test_files_without_branches_pass_branch_check() -> None:
    assert check_coverage.check(report((90, None), {"src/core/scoring/a.py": (100, None)}), GLOBS) == []


def test_empty_file_counts_as_fully_covered() -> None:
    empty = {"num_statements": 0, "covered_lines": 0, "num_branches": 0, "covered_branches": 0}
    data = {"totals": empty, "files": {"src/core/scoring/a.py": {"summary": empty}}}
    assert check_coverage.check(data, GLOBS) == []


def test_non_core_file_may_be_below_core_threshold() -> None:
    assert check_coverage.check(report((90, 90), {"src/core/config.py": (50, 50)}), GLOBS) == []


def test_windows_separators_are_normalized() -> None:
    problems = check_coverage.check(report((99, 99), {"src\\core\\scoring\\a.py": (1, 1)}), GLOBS)
    assert len(problems) == 2


def test_load_core_globs_reads_pyproject(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.core_coverage]\npaths = ["src/core/x/*"]\n', encoding="utf-8")
    assert check_coverage.load_core_globs(pyproject) == ["src/core/x/*"]
    pyproject.write_text("", encoding="utf-8")
    assert check_coverage.load_core_globs(pyproject) == []


def test_project_core_paths_are_configured() -> None:
    globs = check_coverage.load_core_globs(Path(__file__).resolve().parents[2] / "pyproject.toml")
    assert "src/core/scoring/*" in globs
    assert "src/api/auth/*" in globs


def test_main_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.core_coverage]\npaths = ["src/core/scoring/*"]\n', encoding="utf-8")
    cov = tmp_path / "coverage.json"
    args = ["--report", str(cov), "--pyproject", str(pyproject)]

    assert check_coverage.main(args) == 2

    cov.write_text(json.dumps(report((90, 90), {"src/core/scoring/a.py": (96, 96)})), encoding="utf-8")
    assert check_coverage.main(args) == 0
    assert "coverage OK" in capsys.readouterr().out

    cov.write_text(json.dumps(report((50, 50), {})), encoding="utf-8")
    assert check_coverage.main(args) == 1
    assert "FAIL" in capsys.readouterr().err
