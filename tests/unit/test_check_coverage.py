"""Unit tests for scripts/check_coverage.py."""

import json
from pathlib import Path
from typing import Any

import check_coverage
import pytest

GLOBS = ["src/core/scoring/*"]


def report(total: float, files: dict[str, float]) -> dict[str, Any]:
    return {
        "totals": {"percent_covered": total},
        "files": {name: {"summary": {"percent_covered": pct}} for name, pct in files.items()},
    }


def test_passes_when_thresholds_met() -> None:
    data = report(80.0, {"src/core/scoring/a.py": 95.0, "src/api/app.py": 10.0})
    assert check_coverage.check(data, GLOBS) == []


def test_fails_below_global_threshold() -> None:
    problems = check_coverage.check(report(79.99, {}), GLOBS)
    assert len(problems) == 1
    assert "global" in problems[0]


def test_fails_when_core_file_below_threshold() -> None:
    problems = check_coverage.check(report(99.0, {"src/core/scoring/a.py": 94.9}), GLOBS)
    assert problems == ["core file src/core/scoring/a.py coverage 94.90% < 95%"]


def test_non_core_file_may_be_below_core_threshold() -> None:
    assert check_coverage.check(report(90.0, {"src/core/config.py": 50.0}), GLOBS) == []


def test_windows_separators_are_normalized() -> None:
    problems = check_coverage.check(report(99.0, {"src\\core\\scoring\\a.py": 1.0}), GLOBS)
    assert len(problems) == 1


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

    cov.write_text(json.dumps(report(90.0, {"src/core/scoring/a.py": 96.0})), encoding="utf-8")
    assert check_coverage.main(args) == 0
    assert "coverage OK" in capsys.readouterr().out

    cov.write_text(json.dumps(report(50.0, {})), encoding="utf-8")
    assert check_coverage.main(args) == 1
    assert "FAIL" in capsys.readouterr().err
