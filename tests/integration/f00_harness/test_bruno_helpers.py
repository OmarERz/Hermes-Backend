"""The Bruno helper modules are in the repository, not only in a working copy (a git-ignored file is not cloned)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]


def test_no_bruno_helper_module_is_git_ignored() -> None:
    git = shutil.which("git")
    if git is None or not (ROOT / ".git").exists():
        pytest.skip("needs a git checkout")
    modules = sorted((ROOT / "bruno" / "lib").glob("*.js"))
    assert modules, "bruno/lib holds the shared request helpers"
    for module in modules:
        ignored = subprocess.run([git, "check-ignore", "-q", str(module)], cwd=ROOT, check=False)
        assert ignored.returncode == 1, f"{module.relative_to(ROOT)} is git-ignored: a clone would not have it"
