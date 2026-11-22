"""The Python runtime is pinned in one version everywhere (D-066): CI installs .python-version, the image uses the
Dockerfile tag. A Dependabot bump of only one of them must fail here."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_dockerfile_python_matches_python_version() -> None:
    pinned = (ROOT / ".python-version").read_text(encoding="utf-8").strip()
    tags = re.findall(r"^FROM python:([0-9.]+)-", (ROOT / "Dockerfile").read_text(encoding="utf-8"), re.MULTILINE)
    assert tags, "the Dockerfile has no python base image"
    assert set(tags) == {pinned}
