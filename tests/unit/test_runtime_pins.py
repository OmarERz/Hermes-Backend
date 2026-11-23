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


def test_the_api_and_embeddings_images_hide_the_server_header() -> None:
    """F12.3 (ASVS V13.4.6): Uvicorn's `server: uvicorn` header names the backend component; both images drop it."""
    for dockerfile in (ROOT / "Dockerfile", ROOT / "docker" / "embeddings" / "Dockerfile"):
        commands = [line for line in dockerfile.read_text(encoding="utf-8").splitlines() if line.startswith("CMD ")]
        assert any('"uvicorn"' in line and '"--no-server-header"' in line for line in commands), dockerfile


def test_the_api_image_starts_each_request_with_a_clean_context() -> None:
    """F12.3: with --reset-contextvars no log line of a keep-alive connection inherits the previous request's id."""
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert '"--reset-contextvars"' in text
