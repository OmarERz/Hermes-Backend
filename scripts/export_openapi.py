"""Write the API's OpenAPI document to openapi/openapi.json (the contract of the frontend team, API-04).

Usage: uv run python scripts/export_openapi.py [--output PATH] [--check]
`--check` exits with 1 if the file on disk differs from the current app (used by `make openapi-check`).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from pydantic import SecretStr

from api.app import create_app
from core.config import Settings

DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "openapi" / "openapi.json"


def build_openapi() -> dict[str, Any]:
    """OpenAPI of the app, built with fixed dummy settings so it is deterministic and needs no environment.

    `api_docs_enabled` stays off: `app.openapi()` is available even when the docs routes are not served.
    """
    settings = Settings(
        _env_file=None,
        database_url=SecretStr("postgresql://openapi:openapi@localhost/openapi"),
        firebase_project_id="openapi-export",
        cursor_signing_key=SecretStr("openapi-export-key-not-a-secret-0000"),
        api_docs_enabled=False,
    )
    return create_app(settings).openapi()


def render(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true", help="fail if the file differs instead of writing it")
    args = parser.parse_args(argv)
    text = render(build_openapi())
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else None
        if current != text:
            sys.stderr.write(f"{args.output} is out of date: run `make openapi`\n")
            return 1
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
