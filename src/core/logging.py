"""Structured JSON logging with a filter that masks secrets and personal data (SEG-21, SEG-24, C15).

The filter masks, in the final message and in exception text:
- every configured secret value (`Settings.secret_values()`);
- token patterns: Slack (`xoxb-`, `xoxp-`, `xapp-`), `sk-` API keys, JWTs, `Bearer` credentials;
- passwords embedded in URLs (`scheme://user:password@host`);
- e-mail addresses (personal data must not reach the logs).
"""

from __future__ import annotations

import json
import logging
import re
import sys
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import TextIO

MASK = "***"

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]+"), MASK),
    (re.compile(r"\bxapp-[A-Za-z0-9-]+"), MASK),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"), MASK),
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), MASK),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/-]+=*"), rf"\1 {MASK}"),
    (
        re.compile(r"(?P<scheme>[a-z][a-z0-9+.-]*://)(?P<user>[^:/@\s]+):[^@\s/]+@", re.IGNORECASE),
        rf"\g<scheme>\g<user>:{MASK}@",
    ),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), MASK),
)


class SecretMaskingFilter(logging.Filter):
    """Rewrites each record so no configured secret, token pattern or e-mail survives formatting."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        super().__init__()
        # Longest first, so a secret that contains another one is masked whole.
        self._secrets = sorted({s for s in secrets if s}, key=len, reverse=True)

    def mask(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, MASK)
        for pattern, replacement in _PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self.mask(record.getMessage())
        record.args = None
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = self.mask(record.exc_text)
        if record.stack_info:
            record.stack_info = self.mask(record.stack_info)
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line: timestamp (UTC), level, logger, message and exception."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, str] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            entry["exception"] = record.exc_text
        if record.stack_info:
            entry["stack"] = record.stack_info
        return json.dumps(entry, ensure_ascii=False)


# Loggers that install their own handlers and do not propagate to the root (Uvicorn).
_OWN_HANDLER_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access")


def configure_logging(secrets: Iterable[str] = (), level: int = logging.INFO, stream: TextIO | None = None) -> None:
    """Install a single JSON handler with the masking filter on the root logger and on Uvicorn's loggers."""
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(SecretMaskingFilter(secrets))
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)
    for name in _OWN_HANDLER_LOGGERS:
        own = logging.getLogger(name)
        own.handlers = []
        own.propagate = True
