"""Errors of the configuration services. The API maps them to the error envelope; nothing here knows HTTP."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Problem:
    field: str
    issue: str


class ConfigError(Exception):
    """Base class: `message` is safe to show (Spanish, no input values)."""

    def __init__(self, message: str, problems: tuple[Problem, ...] = ()) -> None:
        super().__init__(message)
        self.message = message
        self.problems = problems


class VersionConflictError(ConfigError):
    """The client's expected version is not the current one (409)."""


class ValidationFailedError(ConfigError):
    """The values break a rule (422)."""


class ForbiddenParameterError(ConfigError):
    """The user's role is below the parameter's minimum role (403)."""


class NotFoundError(ConfigError):
    """The version or item does not exist (404)."""


class ConflictError(ConfigError):
    """The change clashes with existing data (409), for example a duplicate name."""


FIRST_PRINTABLE = 32
# Unicode bidirectional controls (embeddings, overrides and isolates): invisible, they make a name or a URL display in a
# different order than it is stored ("Trojan Source"), so a peer company or a feed could pose as another (F12.3).
BIDI_CONTROLS = frozenset(chr(code) for code in (*range(0x202A, 0x202F), *range(0x2066, 0x206A)))


def check_text(field: str, *values: str | None) -> None:
    """Refuse control characters (NUL among them), bidirectional controls and text that is not valid UTF-8 (a lone
    surrogate): the database cannot store some of them and none has a place in a name, a key or a URL."""
    for value in values:
        if value is None:
            continue
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise ValidationFailedError(
                "Los datos enviados no son válidos.", (Problem(field, "invalid_characters"),)
            ) from None
        if any(ord(ch) < FIRST_PRINTABLE or ch == "\x7f" or ch in BIDI_CONTROLS for ch in value):
            raise ValidationFailedError("Los datos enviados no son válidos.", (Problem(field, "invalid_characters"),))
