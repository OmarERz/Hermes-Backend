"""The log filter masks configured secrets, token patterns, URL passwords and e-mails (SEG-24, C15)."""

from __future__ import annotations

import io
import json
import logging
from collections.abc import Iterator

import pytest

from core.logging import MASK, JsonFormatter, SecretMaskingFilter, configure_logging

CONFIGURED = "itop-configured-token-123"


@pytest.fixture
def capture() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    configure_logging(secrets=[CONFIGURED, ""], stream=stream)
    yield stream
    logging.getLogger().handlers.clear()


def lines(stream: io.StringIO) -> list[dict[str, str]]:
    return [json.loads(line) for line in stream.getvalue().splitlines()]


@pytest.mark.parametrize(
    ("message", "leaked"),
    [
        (f"calling iTop with {CONFIGURED}", CONFIGURED),
        ("slack bot xoxb-1234-5678-abcdef", "xoxb-1234-5678-abcdef"),
        ("slack app xapp-1-A0B1-999-zz", "xapp-1-A0B1-999-zz"),
        ("deepseek key sk-abcdef0123456789", "sk-abcdef0123456789"),
        ("token eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl", "eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl"),
        ("Authorization: Bearer abc.def-ghi", "abc.def-ghi"),
        ("db postgresql://app:p4ss-w0rd@db:5432/hermes", "p4ss-w0rd"),
        ("claimed by ana.lopez@example.com", "ana.lopez@example.com"),
    ],
)
def test_masks_in_message(capture: io.StringIO, message: str, leaked: str) -> None:
    logging.getLogger("hermes.test").warning(message)
    out = capture.getvalue()
    assert leaked not in out
    assert MASK in out


def test_masks_values_passed_as_args(capture: io.StringIO) -> None:
    logging.getLogger("hermes.test").info("token=%s user=%s", CONFIGURED, "ana@example.com")
    entry = lines(capture)[0]
    assert entry["message"] == f"token={MASK} user={MASK}"


def fail_with_secret() -> None:
    raise RuntimeError(f"iTop rejected {CONFIGURED}")


def test_masks_exception_text(capture: io.StringIO) -> None:
    try:
        fail_with_secret()
    except RuntimeError:
        logging.getLogger("hermes.test").exception("call failed")
    entry = lines(capture)[0]
    assert CONFIGURED not in entry["exception"]
    assert "RuntimeError" in entry["exception"]


def test_keeps_user_name_in_url(capture: io.StringIO) -> None:
    logging.getLogger("hermes.test").info("connecting to postgresql://app:secret@db/hermes")
    assert lines(capture)[0]["message"] == f"connecting to postgresql://app:{MASK}@db/hermes"


def test_json_shape(capture: io.StringIO) -> None:
    logging.getLogger("hermes.test").error("plain message")
    entry = lines(capture)[0]
    assert set(entry) == {"ts", "level", "logger", "message"}
    assert entry["level"] == "ERROR"
    assert entry["logger"] == "hermes.test"
    assert entry["ts"].endswith("+00:00")


def test_longer_secret_masked_whole() -> None:
    masking = SecretMaskingFilter(["abc", "abcdef-long-secret"])
    assert masking.mask("x abcdef-long-secret y") == f"x {MASK} y"


def test_stack_info_masked() -> None:
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "msg", None, None, sinfo=f"Stack {CONFIGURED}")
    SecretMaskingFilter([CONFIGURED]).filter(record)
    assert CONFIGURED not in JsonFormatter().format(record)


def test_configure_replaces_existing_handlers(capture: io.StringIO) -> None:
    configure_logging(stream=capture)
    assert len(logging.getLogger().handlers) == 1


@pytest.mark.parametrize("name", ["uvicorn.access", "uvicorn.error"])
def test_uvicorn_records_are_masked(capture: io.StringIO, name: str) -> None:
    logging.getLogger(name).info('"GET /api/x?token=%s HTTP/1.1" 200', CONFIGURED)
    assert CONFIGURED not in capture.getvalue()
    assert MASK in capture.getvalue()
