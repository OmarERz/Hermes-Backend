"""The log filter masks configured secrets, token patterns, URL passwords and e-mails (SEG-24, C15)."""

from __future__ import annotations

import contextvars
import io
import json
import logging
from collections.abc import Iterator

import pytest

from core.logging import MASK, JsonFormatter, SecretMaskingFilter, bind_request, configure_logging, request_context

CONFIGURED = "itop-configured-token-123"
# Fake tokens are assembled at runtime so secret scanners do not flag the test source.
SLACK_BOT = "-".join(["xoxb", "1234", "5678", "abcdef"])
DEEPSEEK_KEY = "".join(["sk", "-", "abcdef", "0123456789"])
SLACK_APP = "-".join(["xapp", "1", "A0B1", "999", "zz"])


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
        (f"slack bot {SLACK_BOT}", SLACK_BOT),
        (f"slack app {SLACK_APP}", SLACK_APP),
        (f"deepseek key {DEEPSEEK_KEY}", DEEPSEEK_KEY),
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
    logging.getLogger("hermes.test").info("value=%s user=%s", CONFIGURED, "ana@example.com")
    entry = lines(capture)[0]
    assert entry["message"] == f"value={MASK} user={MASK}"


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
    logging.getLogger("hermes.test").info("connecting to postgresql://app:hunter2@db/hermes")
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
    logging.getLogger(name).info('"GET /api/x?q=%s HTTP/1.1" 200', CONFIGURED)
    assert CONFIGURED not in capture.getvalue()
    assert MASK in capture.getvalue()


def test_lines_inside_a_request_carry_its_masked_context(capture: io.StringIO) -> None:
    """F12.3 (ASVS V16.2.1): who, from where and which request; the context is masked like the message."""
    with request_context(request_id="r-1", client="10.0.0.9", method="GET", path="/api/x/ana@example.com", other="no"):
        bind_request(user="uid-7", unknown="ignored")
        logging.getLogger("hermes.test").warning("inside")
    logging.getLogger("hermes.test").warning("outside")
    inside, outside = lines(capture)
    assert inside["request_id"] == "r-1"
    assert (inside["client"], inside["method"], inside["user"]) == ("10.0.0.9", "GET", "uid-7")
    assert inside["path"] == f"/api/x/{MASK}"
    assert "other" not in inside and "unknown" not in inside
    assert set(outside) == {"ts", "level", "logger", "message"}


def test_binding_outside_a_request_does_nothing(capture: io.StringIO) -> None:
    bind_request(user="uid-7")
    logging.getLogger("hermes.test").warning("plain")
    assert "user" not in lines(capture)[0]


def test_an_error_leaving_the_block_keeps_the_context_for_the_servers_log(capture: io.StringIO) -> None:
    """The server logs an escaped error right after, in the same task: the context must still be there."""

    def handler() -> None:
        with request_context(request_id="r-9", path="/api/x"):
            fail_with_secret()

    def request_that_fails() -> None:
        try:
            handler()
        except RuntimeError:
            logging.getLogger("uvicorn.error").exception("Exception in ASGI application")

    contextvars.copy_context().run(request_that_fails)  # one request, one context, as in a server task
    logging.getLogger("hermes.test").warning("after the request")
    during, after = lines(capture)
    assert during["request_id"] == "r-9"
    assert "request_id" not in after
