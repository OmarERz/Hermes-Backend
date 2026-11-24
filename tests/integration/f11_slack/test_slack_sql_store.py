"""`SqlSlackStore` against PostgreSQL 18, as the slack_module role: the same cases as the in-memory store."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from slackdb import SlackDatabase
from sqlalchemy import Engine
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError

from core.db.session import make_engine
from harness.slack_store_cases import CASES
from notifications_slack.sql_store import SqlSlackStore
from notifications_slack.store import SlackStore

pytestmark = pytest.mark.integration
WRONG_PASSWORD = "wrong"  # noqa: S105 - fake value for tests


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.__name__)
def test_sql_store(slack_engine: Engine, case: Callable[[SlackStore], None]) -> None:
    case(SqlSlackStore(slack_engine))


def test_set_digest_ts_with_nothing_does_nothing(slack_engine: Engine) -> None:
    SqlSlackStore(slack_engine).set_digest_ts([], "1700000000.000001", "C0TEAM0001")


def test_check_passes_for_the_slack_role_and_fails_for_a_wrong_password(
    slack_engine: Engine, slack_db: SlackDatabase
) -> None:
    SqlSlackStore(slack_engine).check()
    wrong = make_engine(make_url(slack_db.slack_url).set(password=WRONG_PASSWORD).render_as_string(hide_password=False))
    try:
        with pytest.raises(OperationalError):
            SqlSlackStore(wrong).check()
    finally:
        wrong.dispose()
