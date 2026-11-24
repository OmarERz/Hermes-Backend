"""`SqlSlackStore` against PostgreSQL 18, as the slack_module role: the same cases as the in-memory store."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from sqlalchemy import Engine

from harness.slack_store_cases import CASES
from notifications_slack.sql_store import SqlSlackStore
from notifications_slack.store import SlackStore

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.__name__)
def test_sql_store(slack_engine: Engine, case: Callable[[SlackStore], None]) -> None:
    case(SqlSlackStore(slack_engine))


def test_set_digest_ts_with_nothing_does_nothing(slack_engine: Engine) -> None:
    SqlSlackStore(slack_engine).set_digest_ts([], "1700000000.000001")
