"""The judge's daily budget reads the day's spending from llm_usage_daily and the limits from the parameters."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from dbprovision import provisioned_database
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id
from core.db.seeds import seed
from core.db.session import make_engine
from core.judge.budget import FALLBACK_PRICE, ModelPrice
from core.judge.package import ReviewPackage
from core.judge.service import JudgeService
from core.judge.session import Failure, ReviewStatus
from core.judge.store import judge_environment, load_daily_budget, load_model_price
from doubles.llm import LlmDouble, tool_call_completion
from harness.judge import double_llm_client, finding_package

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]
TODAY = date(2026, 11, 22)
PRICE = ModelPrice(input=Decimal(1), cached_input=Decimal("0.1"), output=Decimal(2))  # a turn: USD 0.015


@pytest.fixture
def engine(postgres_url: str) -> Iterator[Engine]:
    with provisioned_database(postgres_url, "judgebudget") as db:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.attributes["url"] = db.migrator_url
        command.upgrade(cfg, "head")
        engine = make_engine(db.superuser_url)
        with Session(engine) as session, session.begin():
            seed(session, "empty")
        try:
            yield engine
        finally:
            engine.dispose()


def spend(session: Session, usd: str, when: datetime) -> None:
    session.add(
        m.LlmReview(
            id=new_id(),
            agent="judge",
            mode="scoring",
            model="deepseek-v4-pro",
            response_model={},
            prompt_version="v",
            prompt_hash="h",
            schema_version="s",
            schema_hash="h",
            parameters={},
            input_ref="test",
            calls=[],
            status="applied",
            attempts=1,
            tokens_input=0,
            tokens_cached=0,
            tokens_output=0,
            tokens_reasoning=0,
            cost_usd=Decimal(usd),
            latency_ms=0,
            ladder_level=0,
            created_at=when,
        )
    )
    session.flush()


def test_daily_budget_from_the_ledger_and_the_parameters(engine: Engine) -> None:
    with Session(engine) as session, session.begin():
        spend(session, "3.90", datetime(2026, 11, 22, 10, 0, tzinfo=UTC))
        spend(session, "9.00", datetime(2026, 11, 21, 10, 0, tzinfo=UTC))  # yesterday does not count
        budget = load_daily_budget(session, PRICE, TODAY)
        assert budget.allows(critical=False)  # 3.90 + 0.015 <= 4.00
        spend(session, "0.10", datetime(2026, 11, 22, 11, 0, tzinfo=UTC))
        assert not budget.allows(critical=False)  # read live: 4.00 + 0.015 > 4.00
        assert budget.allows(critical=True)  # the 20% reserve is for critical work
        session.execute(
            text(
                "INSERT INTO setting_value (setting_key, version, value, origin, changed_at) VALUES "
                "('daily_budget_usd', 1, '\"20\"', 'frontend', now())"
            )
        )
        assert load_daily_budget(session, PRICE, TODAY).allows(critical=False)


def test_model_prices_are_not_configured_yet(engine: Engine) -> None:
    with Session(engine) as session:
        assert load_model_price(session, "deepseek-v4-pro") is None  # gap: model_prices is not seeded


def test_an_exhausted_day_stops_the_judge_before_any_call(engine: Engine) -> None:
    with Session(engine) as session, session.begin():
        spend(session, "5.00", datetime.now(UTC))
        env = judge_environment(session, datetime.now(UTC).date())
        assert env.price is FALLBACK_PRICE  # model_prices is not configured (gap reported): never a zero cost
        assert env.settings.model == "deepseek-v4-pro"
        double = LlmDouble()
        double.add_case("case", [tool_call_completion("finalize_review", {"summary": "x", "mitigation_steps": []})])
        double.use("case")
        result = JudgeService(double_llm_client(double), env).evaluate(ReviewPackage.from_content(finding_package()))
        assert result.status is ReviewStatus.NO_JUDGE_REVIEW
        assert result.failure is Failure.BUDGET
        double.assert_calls(0)


def test_a_configured_price_is_used(engine: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("core.judge.store.load_model_price", lambda _session, _model: PRICE)
    with Session(engine) as session:
        assert judge_environment(session, TODAY).price == PRICE
