"""Per-app read sources the routes depend on (overridable in tests): the metrics dashboard from the database."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session, sessionmaker

from core.metrics.dashboard import Dashboard, build_dashboard

DashboardSource = Callable[[datetime], Dashboard]


def get_dashboard_source(request: Request) -> DashboardSource:
    """The metrics dashboard read from the database (F8, `daily_metric` and the judge ladder)."""
    session_factory: sessionmaker[Session] = request.app.state.session_factory

    def read(now: datetime) -> Dashboard:
        with session_factory() as session:
            return build_dashboard(session, now)

    return read


MetricsSource = Annotated[DashboardSource, Depends(get_dashboard_source)]
