"""Per-app sample stores: created items stay retrievable until the real services and tables replace them."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session, sessionmaker

from api.routes.models import PeerCompany, Run, Source
from core.metrics.dashboard import Dashboard, build_dashboard

DashboardSource = Callable[[datetime], Dashboard]


def get_runs(request: Request) -> list[Run]:
    runs: list[Run] = request.app.state.runs
    return runs


def get_peers(request: Request) -> list[PeerCompany]:
    peers: list[PeerCompany] = request.app.state.peers
    return peers


def get_sources(request: Request) -> list[Source]:
    sources: list[Source] = request.app.state.sources
    return sources


def get_dashboard_source(request: Request) -> DashboardSource:
    """The metrics dashboard read from the database (F8, `daily_metric` and the judge ladder)."""
    session_factory: sessionmaker[Session] = request.app.state.session_factory

    def read(now: datetime) -> Dashboard:
        with session_factory() as session:
            return build_dashboard(session, now)

    return read


RunStore = Annotated[list[Run], Depends(get_runs)]
PeerStore = Annotated[list[PeerCompany], Depends(get_peers)]
SourceStore = Annotated[list[Source], Depends(get_sources)]
MetricsSource = Annotated[DashboardSource, Depends(get_dashboard_source)]
