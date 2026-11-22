"""Per-app sample stores: created items stay retrievable until the real services and tables replace them."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request

from api.routes.models import PeerCompany, Run, Source


def get_runs(request: Request) -> list[Run]:
    runs: list[Run] = request.app.state.runs
    return runs


def get_peers(request: Request) -> list[PeerCompany]:
    peers: list[PeerCompany] = request.app.state.peers
    return peers


def get_sources(request: Request) -> list[Source]:
    sources: list[Source] = request.app.state.sources
    return sources


RunStore = Annotated[list[Run], Depends(get_runs)]
PeerStore = Annotated[list[PeerCompany], Depends(get_peers)]
SourceStore = Annotated[list[Source], Depends(get_sources)]
