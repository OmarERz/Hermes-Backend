"""Database session per request: commits when the handler returns, rolls back when it raises."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session, sessionmaker


def get_session(request: Request) -> Iterator[Session]:
    factory: sessionmaker[Session] = request.app.state.session_factory
    with factory() as session, session.begin():
        yield session


SessionDep = Annotated[Session, Depends(get_session)]
