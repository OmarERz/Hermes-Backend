"""Database session per request. Reads need nothing more; a handler that writes calls `session.commit()` itself
before it returns, so the client never gets a success for a change that was not saved. An unfinished transaction is
rolled back when the session closes."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session, sessionmaker


def get_session(request: Request) -> Iterator[Session]:
    factory: sessionmaker[Session] = request.app.state.session_factory
    with factory() as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]
