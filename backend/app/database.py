"""Engine, session factory, and declarative base.

Postgres is the target (see CLAUDE.md -- time-window correlation and the
entity-key index are the whole point). SQLite is a local-dev and test
fallback only; anything that depends on Postgres-specific behaviour belongs
behind a feature check, not a silent assumption.
"""

from __future__ import annotations

import os

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./soc_triage.db")


def _engine_kwargs(url: str) -> dict:
    if url.startswith("sqlite"):
        # check_same_thread: FastAPI hands a session to a threadpool worker.
        return {"connect_args": {"check_same_thread": False}}
    return {"pool_pre_ping": True}


engine = create_engine(DATABASE_URL, **_engine_kwargs(DATABASE_URL))

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
    pass


@event.listens_for(Engine, "connect")
def _sqlite_foreign_keys(dbapi_connection, connection_record) -> None:
    """SQLite ignores FK constraints unless asked not to.

    Without this, the ON DELETE CASCADE on event_entities is a no-op under
    SQLite and tests would pass on behaviour Postgres does not share.
    """
    if engine.dialect.name != "sqlite":
        return
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def get_db():
    """FastAPI dependency. One session per request, always closed."""
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
