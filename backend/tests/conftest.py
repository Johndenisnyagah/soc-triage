"""Test fixtures.

DATABASE_URL is forced to a throwaway SQLite file *before* any app module is
imported. Forced, not `setdefault`: a developer with DATABASE_URL exported for
their local Postgres must not have the suite quietly truncate it.

To run the suite against Postgres, set `TEST_DATABASE_URL` instead -- a
separately named variable, so pointing the tests at a database is always a
deliberate act. Every table in it is truncated between tests. CI does this
against a throwaway service container.
"""

from __future__ import annotations

import os
import pathlib
import tempfile

_TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "").strip()
if _TEST_DATABASE_URL:
    os.environ["DATABASE_URL"] = _TEST_DATABASE_URL
else:
    _TMP_DIR = pathlib.Path(tempfile.mkdtemp(prefix="soc-triage-tests-"))
    os.environ["DATABASE_URL"] = f"sqlite:///{(_TMP_DIR / 'test.db').as_posix()}"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app import models  # noqa: E402,F401 -- populates Base.metadata
from app.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def schema():
    """Fresh tables per test."""
    Base.metadata.create_all(bind=engine)
    yield
    with engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            # Sequences survive DELETE on Postgres; SQLite reuses max(id)+1.
            # RESTART IDENTITY makes ids start from 1 on both, as tests expect.
            names = ", ".join(t.name for t in Base.metadata.sorted_tables)
            conn.execute(text(f"TRUNCATE {names} RESTART IDENTITY CASCADE"))
        else:
            for table in reversed(Base.metadata.sorted_tables):
                conn.execute(table.delete())


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
