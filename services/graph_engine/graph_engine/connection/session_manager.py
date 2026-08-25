"""Neo4j session context manager."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator


@contextmanager
def neo4j_session(driver, database: str = "neo4j") -> Iterator[Any]:
    session = driver.session(database=database)
    try:
        yield session
    finally:
        session.close()
