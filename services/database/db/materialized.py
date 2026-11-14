"""Materialized-view refresh: the clock that keeps the dashboards honest.

A materialized view is a SNAPSHOT — current to the last refresh, never to
the row. This module is the one place that advances that clock, and it
reports what happened per view (timing, errors named) so an operator never
has to guess how stale a dashboard number is.

``REFRESH MATERIALIZED VIEW CONCURRENTLY`` runs outside any transaction
(a PostgreSQL rule, not a choice) and never blocks readers: dashboards
keep serving the previous snapshot while the new one is built. The views'
unique indexes (migration 0155) are what make CONCURRENTLY legal.

Honest boundary: SQLite has no materialized views (0130's rule). On
SQLite this module reports each view as ``absent`` — the dashboards fall
back to live GROUP BY queries there, and nothing pretends otherwise.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from sqlalchemy import text

logger = logging.getLogger(__name__)

MATERIALIZED_VIEWS = ("mv_portfolio_summary", "mv_compliance_summary")


def refresh_materialized_views(engine: Any, *,
                               concurrently: bool = True) -> dict[str, dict]:
    """Refresh every registered view; returns per-view outcomes.

    A failing view is reported (``status: failed`` + error type), never
    raised past the others: one broken aggregate must not stop the rest of
    the dashboards from advancing.
    """
    outcomes: dict[str, dict] = {}
    is_postgres = getattr(engine.dialect, "name", "") == "postgresql"
    with engine.connect() as connection:
        existing = {
            row[0] for row in connection.execute(text(
                "SELECT matviewname FROM pg_matviews" if is_postgres
                else "SELECT name FROM sqlite_master WHERE 0"))
        }
    for name in MATERIALIZED_VIEWS:
        started = time.perf_counter()
        if not is_postgres:
            outcomes[name] = {"status": "absent",
                              "detail": "SQLite has no materialized views; "
                                        "dashboards query live there"}
            continue
        if name not in existing:
            outcomes[name] = {"status": "absent",
                              "detail": "not created (migration chain behind?)"}
            continue
        try:
            # CONCURRENTLY must run outside a transaction block.
            with engine.connect().execution_options(
                    isolation_level="AUTOCOMMIT") as connection:
                keyword = "CONCURRENTLY" if concurrently else ""
                connection.execute(text(
                    f"REFRESH MATERIALIZED VIEW {keyword} {name}".replace("  ", " ")))
            outcomes[name] = {
                "status": "refreshed",
                "seconds": round(time.perf_counter() - started, 4),
            }
        except Exception as exc:  # noqa: BLE001 — report, keep refreshing
            logger.exception("materialized_view_refresh_failed",
                             extra={"view": name})
            outcomes[name] = {"status": "failed",
                              "error_type": type(exc).__name__}
    return outcomes
