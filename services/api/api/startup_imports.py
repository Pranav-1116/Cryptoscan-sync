"""Import the engine packages the routes reach for lazily, once, at startup.

A lot of routers import their engine package *inside* the handler, e.g.
``from automation.blast_radius import analyze_blast_radius``. That keeps the
import graph small at boot but has two costs that only show up in production:

* the first request to each such route pays the whole transitive import bill
  (tens of milliseconds to a few hundred), which reads as a slow endpoint;
* two first-requests arriving at the same time import different modules whose
  graphs overlap — ``automation.watchers.cert_expiry`` imports ``automation``
  while another thread is still holding that module's lock — and CPython can
  raise ``_DeadlockError`` (import lock inversion). The request then answers 500.

Warming them sequentially in the lifespan pays the bill once, on the boot path,
where a failure is visible and a slow start is not a user-visible fault.

The list is deliberately the engine packages behind the heaviest routes rather
than everything importable: this is a warm-up, not an eager-import of the app.
"""

from __future__ import annotations

import importlib
import logging

logger = logging.getLogger(__name__)

#: Imported in this order at startup. Order is alphabetical by package so the
#: warm-up itself is deterministic; it is not a dependency order.
WARM_MODULES: tuple[str, ...] = (
    "automation.blast_radius",
    "automation.watchers.cert_expiry",
    "cloud_scanner.org.enumerators",
    "governance.backup_jobs",
    "vendor_intel.profile",
)


def warm(modules: tuple[str, ...] = WARM_MODULES) -> dict[str, str]:
    """Import each module, returning ``{module: "ok" | "<error>"}``.

    Never raises. A broken optional engine must not stop the API from booting —
    the route that needs it will report the failure with its own status code —
    but the failure is logged at warning level so it is not silent either.
    """
    report: dict[str, str] = {}
    for name in modules:
        try:
            importlib.import_module(name)
        except Exception as exc:  # noqa: BLE001 - warm-up must not fail the boot
            report[name] = f"{type(exc).__name__}: {exc}"
            logger.warning("startup_warm_import_failed", extra={"module": name, "error": str(exc)})
        else:
            report[name] = "ok"
    ok = sum(1 for status in report.values() if status == "ok")
    logger.info("startup_warm_imports", extra={"ok": ok, "total": len(modules)})
    return report
