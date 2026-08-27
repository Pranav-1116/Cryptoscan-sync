"""Org fan-out concurrency — bounded pool with per-org rate budget.

Scanning a 300-account organization serially takes hours; scanning it
unbounded triggers every throttle in the cloud. The pool runs account
scans on a bounded worker thread set, staggered by a token-bucket rate
budget, and preserves per-account telemetry in the org roll-up.
"""

from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from cloud_scanner.core.reliability import ScanTelemetry

#: verdict precedence (worst first)
_VERDICT_ORDER = {"FAILED": 3, "PARTIAL": 2, "OK": 1, "SKIPPED": 0}


def worst_status(statuses: list[str]) -> str:
    return max(statuses, key=lambda s: _VERDICT_ORDER.get(s, 0)) if statuses else "SKIPPED"


class TokenBucketLimiter:
    """Classic token bucket — the org's rate budget.

    ``rate_per_second`` tokens regenerate per second, up to ``burst``.
    ``acquire`` blocks until a token is available. Clock and sleep are
    injectable for deterministic tests.
    """

    def __init__(
        self,
        *,
        rate_per_second: float = 4.0,
        burst: int = 8,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.rate = max(0.001, float(rate_per_second))
        self.burst = max(1, int(burst))
        self._tokens = float(self.burst)
        self._last = clock()
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()

    def acquire(self, tokens: int = 1) -> float:
        """Consume ``tokens``; returns the wait applied (0 if none)."""
        waited = 0.0
        while True:
            with self._lock:
                now = self._clock()
                self._tokens = min(self.burst, self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return waited
                deficit = (tokens - self._tokens) / self.rate
            self._sleep(deficit)
            waited += deficit


def _fanout_workers(default: int = 8) -> int:
    try:
        return max(1, int(os.environ.get("CRYPTOSCAN_CLOUD_FANOUT_WORKERS") or default))
    except ValueError:
        return default


def scan_accounts_parallel(
    scan_account: Callable[[dict[str, Any]], dict[str, Any]],
    accounts: list[dict[str, Any]],
    *,
    max_workers: int | None = None,
    limiter: TokenBucketLimiter | None = None,
) -> dict[str, Any]:
    """Scan accounts on a bounded pool with a per-org rate budget.

    ``scan_account(account)`` returns a dict with at least ``resources``
    and ``live_scan`` (the per-account CloudScanner.scan_live result).
    One account failing never stops the others; everything lands in the
    roll-up.
    """
    workers = max_workers or _fanout_workers()
    if limiter is None:
        limiter = TokenBucketLimiter(
            rate_per_second=_stagger_rate(),
            burst=max(1, workers),
        )

    results: list[dict[str, Any]] = []
    lock = threading.Lock()
    index = 0

    def _run(account: dict[str, Any]) -> dict[str, Any]:
        limiter.acquire()
        try:
            outcome = scan_account(account) or {}
            return {"account": account.get("account_id"), "ok": True, **outcome}
        except Exception as exc:  # noqa: BLE001 — one account must not sink the org
            return {
                "account": account.get("account_id"),
                "ok": False,
                "resources": 0,
                "findings": [],
                "live_scan": {
                    "status": "FAILED",
                    "errors": [{"provider": "org", "service": "account", "region": "global", "code": type(exc).__name__, "error": str(exc)[:300]}],
                },
                "error": f"{type(exc).__name__}: {exc}"[:300],
            }

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_run, account): account for account in accounts}
        for future in as_completed(futures):
            outcome = future.result()
            with lock:
                results.append(outcome)
                index += 1

    results.sort(key=lambda row: str(row.get("account") or ""))
    return {
        "results": results,
        "rollup": rollup_org(results, total_accounts=len(accounts)),
    }


def _stagger_rate() -> float:
    """Account-scan starts per second (CRYPTOSCAN_CLOUD_ORG_RATE, default 4)."""
    try:
        return max(0.1, float(os.environ.get("CRYPTOSCAN_CLOUD_ORG_RATE") or 4.0))
    except ValueError:
        return 4.0


def rollup_org(results: list[dict[str, Any]], *, total_accounts: int | None = None) -> dict[str, Any]:
    """Aggregate per-account outcomes into an org-level telemetry summary."""
    scanned = [row for row in results if row.get("ok")]
    failed = [row for row in results if not row.get("ok")]
    partial_accounts = 0
    errors: list[dict[str, Any]] = []
    resources = 0
    statuses: list[str] = []

    for row in scanned:
        live_scan = row.get("live_scan") or {}
        status = str(live_scan.get("status") or "SKIPPED")
        statuses.append(status if status in _VERDICT_ORDER else "PARTIAL")
        if status == "PARTIAL":
            partial_accounts += 1
        resources += int(live_scan.get("resources_scanned") or row.get("resources") or 0)
        for error in (live_scan.get("errors") or [])[:10]:
            errors.append({"account": row.get("account"), **error})

    for row in failed:
        for error in ((row.get("live_scan") or {}).get("errors") or [])[:3]:
            errors.append({"account": row.get("account"), **error})

    if scanned:
        org_status = worst_status(statuses)
        if failed and org_status in {"OK", "SKIPPED"}:
            # some accounts failed but results were obtained: PARTIAL,
            # never an empty success and never a silent org-FAILED
            org_status = "PARTIAL"
    else:
        org_status = "FAILED" if failed else "SKIPPED"

    return {
        "status": org_status,
        "accounts_total": total_accounts if total_accounts is not None else len(results),
        "accounts_scanned": len(scanned),
        "accounts_failed": len(failed),
        "accounts_partial": partial_accounts,
        "resources_scanned": resources,
        "error_count": len(errors),
        "errors": errors[:50],
    }


def org_telemetry_from(rollup: dict[str, Any]) -> ScanTelemetry:
    """Materialize org roll-up as ScanTelemetry-compatible summary block."""
    telemetry = ScanTelemetry()
    telemetry.resources_scanned = int(rollup.get("resources_scanned") or 0)
    for error in rollup.get("errors") or []:
        telemetry.errors.append(
            {
                "provider": str(error.get("provider") or "org"),
                "service": str(error.get("service") or "account"),
                "region": str(error.get("region") or "global"),
                "code": str(error.get("code") or "Error"),
                "error": str(error.get("error") or "")[:300],
            }
        )
    return telemetry
