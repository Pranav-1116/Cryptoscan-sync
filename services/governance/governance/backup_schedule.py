"""Scheduled backup sweep — the worker-tick counterpart to report_sweep.

Pure + deterministic. Backup configurations live as app_settings (JSON), so the
same store the platform already uses drives the schedule. On each worker tick
`run_due_backups_sweep` reads configs, decides which are due (interval elapsed),
runs the backup cycle against the real runner backend, persists artifacts to the
storage sink, applies retention, and records the last-run time.

Backends/storage/clock are injected so this is fully testable offline.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import asdict
from typing import Any, Callable

from . import backup_jobs as bj

SETTING_KEY = "governance.backup_schedules"


def load_configs(settings_repo) -> list[bj.BackupConfig]:
    raw = settings_repo.get(SETTING_KEY, default=[])
    out: list[bj.BackupConfig] = []
    for item in raw or []:
        last = item.get("last_run_at")
        out.append(bj.BackupConfig(
            database_id=item["database_id"],
            engine=item.get("engine", "postgres"),
            interval_hours=float(item.get("interval_hours", 24.0)),
            retention_policy=item.get("retention_policy"),
            sequence=int(item.get("sequence", 0)),
            last_run_at=dt.datetime.fromisoformat(last) if last else None,
        ))
    return out


def save_configs(settings_repo, configs: list[bj.BackupConfig], *, by: str = "backup-sweep") -> None:
    payload = []
    for c in configs:
        d = {"database_id": c.database_id, "engine": c.engine,
             "interval_hours": c.interval_hours, "sequence": c.sequence,
             "retention_policy": c.retention_policy,
             "last_run_at": c.last_run_at.isoformat() if c.last_run_at else None}
        payload.append(d)
    settings_repo.set(SETTING_KEY, payload, updated_by=by)


def run_due_backups_sweep(*, settings_repo, backend_for: Callable[[str], Any],
                          storage: bj.InMemoryBackupStorage, encryption_key: bytes,
                          signing_secret: str, now: dt.datetime | None = None,
                          apply_retention: bool = True) -> dict[str, Any]:
    """Worker-tick entrypoint: run due scheduled backups + retention.

    Returns a summary dict suitable for monitor events/SSE. Never raises for an
    individual backup failure — one bad database must not kill the sweep.
    """
    ref = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    configs = load_configs(settings_repo)
    outcomes: list[dict[str, Any]] = []
    for cfg in configs:
        due = cfg.last_run_at is None or (
            ref - cfg.last_run_at.astimezone(dt.timezone.utc)
        ) >= dt.timedelta(hours=cfg.interval_hours)
        if not due:
            outcomes.append({"database_id": cfg.database_id, "status": "SKIPPED_NOT_DUE"})
            continue
        try:
            backend = backend_for(cfg.engine)
            res = bj.run_backup_job(backend=backend, storage=storage, config=cfg,
                                    encryption_key=encryption_key, signing_secret=signing_secret,
                                    now=ref)
            outcomes.append({"database_id": cfg.database_id, "engine": cfg.engine,
                             "status": "BACKED_UP", "storage_key": res["storage_key"],
                             "sequence": res["manifest"]["sequence"]})
        except Exception as exc:  # noqa: BLE001 — isolate per-DB failure
            outcomes.append({"database_id": cfg.database_id, "engine": cfg.engine,
                             "status": "FAILED", "detail": f"{type(exc).__name__}: {exc}"[:300]})
    save_configs(settings_repo, configs)

    retention = None
    if apply_retention:
        r = bj.execute_retention(storage=storage, signing_secret=signing_secret, now=ref)
        retention = {"kept": r["plan"]["kept"], "purged": r["plan"]["purged"],
                     "deleted_keys": r["deleted_keys"]}
    return {"swept_at": ref.isoformat(), "configs": len(configs),
            "backed_up": sum(1 for o in outcomes if o["status"] == "BACKED_UP"),
            "failed": sum(1 for o in outcomes if o["status"] == "FAILED"),
            "outcomes": outcomes, "retention": retention,
            "stored_backups": len(storage.list_manifests())}
